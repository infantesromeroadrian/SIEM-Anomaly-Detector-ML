"""
End-to-end evaluation: download, train, evaluate, write ``results/metrics.json``.

Protocol (fixed before looking at the test period):

* Temporal split by UTC calendar day: train = 21-22 Jan 2022, validation =
  23 Jan (benign), test = 24 Jan onwards (contains the attack campaign).
* Models are fitted on ``train`` only (unsupervised, no labels used).
* The alert threshold of every model is the 99th percentile of its scores on
  ``validation`` (benign), chosen without touching ``test``.
* ``test`` is scored exactly once per model and seed. Seeds are listed in
  ``SEEDS`` up front; nothing is tuned afterwards.
* ``known_ips`` (allow-list feature) is built from the training period only.

Usage:
    python -m backend.eval.run [--data-dir DIR] [--out results] [--save-model models]
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from backend.eval import fetch
from backend.eval.dataset import (
    ATTACK_TYPES,
    TRAIN_END,
    VAL_END,
    load_events,
    load_other_host_events,
    split_events,
)
from backend.eval.metrics import choose_threshold, evaluate, wilson_interval
from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES, FeatureEngineer

SEEDS = (0, 1, 2, 3, 4)
THRESHOLD_QUANTILE = 0.99
RATE_COL = FEATURE_NAMES.index("requests_per_second")  # always read from the full matrix

#: Feature-set variants. ``all_features`` is the pre-registered protocol (held-out result).
#: ``no_calendar_features`` was added AFTER inspecting the first run: validation scores showed
#: the GMM/DBSCAN components saturating because day_of_week / is_weekend leave the support of a
#: 2-day training window. Its numbers are therefore post-hoc (in-sample with respect to the
#: design decision) and are reported as such.
VARIANTS: dict[str, dict[str, object]] = {
    "all_features": {"drop": (), "post_hoc": False},
    "no_calendar_features": {"drop": ("day_of_week", "is_weekend"), "post_hoc": True},
}


def variant_columns(name: str) -> list[int]:
    """Return the feature column indices kept by a variant."""
    drop = set(VARIANTS[name]["drop"])  # type: ignore[arg-type]
    return [i for i, f in enumerate(FEATURE_NAMES) if f not in drop]


def build_matrix(events: list, train_idx: list[int]) -> np.ndarray:
    """Extract features for all events in chronological order (causal windows)."""
    known = {events[i].parsed["source_ip"] for i in train_idx}
    fe = FeatureEngineer(config={"known_ips": sorted(known)})
    return np.stack([fe.extract_sync(e.parsed).to_array() for e in events])


def _cdf(reference: np.ndarray) -> Callable[[np.ndarray], np.ndarray]:
    """Share of ``reference`` (benign validation scores) strictly below each value."""
    ref = np.sort(reference)
    return lambda v: np.searchsorted(ref, v, side="left") / len(ref)


def make_scorers(rate_pos: int) -> dict[str, Callable[..., Callable[[np.ndarray], np.ndarray]]]:
    """Return ``name -> fit(x_train, seed, x_val) -> score(x)`` factories."""

    def iforest(
        x_train: np.ndarray, seed: int, x_val: np.ndarray
    ) -> Callable[[np.ndarray], np.ndarray]:
        m = IsolationForest(n_estimators=100, random_state=seed, n_jobs=1).fit(x_train)
        return lambda x: -m.decision_function(x)

    def rule(
        x_train: np.ndarray, seed: int, x_val: np.ndarray
    ) -> Callable[[np.ndarray], np.ndarray]:
        # Baseline: requests from the same IP in the last 60 s.
        return lambda x: x[:, rate_pos] * 60.0

    def ensemble(weights: list[float], key: str = "risk"):
        def fit(
            x_train: np.ndarray, seed: int, x_val: np.ndarray
        ) -> Callable[[np.ndarray], np.ndarray]:
            m = AnomalyEnsemble(ensemble_weights=weights, random_state=seed)
            m.train(x_train)
            return lambda x: m.score_batch(x)[key]

        return fit

    def combined(
        x_train: np.ndarray, seed: int, x_val: np.ndarray
    ) -> Callable[[np.ndarray], np.ndarray]:
        """Alert if the rule OR the Isolation Forest exceeds its own validation quantile."""
        rule_s = rule(x_train, seed, x_val)
        if_s = iforest(x_train, seed, x_val)
        cdf_r, cdf_i = _cdf(rule_s(x_val)), _cdf(if_s(x_val))

        def score(x: np.ndarray) -> np.ndarray:
            return np.maximum(cdf_r(rule_s(x)), cdf_i(if_s(x)))

        score.fixed_threshold = THRESHOLD_QUANTILE  # type: ignore[attr-defined]
        return score

    return {
        "rule_requests_per_60s": rule,
        "isolation_forest": iforest,
        "combined_rule_or_isolation_forest": combined,
        "ensemble_legacy_weights_0.5_0.3_0.2": ensemble([0.5, 0.3, 0.2]),
        "component_dbscan_only": ensemble([0.0, 1.0, 0.0]),
        "component_gmm_only": ensemble([0.0, 0.0, 1.0]),
    }


def build_other_matrix(streams: dict[str, list], known: list[str]) -> np.ndarray:
    """Features of the other hosts' benign test-period lines (one engineer per vhost, warmed up)."""
    parts = []
    for evs in streams.values():
        fe = FeatureEngineer(config={"known_ips": known})
        rows = [(e.timestamp, fe.extract_sync(e.parsed).to_array()) for e in evs]
        parts.extend(r for t, r in rows if t >= VAL_END)
    return np.stack(parts)


def run_model(
    fit: Callable[..., Callable[[np.ndarray], np.ndarray]],
    x: np.ndarray,
    cols: list[int],
    idx: dict[str, list[int]],
    events: list,
    seed: int,
    x_other: np.ndarray | None = None,
) -> dict[str, object]:
    """Fit on train, set threshold on val, evaluate test once."""
    xm = x[:, cols]
    score = fit(xm[idx["train"]], seed, xm[idx["val"]])
    thr = getattr(score, "fixed_threshold", None)
    if thr is None:
        thr = choose_threshold(score(xm[idx["val"]]), THRESHOLD_QUANTILE)
    test_events = [events[i] for i in idx["test"]]
    # Attacks the volume rule cannot see: local request rate within the benign validation range.
    rule_thr = choose_threshold(x[idx["val"], RATE_COL] * 60.0, THRESHOLD_QUANTILE)
    low_rate = x[idx["test"], RATE_COL] * 60.0 <= rule_thr
    out = evaluate(
        np.array([e.is_attack for e in test_events]),
        score(xm[idx["test"]]),
        thr,
        [e.labels for e in test_events],
        ATTACK_TYPES,
        subset_mask=low_rate,
    )
    if x_other is not None:
        flagged = score(x_other[:, cols]) > thr
        out["fpr_other_hosts"] = {"n": int(len(flagged)), "fpr": float(flagged.mean())}
    return out


def aggregate(runs: list[dict[str, object]]) -> dict[str, object]:
    """Mean and std across seeds for scalar metrics and per-type recall."""
    scalar = ("precision", "recall", "f1", "fpr", "pr_auc", "roc_auc")
    out: dict[str, object] = {"n_seeds": len(runs)}
    for k in scalar:
        v = np.array([r[k] for r in runs], dtype=float)
        out[k] = {"mean": float(v.mean()), "std": float(v.std())}
    by_type = {}
    for t in ATTACK_TYPES:
        rec = np.array([r["recall_by_attack_type"][t]["recall"] for r in runs], dtype=float)
        by_type[t] = {
            "n": runs[0]["recall_by_attack_type"][t]["n"],
            "recall_mean": float(rec.mean()),
            "recall_std": float(rec.std()),
        }
    out["recall_by_attack_type"] = by_type
    lr = np.array([r["recall_low_rate_attacks"]["recall"] for r in runs], dtype=float)
    n_lr = runs[0]["recall_low_rate_attacks"]["n"]
    lr_mean = float(np.nanmean(lr)) if not np.isnan(lr).all() else None
    lo, hi = wilson_interval(round(lr_mean * n_lr), n_lr) if lr_mean is not None else (None, None)
    out["recall_low_rate_attacks"] = {
        "n": n_lr,
        "recall_mean": lr_mean,
        "recall_std": float(np.nanstd(lr)) if lr_mean is not None else None,
        "wilson95": [lo, hi],
    }
    if "fpr_other_hosts" in runs[0]:
        f = np.array([r["fpr_other_hosts"]["fpr"] for r in runs], dtype=float)
        out["fpr_other_hosts"] = {
            "n": runs[0]["fpr_other_hosts"]["n"],
            "mean": float(f.mean()),
            "std": float(f.std()),
        }
    return out


def _git_commit() -> str:
    """Return HEAD, suffixed with ``+dirty`` when the working tree has uncommitted changes."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return head + ("+dirty" if dirty else "")
    except Exception:
        return "unknown"


def render_report(m: dict) -> str:
    """Render the markdown report from the metrics dictionary (single source of truth)."""
    d = m["dataset"]
    lines = [
        "# Evaluation report",
        "",
        f"Generated {m['meta']['generated_utc']} from commit `{m['meta']['git_commit'][:12]}{'+dirty' if m['meta']['git_commit'].endswith('+dirty') else ''}`. "
        "Every number below is read from `metrics.json`.",
        "",
        f"Dataset: {d['name']} ({d['license']}). Split: train {d['n_train']} / "
        f"validation {d['n_val']} / test {d['n_test']} lines "
        f"({d['n_test_attack']} attack, prevalence {d['test_prevalence']:.3f}).",
        f"Threshold: {m['protocol']['threshold_quantile']:.0%} quantile of benign validation scores. "
        f"Mean over seeds {m['protocol']['seeds']} (std in parentheses; rule baseline is deterministic). "
        f"PR-AUC of a random scorer equals the prevalence ({d['test_prevalence']:.3f}).",
    ]
    for variant, res in m["results"].items():
        post = m["protocol"]["variants"][variant]["post_hoc"]
        dropped = m["protocol"]["variants"][variant]["dropped"]
        lines += [
            "",
            f"## Variant `{variant}`"
            + (" (POST-HOC, in-sample design decision)" if post else " (pre-registered, held-out)"),
            "",
        ]
        if dropped:
            lines += [f"Dropped features: {', '.join(dropped)}.", ""]
        lines += [
            "| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR (test benign) | FPR (other hosts) |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for name, r in res.items():
            cells = " | ".join(
                f"{r[k]['mean']:.3f} ({r[k]['std']:.3f})"
                for k in ("precision", "recall", "f1", "pr_auc", "roc_auc", "fpr")
            )
            fo = r["fpr_other_hosts"]
            lines.append(f"| {name} | {cells} | {fo['mean']:.4f} ({fo['std']:.4f}) |")
        first = next(iter(res.values()))
        lines += [
            "",
            "Recall by attack type (n in header):",
            "",
            "| Model | "
            + " | ".join(f"{t} (n={first['recall_by_attack_type'][t]['n']})" for t in ATTACK_TYPES)
            + " |",
            "|---|" + "---|" * len(ATTACK_TYPES),
        ]
        for name, r in res.items():
            lines.append(
                f"| {name} | "
                + " | ".join(
                    f"{r['recall_by_attack_type'][t]['recall_mean']:.3f}" for t in ATTACK_TYPES
                )
                + " |"
            )
        lines += [
            "",
            f"Attacks invisible to the volume rule (per-IP requests in 60 s within the benign validation range; n={first['recall_low_rate_attacks']['n']}):",
            "",
            "| Model | Recall |",
            "|---|---|",
        ]
        for name, r in res.items():
            lr = r["recall_low_rate_attacks"]
            rec = (
                "n/a"
                if lr["recall_mean"] is None
                else f"{lr['recall_mean']:.3f} ({lr['recall_std']:.3f}), Wilson 95% [{lr['wilson95'][0]:.2f}, {lr['wilson95'][1]:.2f}]"
            )
            lines.append(f"| {name} | {rec} |")
    lines += [
        "",
        "Types with a handful of lines (e.g. `escalate`, `webshell_upload`) have no statistical power; "
        "treat their recall as anecdotal.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=fetch.default_data_dir())
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument(
        "--save-model", type=Path, default=None, help="directory to write the API model"
    )
    args = ap.parse_args(argv)

    root = fetch.fetch(args.data_dir)
    events, unparsed = load_events(root)
    idx = split_events(events)

    # Sanity guard on the a-priori split: the benign periods must contain no labelled attack.
    leaked = sum(events[i].is_attack for k in ("train", "val") for i in idx[k])
    if leaked:
        msg = f"{leaked} attack lines fall in train/val; the temporal split is invalid"
        raise RuntimeError(msg)

    x = build_matrix(events, idx["train"])
    known = sorted({events[i].parsed["source_ip"] for i in idx["train"]})
    other_streams, other_unparsed = load_other_host_events(root)
    x_other = build_other_matrix(other_streams, known)
    test_attack = int(sum(events[i].is_attack for i in idx["test"]))
    results: dict[str, dict[str, dict]] = {}
    for variant in VARIANTS:
        cols = variant_columns(variant)
        scorers = make_scorers(cols.index(RATE_COL))
        res: dict[str, dict] = {}
        for name, fit in scorers.items():
            seeds = (0,) if name.startswith("rule") else SEEDS
            res[name] = aggregate([run_model(fit, x, cols, idx, events, s, x_other) for s in seeds])
        results[variant] = res

    metrics = {
        "meta": {
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": _git_commit(),
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
        },
        "dataset": {
            "name": "AIT Log Data Set V2.0, scenario russellmitchell, intranet_server Apache access log",
            "doi": "10.5281/zenodo.5789064",
            "license": "CC-BY-NC-SA-4.0",
            "manifest": json.loads(fetch.MANIFEST.read_text())["files"],
            "unparsed_lines": unparsed,
            "n_train": len(idx["train"]),
            "n_val": len(idx["val"]),
            "n_test": len(idx["test"]),
            "n_test_attack": test_attack,
            "test_prevalence": test_attack / len(idx["test"]),
            "base_rate": {"train": 0.0, "val": 0.0, "test": test_attack / len(idx["test"])},
            "n_other_hosts_benign_test": int(len(x_other)),
            "other_hosts_unparsed_lines": other_unparsed,
            "other_hosts": "webserver mail.smith + cloud.smith vhosts (unlabelled, benign by dataset convention)",
        },
        "protocol": {
            "train_end_utc": TRAIN_END.isoformat(),
            "val_end_utc": VAL_END.isoformat(),
            "threshold_quantile": THRESHOLD_QUANTILE,
            "seeds": list(SEEDS),
            "features": list(FEATURE_NAMES),
            "variants": {
                k: {"dropped": list(v["drop"]), "post_hoc": v["post_hoc"]}
                for k, v in VARIANTS.items()
            },
        },
        "results": results,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    (args.out / "report.md").write_text(render_report(metrics))
    print((args.out / "report.md").read_text())

    if args.save_model:
        # The served model uses the post-hoc variant (see VARIANTS); columns are stored with it.
        cols = variant_columns("no_calendar_features")
        ens = AnomalyEnsemble(random_state=0)
        ens.train(x[idx["train"]][:, cols])
        ens.save(args.save_model)
        _attach_metadata(args.save_model, events, idx, cols)
    return 0


def _attach_metadata(
    model_dir: Path, events: list, idx: dict[str, list[int]], cols: list[int]
) -> None:
    """Add serving metadata (known IPs, provenance) to the newest saved ensemble."""
    import joblib

    path = sorted(model_dir.glob("ensemble_*.joblib"))[-1]
    data = joblib.load(path)
    data["metadata"] = {
        "training_date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_samples": len(idx["train"]),
        "trained_on": "AIT-LDSv2 russellmitchell, 2022-01-21..22 (benign)",
        "known_ips": sorted({events[i].parsed["source_ip"] for i in idx["train"]}),
        "features": [FEATURE_NAMES[i] for i in cols],
        "feature_columns": cols,
    }
    joblib.dump(data, path)


if __name__ == "__main__":
    sys.exit(main())
