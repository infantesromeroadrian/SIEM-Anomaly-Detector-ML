from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np

from backend.eval import run
from backend.eval.dataset import (
    TRAIN_END,
    VAL_END,
    Event,
    load_events,
    read_labels,
    split_events,
)
from backend.eval.fetch import sha256_file
from backend.eval.metrics import choose_threshold, evaluate

LINE = '{ip} - - [{ts} +0000] "GET {path} HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'


def make_root(tmp_path):
    root = tmp_path / "ds"
    logs = root / "gather/intranet_server/logs/apache2"
    labels = root / "labels/intranet_server/logs/apache2"
    logs.mkdir(parents=True)
    labels.mkdir(parents=True)
    stem = "intranet.smith.russellmitchell.com-access.log"
    days = {4: "21/Jan/2022", 3: "22/Jan/2022", 2: "24/Jan/2022", 1: "24/Jan/2022"}
    for suffix, day in days.items():
        lines = [
            LINE.format(ip="10.0.0.1", ts=f"{day}:10:00:0{i}", path=f"/p{i}") for i in range(3)
        ]
        if suffix == 2:
            lines.append("garbage that cannot be parsed\n")
        (logs / f"{stem}.{suffix}").write_text("".join(lines))
    (labels / f"{stem}.2").write_text(
        json.dumps({"line": 2, "labels": ["dirb", "foothold"], "rules": {}}) + "\n"
    )
    return root


def test_read_labels_missing_file_is_empty(tmp_path):
    assert read_labels(tmp_path / "nope") == {}


def test_load_and_split(tmp_path):
    events, unparsed = load_events(make_root(tmp_path))
    assert unparsed == 1
    assert len(events) == 12
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    attacks = [e for e in events if e.is_attack]
    assert len(attacks) == 1 and "dirb" in attacks[0].labels
    idx = split_events(events)
    assert len(idx["train"]) == 6 and len(idx["val"]) == 0 and len(idx["test"]) == 6
    assert all(events[i].timestamp < TRAIN_END for i in idx["train"])
    assert all(events[i].timestamp >= VAL_END for i in idx["test"])


def test_split_boundaries():
    def ev(ts):
        return Event({}, ts, False)

    events = [
        ev(datetime(2022, 1, 22, 23, 59, 59, tzinfo=timezone.utc)),
        ev(TRAIN_END),
        ev(datetime(2022, 1, 23, 23, 59, 59, tzinfo=timezone.utc)),
        ev(VAL_END),
    ]
    idx = split_events(events)
    assert idx == {"train": [0], "val": [1, 2], "test": [3]}


def test_threshold_uses_only_given_scores():
    scores = np.arange(100, dtype=float)
    assert choose_threshold(scores, 0.99) == np.quantile(scores, 0.99)


def test_evaluate_metrics():
    y = np.array([1, 1, 0, 0, 1])
    scores = np.array([0.9, 0.8, 0.2, 0.6, 0.1])
    labels = [
        frozenset({"dirb"}),
        frozenset({"wpscan"}),
        frozenset(),
        frozenset(),
        frozenset({"dirb"}),
    ]
    out = evaluate(
        y,
        scores,
        0.5,
        labels,
        ("dirb", "wpscan", "escalate"),
        subset_mask=np.array([0, 0, 0, 0, 1]),
    )
    assert (out["tp"], out["fp"], out["fn"], out["tn"]) == (2, 1, 1, 1)
    assert abs(out["precision"] - 2 / 3) < 1e-9 and abs(out["recall"] - 2 / 3) < 1e-9
    assert out["fpr"] == 0.5
    assert out["recall_by_attack_type"]["dirb"] == {"n": 2, "recall": 0.5}
    assert np.isnan(out["recall_by_attack_type"]["escalate"]["recall"])
    assert out["recall_low_rate_attacks"] == {"n": 1, "recall": 0.0}
    assert 0 < out["pr_auc"] <= 1 and 0 < out["roc_auc"] <= 1


def test_evaluate_single_class_has_no_auc():
    out = evaluate(np.zeros(3), np.array([0.1, 0.2, 0.3]), 0.15, [frozenset()] * 3, ())
    assert out["pr_auc"] is None and out["roc_auc"] is None
    assert out["precision"] == 0.0 and out["f1"] == 0.0


def test_variant_columns_drop_calendar():
    all_cols = run.variant_columns("all_features")
    no_cal = run.variant_columns("no_calendar_features")
    assert len(all_cols) - len(no_cal) == 2
    assert run.RATE_COL in no_cal


def test_end_to_end_pipeline_on_synthetic_dataset(tmp_path):
    """Run the real pipeline code on a tiny generated dataset (determinism + schema)."""
    rng = np.random.default_rng(0)
    events = []
    for day, attack in ((21, False), (22, False), (23, False), (24, True)):
        for i in range(120):
            ts = datetime(2022, 1, day, 8, 0, tzinfo=timezone.utc).timestamp() + i * 30
            parsed = {
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc),
                "source_ip": "10.0.0.1",
                "endpoint": "/",
                "status_code": 200,
                "bytes_sent": int(rng.integers(100, 1000)),
                "user_agent": "Mozilla",
                "event_type": "http_request",
            }
            is_att = attack and i % 2 == 0
            if is_att:
                parsed["source_ip"] = "172.0.0.9"
                parsed["endpoint"] = f"/scan{i}"
                parsed["status_code"] = 404
                parsed["timestamp"] = datetime.fromtimestamp(ts + 0.1, tz=timezone.utc)
            events.append(
                Event(
                    parsed,
                    parsed["timestamp"],
                    is_att,
                    frozenset({"dirb"}) if is_att else frozenset(),
                )
            )
    events.sort(key=lambda e: e.timestamp)
    idx = split_events(events)
    x = run.build_matrix(events, idx["train"])
    cols = run.variant_columns("no_calendar_features")
    scorers = run.make_scorers(cols.index(run.RATE_COL))
    r1 = run.run_model(scorers["isolation_forest"], x, cols, idx, events, 0)
    r2 = run.run_model(scorers["isolation_forest"], x, cols, idx, events, 0)
    assert r1 == r2 or json.dumps(r1, default=str, sort_keys=True) == json.dumps(
        r2, default=str, sort_keys=True
    )
    agg = run.aggregate([r1, r2])
    assert agg["n_seeds"] == 2 and 0 <= agg["recall"]["mean"] <= 1
    assert r1["n_attack"] == 60


def test_render_report_contains_every_model():
    cell = {"mean": 0.5, "std": 0.0}
    res = {
        "precision": cell,
        "recall": cell,
        "f1": cell,
        "fpr": cell,
        "pr_auc": cell,
        "roc_auc": cell,
        "recall_by_attack_type": {
            t: {"n": 1, "recall_mean": 1.0, "recall_std": 0.0} for t in run.ATTACK_TYPES
        },
        "recall_low_rate_attacks": {
            "n": 0,
            "recall_mean": None,
            "recall_std": None,
            "wilson95": [None, None],
        },
        "fpr_other_hosts": {"n": 5, "mean": 0.1, "std": 0.0},
    }
    m = {
        "meta": {"generated_utc": "t", "git_commit": "abc" * 5},
        "dataset": {
            "name": "d",
            "license": "l",
            "n_train": 1,
            "n_val": 1,
            "n_test": 2,
            "n_test_attack": 1,
            "test_prevalence": 0.5,
        },
        "protocol": {
            "threshold_quantile": 0.99,
            "seeds": [0],
            "variants": {"v": {"dropped": ["x"], "post_hoc": True}},
        },
        "results": {"v": {"modelA": res}},
    }
    text = run.render_report(m)
    assert "modelA" in text and "POST-HOC" in text and "n/a" in text


def test_sha256_file(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_readme_results_block_is_generated_from_results_json():
    """Every figure in the README must come from results/*.json (traceability)."""
    from pathlib import Path

    from backend.eval import readme

    root = Path(__file__).resolve().parents[1]
    assert readme.update(root / "README.md", root / "results") == (root / "README.md").read_text()


def test_wilson_interval():
    from backend.eval.metrics import wilson_interval

    lo, hi = wilson_interval(0, 19)
    assert lo == 0.0 and 0.15 < hi < 0.19
    lo, hi = wilson_interval(19, 19)
    assert hi == 1.0 and 0.8 < lo < 0.85
    assert all(np.isnan(v) for v in wilson_interval(0, 0))
    lo, hi = wilson_interval(10, 20)
    assert lo < 0.5 < hi


def test_combined_scorer_alerts_when_either_component_fires():
    rng = np.random.default_rng(0)
    n_feat = len(run.FEATURE_NAMES)
    cols = run.variant_columns("no_calendar_features")
    x_train = rng.normal(1, 0.1, (300, len(cols)))
    x_val = rng.normal(1, 0.1, (200, len(cols)))
    rate_pos = cols.index(run.RATE_COL)
    x_train[:, rate_pos] = x_val[:, rate_pos] = 0.01
    fit = run.make_scorers(rate_pos)["combined_rule_or_isolation_forest"]
    score = fit(x_train, 0, x_val)
    assert score.fixed_threshold == run.THRESHOLD_QUANTILE
    flood = x_val[:5].copy()
    flood[:, rate_pos] = 5.0  # volumetric: rule fires
    odd = x_val[:5].copy()
    odd[:] = 100.0  # far outside the training support: Isolation Forest fires
    odd[:, rate_pos] = 0.01  # ... while the volume rule stays quiet
    normal = x_val[:5]
    thr = score.fixed_threshold
    assert (score(flood) > thr).all() and (score(odd) > thr).all()
    assert (score(normal) <= thr).all()
    assert n_feat > len(cols)


def test_load_other_host_events_and_matrix(tmp_path):
    from backend.eval.dataset import load_other_host_events
    from backend.eval.fetch import OTHER_HOST_LOGS

    root = tmp_path
    for rel in OTHER_HOST_LOGS:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        day = "24/Jan/2022" if rel.endswith(".1") else "21/Jan/2022"
        p.write_text(LINE.format(ip="10.1.1.1", ts=f"{day}:10:00:00", path="/a") + "bad line\n")
    streams, unparsed = load_other_host_events(root)
    assert set(streams) == {"mail", "cloud"} and unparsed == len(OTHER_HOST_LOGS)
    x = run.build_other_matrix(streams, ["10.1.1.1"])
    assert x.shape == (2, len(run.FEATURE_NAMES))  # only the 24 Jan lines of each vhost


def test_readme_headline_figures_match_metrics():
    """The few literal figures in the README headline must agree with results/metrics.json."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    m = json.loads((root / "results/metrics.json").read_text())
    rule = m["results"]["all_features"]["rule_requests_per_60s"]
    assert round(rule["f1"]["mean"], 3) == 0.999 and rule["fpr"]["mean"] == 0.0
    iso = m["results"]["all_features"]["isolation_forest"]
    low = iso["recall_low_rate_attacks"]
    assert round(rule["fpr_other_hosts"]["mean"] * 100, 1) == 55.7
    assert round(iso["fpr_other_hosts"]["mean"] * 100, 2) == 0.02
    assert round(low["recall_mean"], 2) == 0.78
    assert [round(v, 2) for v in low["wilson95"]] == [0.57, 0.91]
    text = (root / "README.md").read_text()
    for claim in (
        "F1 0.999, FPR 0 %",
        "55.7 %",
        "0.02 %",
        "0.78 [0.57, 0.91]",
        "by convention",
        "added after the first",
    ):
        assert claim in text
