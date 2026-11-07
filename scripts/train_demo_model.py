#!/usr/bin/env python3
"""
Train a DEMO model on synthetic benign web traffic so `docker compose up` works offline.

This model exists only to exercise the API. It is trained on randomly generated
requests, has not been evaluated and must not be used to draw conclusions about
detection quality. The evaluated model is produced by `make reproduce`
(see results/report.md).
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES, FeatureEngineer
from backend.parsers.nginx import NginxParser

PATHS = ["/", "/index.html", "/login", "/api/items", "/static/app.js", "/static/site.css", "/about"]
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", "Mozilla/5.0 (Macintosh) Safari/605.1"]
DROP = ("day_of_week", "is_weekend")  # same rationale as backend/eval/run.py


def synthetic_lines(n: int, seed: int) -> list[str]:
    """Generate ``n`` benign combined-format access-log lines from a few users."""
    rng = random.Random(seed)
    t = datetime(2026, 1, 5, 8, 0, tzinfo=timezone.utc)
    ips = [f"10.0.0.{i}" for i in range(10, 25)]
    out = []
    for _ in range(n):
        t += timedelta(seconds=rng.expovariate(1 / 20))
        out.append(
            f"{rng.choice(ips)} - - [{t.strftime('%d/%b/%Y:%H:%M:%S')} +0000] "
            f'"GET {rng.choice(PATHS)} HTTP/1.1" {rng.choices([200, 304, 404], [90, 6, 4])[0]} '
            f'{rng.randint(200, 20000)} "-" "{rng.choice(AGENTS)}"'
        )
    return out


def main() -> int:
    """Train and save the demo model."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("models"))
    ap.add_argument("--n", type=int, default=3000)
    args = ap.parse_args()

    parser = NginxParser()
    parsed = [parser.parse(line).to_dict() for line in synthetic_lines(args.n, seed=0)]
    known = sorted({p["source_ip"] for p in parsed})
    fe = FeatureEngineer(config={"known_ips": known})
    x = np.stack([fe.extract_sync(p).to_array() for p in parsed])
    cols = [i for i, f in enumerate(FEATURE_NAMES) if f not in DROP]

    ens = AnomalyEnsemble(random_state=0)
    ens.train(x[:, cols])
    ens.save(args.out)
    path = sorted(args.out.glob("ensemble_*.joblib"))[-1]
    data = joblib.load(path)
    data["metadata"] = {
        "training_date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_samples": int(len(x)),
        "trained_on": "SYNTHETIC DEMO DATA - not evaluated",
        "known_ips": known,
        "features": [FEATURE_NAMES[i] for i in cols],
        "feature_columns": cols,
    }
    joblib.dump(data, path)
    print(f"demo model written to {path} (synthetic data, not evaluated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
