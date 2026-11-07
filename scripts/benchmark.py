#!/usr/bin/env python3
"""
Measure in-process scoring throughput (parse + features + ensemble score, one event at a time).

This excludes HTTP, PostgreSQL and Redis, so it is an upper bound for the model path only,
not an API throughput figure. Hardware and library versions are recorded in the output.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import sklearn

from backend.eval import fetch
from backend.eval.dataset import load_events, split_events
from backend.eval.run import build_matrix, variant_columns
from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FeatureEngineer
from backend.parsers.nginx import NginxParser


def cpu_model() -> str:
    """Return the CPU model string (Linux) or the platform processor."""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main() -> int:
    """Run the benchmark."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("results/benchmark.json"))
    ap.add_argument("--data-dir", type=Path, default=fetch.default_data_dir())
    args = ap.parse_args()

    events, _ = load_events(fetch.fetch(args.data_dir))
    idx = split_events(events)
    cols = variant_columns("no_calendar_features")
    x = build_matrix(events, idx["train"])
    model = AnomalyEnsemble(random_state=0)
    model.train(x[idx["train"]][:, cols])

    raw = [e.parsed["payload"] for e in events if e.timestamp >= events[idx["test"][0]].timestamp][
        :3000
    ]
    parser = NginxParser()
    fe = FeatureEngineer(config={"known_ips": ["127.0.0.1"]})
    lat = []
    t_all = time.perf_counter()
    for line in raw:
        t0 = time.perf_counter()
        feats = fe.extract_sync(parser.parse(line).to_dict())
        model.score_batch(feats.to_array().reshape(1, -1)[:, cols])
        lat.append((time.perf_counter() - t0) * 1000)
    total = time.perf_counter() - t_all
    result = {
        "events": len(raw),
        "events_per_second": len(raw) / total,
        "latency_ms_p50": float(np.percentile(lat, 50)),
        "latency_ms_p95": float(np.percentile(lat, 95)),
        "latency_ms_p99": float(np.percentile(lat, 99)),
        "scope": "single process, in-memory, parse+features+score; excludes HTTP/DB/Redis",
        "hardware": {"cpu": cpu_model(), "platform": platform.platform()},
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
