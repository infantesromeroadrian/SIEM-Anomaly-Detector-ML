# ML architecture

This document describes what the code does today. Measured results live in
[`../results/report.md`](../results/report.md); nothing here is a performance target.

## Pipeline

```
raw line -> parser (ParsedLog) -> FeatureEngineer.extract_sync -> 21-d vector
         -> IsolationForest (default) [+ opt-in DBSCAN, GMM on scaled features] -> risk in [0, 1]
```

- **Features** (`backend/ml/features.py`): temporal, per-IP sliding-window rates and ratios (60 s / 5 min),
  request-content statistics (length, special-character ratio, entropy), context flags. Deterministic, causal,
  in-memory (`WindowedAggregator`), memory bounded by `MAX_TRACKED_IPS` and `MAX_EVENTS_PER_IP`.
- **Scoring** (`backend/ml/scoring.py`, shared by `AnomalyEnsemble` and `ModelLoader`):
  - Isolation Forest: `sigmoid(-10 * decision_function)`.
  - GMM: `sigmoid(-0.5 * (log_likelihood + 10))`.
  - DBSCAN: no `predict`; a point joins the nearest cluster centroid if within `2*eps`, otherwise scores 0.9.
  - Risk = w_IF * IF + w_DBSCAN * DBSCAN + w_GMM * GMM with `ENSEMBLE_WEIGHTS` defaulting to `1.0,0.0,0.0`:
    components with weight 0 are neither trained nor scored. DBSCAN and GMM were retired from the default
    because they added nothing measurable (and the GMM generalised badly to other hosts); the legacy
    0.5/0.3/0.2 ensemble is still evaluated in the report for reference.
  The sigmoid constants and the 0.9 outlier score are heuristics. On the AIT data the GMM and DBSCAN parts
  saturate to constants, so the original ensemble reduced to Isolation Forest (see the report).
- **Alert levels** (`ALERT_THRESHOLD_*`): 0.4 / 0.6 / 0.8 on the risk score. Not calibrated.

## Training and evaluation

- `python -m backend.eval.run` (or `make reproduce`): fetch and verify the dataset, split by day, fit on the
  benign training period, fix a 99% validation-quantile threshold per model, score the test period once per
  seed, write `results/metrics.json` and `results/report.md`.
- Baselines: Isolation Forest alone, and a volume rule (requests per source IP in the last 60 s).
- `scripts/train_demo_model.py` trains on synthetic benign traffic so the container can start offline. It is
  never evaluated.

## Known weaknesses

- Heuristic score normalisation (above); no probability calibration.
- Calendar features need long enough training windows to be meaningful; with 2 days they leave the training
  support on the next day. The `no_calendar_features` variant (post-hoc) drops them.
- Feature state is per process; no shared store.
- Model files are pickles (`joblib`).
