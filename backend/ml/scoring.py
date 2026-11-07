"""
Vectorised scoring shared by ``AnomalyEnsemble`` and ``ModelLoader``.

Keeping one implementation avoids the two code paths drifting apart.
Scores are monotone transforms of each model's native anomaly signal, mapped
to [0, 1]. The sigmoid constants are heuristics; operational thresholds must be
fixed on held-out benign data (see ``backend/eval``), not read from these values.
"""

from __future__ import annotations

from typing import Any

import numpy as np

#: DBSCAN score assigned to points that fall outside every cluster.
DBSCAN_OUTLIER_SCORE = 0.9
#: Distance (in scaled units) mapped to a DBSCAN score of 1.0.
DBSCAN_DISTANCE_SCALE = 10.0


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -50.0, 50.0)))


def dbscan_scores(
    x_scaled: np.ndarray,
    centroids: dict[int, np.ndarray],
    eps: float,
) -> np.ndarray:
    """
    Score points against DBSCAN cluster centroids.

    DBSCAN has no ``predict``; a point joins the nearest cluster if it lies
    within ``2 * eps`` of its centroid, otherwise it is an outlier.
    """
    n = x_scaled.shape[0]
    if not centroids:
        return np.full(n, DBSCAN_OUTLIER_SCORE)
    cent = np.stack(list(centroids.values()))
    dist = np.linalg.norm(x_scaled[:, None, :] - cent[None, :, :], axis=2)
    nearest = dist.min(axis=1)
    scores = np.minimum(nearest / DBSCAN_DISTANCE_SCALE, 1.0)
    scores[nearest > 2.0 * eps] = DBSCAN_OUTLIER_SCORE
    return scores


def score_arrays(
    x: np.ndarray,
    *,
    isolation_forest: Any,
    dbscan: Any,
    gmm: Any,
    scaler: Any,
    centroids: dict[int, np.ndarray],
    weights: list[float],
) -> dict[str, np.ndarray]:
    """
    Score a batch of feature vectors.

    Returns:
        Dict with ``isolation_forest``, ``dbscan``, ``gmm`` and ``risk`` arrays of shape (n,).
    """
    x = np.atleast_2d(x)
    x_scaled = scaler.transform(x)
    n = x.shape[0]
    if_score = _sigmoid(-10.0 * isolation_forest.decision_function(x))
    # Components with zero weight are not trained and not scored.
    gmm_score = (
        _sigmoid(-0.5 * (gmm.score_samples(x_scaled) + 10.0)) if weights[2] > 0 else np.zeros(n)
    )
    db_score = dbscan_scores(x_scaled, centroids, dbscan.eps) if weights[1] > 0 else np.zeros(n)
    risk = weights[0] * if_score + weights[1] * db_score + weights[2] * gmm_score
    return {
        "isolation_forest": if_score,
        "dbscan": db_score,
        "gmm": gmm_score,
        "risk": np.clip(risk, 0.0, 1.0),
    }
