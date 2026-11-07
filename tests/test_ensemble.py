from __future__ import annotations

import numpy as np
import pytest

from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES, LogFeatures
from backend.ml.scoring import dbscan_scores


def test_scores_have_expected_shape_and_range(trained_ensemble, benign_matrix):
    s = trained_ensemble.score_batch(benign_matrix[:50])
    assert set(s) == {"isolation_forest", "dbscan", "gmm", "risk"}
    for v in s.values():
        assert v.shape == (50,)
        assert np.all((v >= 0) & (v <= 1))


def test_deterministic_with_seed(benign_matrix):
    def fit():
        e = AnomalyEnsemble(
            ensemble_weights=[0.5, 0.3, 0.2], random_state=7, dbscan_min_samples=5, dbscan_eps=3.0
        )
        e.train(benign_matrix)
        return e.score_batch(benign_matrix[:40])["risk"]

    assert np.array_equal(fit(), fit())


def test_different_seeds_can_differ(benign_matrix):
    def fit(seed):
        e = AnomalyEnsemble(
            ensemble_weights=[0.5, 0.3, 0.2],
            random_state=seed,
            dbscan_min_samples=5,
            dbscan_eps=3.0,
        )
        e.train(benign_matrix)
        return e.score_batch(benign_matrix[:40])["isolation_forest"]

    assert not np.array_equal(fit(1), fit(2))


def test_outlier_scores_higher_than_inliers(trained_ensemble, benign_matrix):
    outlier = np.full((1, benign_matrix.shape[1]), 50.0, dtype=np.float32)
    assert trained_ensemble.score_batch(outlier)["risk"][0] > np.median(
        trained_ensemble.score_batch(benign_matrix)["risk"]
    )


def test_untrained_raises():
    with pytest.raises(RuntimeError, match="trained"):
        AnomalyEnsemble().score_batch(np.zeros((1, len(FEATURE_NAMES))))


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="sum to 1.0"):
        AnomalyEnsemble(ensemble_weights=[0.5, 0.5, 0.5])


def _features(**over):
    base = dict.fromkeys(FEATURE_NAMES, 0)
    base.update(over)
    return LogFeatures(**{k: base[k] for k in FEATURE_NAMES})


def test_predict_returns_result(trained_ensemble):
    r = trained_ensemble.predict(_features(requests_per_second=0.5))
    assert 0 <= r.risk_score <= 1
    assert r.confidence in {"low", "medium", "high"}
    assert len(r.important_features) == 5
    assert all(name in FEATURE_NAMES for name, _ in r.important_features)


def test_predict_untrained_raises():
    with pytest.raises(RuntimeError):
        AnomalyEnsemble().predict(_features())


def test_save_and_load_roundtrip(trained_ensemble, benign_matrix, tmp_path):
    trained_ensemble.save(tmp_path)
    path = next(tmp_path.glob("ensemble_*.joblib"))
    loaded = AnomalyEnsemble.load(path)
    assert loaded.is_trained
    assert np.allclose(
        loaded.score_batch(benign_matrix[:30])["risk"],
        trained_ensemble.score_batch(benign_matrix[:30])["risk"],
    )


def test_dbscan_scores_without_clusters_are_outliers():
    out = dbscan_scores(np.zeros((3, 2)), {}, eps=1.0)
    assert np.all(out == 0.9)


def test_get_ensemble_singleton(monkeypatch, tmp_path):
    import backend.ml.ensemble as mod

    monkeypatch.setattr(mod, "_global_ensemble", None)
    monkeypatch.setattr(mod.settings, "model_path", tmp_path)
    assert mod.get_ensemble() is mod.get_ensemble()


def test_default_is_isolation_forest_only_and_skips_other_components(benign_matrix):
    e = AnomalyEnsemble(random_state=0)
    assert e.ensemble_weights == [1.0, 0.0, 0.0]
    e.train(benign_matrix)
    assert e._cluster_centroids == {} and not hasattr(e.gmm, "weights_")
    s = e.score_batch(benign_matrix[:10])
    assert np.all(s["dbscan"] == 0) and np.all(s["gmm"] == 0)
    assert np.allclose(s["risk"], s["isolation_forest"])
