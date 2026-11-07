from __future__ import annotations

import joblib
import numpy as np
import pytest

from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES, FeatureEngineer
from backend.ml.model_loader import ModelLoader, get_model_loader


def test_missing_file_raises(tmp_path, reset_singletons):
    with pytest.raises(FileNotFoundError):
        ModelLoader().load_model(tmp_path / "nope.joblib")


def test_empty_directory_raises(tmp_path, reset_singletons):
    with pytest.raises(FileNotFoundError, match="No ensemble"):
        ModelLoader().load_model(tmp_path)


def test_corrupted_model_raises_value_error(tmp_path, reset_singletons):
    bad = tmp_path / "ensemble_bad.joblib"
    bad.write_bytes(b"not a joblib file")
    with pytest.raises(ValueError, match="Failed to load"):
        ModelLoader().load_model(bad)


def test_predict_without_model_raises(reset_singletons):
    loader = ModelLoader()
    assert not loader.is_loaded()
    fe = FeatureEngineer()
    feats = fe.extract_sync({"source_ip": "1.1.1.1", "endpoint": "/"})
    with pytest.raises(RuntimeError, match="not loaded"):
        loader.predict(feats)


def test_load_directory_and_predict_with_metadata(trained_ensemble, tmp_path, reset_singletons):
    cols = list(range(len(FEATURE_NAMES) - 2))
    meta = {"known_ips": ["10.9.9.9"], "feature_columns": cols, "training_date": "t"}
    # Train on the column subset so shapes agree with the metadata.
    sub = AnomalyEnsemble(
        ensemble_weights=[0.5, 0.3, 0.2], random_state=0, dbscan_min_samples=5, dbscan_eps=3.0
    )
    sub.train(np.random.default_rng(0).normal(1, 0.3, (200, len(cols))).astype(np.float32))
    sub.save(tmp_path / "sub")
    sub_path = next((tmp_path / "sub").glob("ensemble_*.joblib"))
    sub_data = joblib.load(sub_path)
    sub_data["metadata"] = meta
    joblib.dump(sub_data, sub_path)

    loader = get_model_loader()
    loader.load_model(tmp_path / "sub")
    assert loader.is_loaded()
    from backend.ml.features import get_feature_engineer

    assert "10.9.9.9" in get_feature_engineer().known_ips
    feats = FeatureEngineer().extract_sync({"source_ip": "1.1.1.1", "endpoint": "/x"})
    out = loader.predict(feats, ensemble_weights=[0.5, 0.3, 0.2])
    assert 0 <= out["risk_score"] <= 1
    assert len(out["important_features"]) == 5
    assert out["model_version"] == "t"


def test_initialize_model(trained_ensemble, tmp_path, reset_singletons):
    from backend.ml.model_loader import initialize_model

    trained_ensemble.save(tmp_path)
    initialize_model(tmp_path)
    assert get_model_loader().is_loaded()
