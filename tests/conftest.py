"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def access_lines() -> list[str]:
    return (FIXTURES / "access_log_sample.txt").read_text().splitlines()


@pytest.fixture(scope="session")
def auth_lines() -> list[str]:
    return (FIXTURES / "auth_log_sample.txt").read_text().splitlines()


@pytest.fixture(scope="session")
def benign_matrix() -> np.ndarray:
    """Small deterministic 'normal' feature matrix with the real column count."""
    rng = np.random.default_rng(0)
    x = rng.normal(loc=1.0, scale=0.3, size=(300, len(FEATURE_NAMES))).astype(np.float32)
    return x


@pytest.fixture(scope="session")
def trained_ensemble(benign_matrix: np.ndarray) -> AnomalyEnsemble:
    ens = AnomalyEnsemble(
        ensemble_weights=[0.5, 0.3, 0.2], random_state=0, dbscan_min_samples=5, dbscan_eps=3.0
    )
    ens.train(benign_matrix)
    return ens


@pytest.fixture
def reset_singletons(monkeypatch: pytest.MonkeyPatch):
    """Fresh model loader and feature engineer for each API test."""
    import backend.ml.features as features
    import backend.ml.model_loader as model_loader

    monkeypatch.setattr(model_loader, "_model_loader", None)
    monkeypatch.setattr(model_loader.ModelLoader, "_instance", None)
    monkeypatch.setattr(model_loader.ModelLoader, "_initialized", False)
    monkeypatch.setattr(features, "_feature_engineer", None)
