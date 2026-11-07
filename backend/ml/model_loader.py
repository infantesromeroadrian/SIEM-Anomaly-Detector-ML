"""
Model loader with singleton pattern.

Loads the trained ML ensemble once and provides prediction interface.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import structlog
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

from backend.config import settings
from backend.ml.features import FEATURE_NAMES, FeatureEngineer, LogFeatures
from backend.ml.scoring import score_arrays

logger = structlog.get_logger(__name__)


class ModelLoader:
    """
    Singleton model loader for ML ensemble.

    Loads model once and keeps in memory for fast predictions.
    Thread-safe for concurrent requests.
    """

    _instance: ModelLoader | None = None
    _initialized: bool = False

    def __new__(cls) -> ModelLoader:
        """Create singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize model loader (only once)."""
        if not self._initialized:
            self.model_path: Path | None = None
            self.isolation_forest: IsolationForest | None = None
            self.dbscan: DBSCAN | None = None
            self.gmm: GaussianMixture | None = None
            self.scaler: StandardScaler | None = None
            self.metadata: dict[str, Any] = {}
            self.feature_cols: list[int] | None = None
            self.feature_engineer: FeatureEngineer | None = None

            # DBSCAN training data for prediction
            self._X_scaled_training: np.ndarray | None = None
            self._cluster_centroids: dict[int, np.ndarray] = {}

            self._initialized = True

    def load_model(self, model_path: Path | str) -> None:
        """
        Load trained ensemble from disk.

        Args:
            model_path: Path to joblib file with ensemble

        Raises:
            FileNotFoundError: If model file doesn't exist
            ValueError: If model file is corrupted
        """
        model_path = Path(model_path)
        if model_path.is_dir():
            candidates = sorted(model_path.glob("ensemble_*.joblib"))
            if not candidates:
                msg = f"No ensemble_*.joblib found in {model_path}"
                raise FileNotFoundError(msg)
            model_path = candidates[-1]
        if not model_path.exists():
            msg = f"Model file not found: {model_path}"
            raise FileNotFoundError(msg)

        logger.info("loading_model", path=str(model_path))
        start_time = time.time()

        try:
            ensemble = joblib.load(model_path)

            # Extract components
            self.isolation_forest = ensemble["isolation_forest"]
            self.dbscan = ensemble["dbscan"]
            self.gmm = ensemble["gmm"]
            self.scaler = ensemble["scaler"]
            self.metadata = ensemble.get("metadata", {})
            self.feature_cols: list[int] | None = self.metadata.get("feature_columns")
            self._apply_serving_metadata()
            self.model_path = model_path

            # Load DBSCAN training data for prediction
            self._X_scaled_training = ensemble.get("_X_scaled_training")
            self._cluster_centroids = ensemble.get("_cluster_centroids", {})

            load_time = (time.time() - start_time) * 1000

            logger.info(
                "model_loaded",
                path=str(model_path),
                load_time_ms=round(load_time, 2),
                n_samples_trained=self.metadata.get("n_samples", "unknown"),
                training_date=self.metadata.get("training_date", "unknown"),
            )

        except Exception as e:
            logger.exception("model_load_failed", path=str(model_path))
            raise ValueError(f"Failed to load model: {e}") from e

    def _apply_serving_metadata(self) -> None:
        """Register the training-time IP allow-list with the process-wide feature engineer."""
        known = self.metadata.get("known_ips")
        if known:
            from backend.ml.features import get_feature_engineer

            get_feature_engineer().known_ips |= set(known)

    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return all(
            [
                self.isolation_forest is not None,
                self.scaler is not None,
            ]
        )

    def predict(
        self,
        features: LogFeatures,
        ensemble_weights: list[float] | None = None,
    ) -> dict[str, Any]:
        """
        Predict anomaly score for log features.

        Args:
            features: Extracted log features
            ensemble_weights: Custom weights [IF, DBSCAN, GMM]. Defaults to [1.0, 0.0, 0.0]

        Returns:
            Dictionary with:
                - risk_score: Aggregated score (0.0-1.0)
                - isolation_forest_score: IF score
                - dbscan_score: DBSCAN score
                - gmm_score: GMM score
                - is_anomaly: Boolean flag
                - important_features: Top contributing features

        Raises:
            RuntimeError: If model not loaded
        """
        if not self.is_loaded():
            msg = "Model not loaded. Call load_model() first."
            raise RuntimeError(msg)

        if ensemble_weights is None:
            ensemble_weights = [1.0, 0.0, 0.0]

        start_time = time.time()
        X = features.to_array().reshape(1, -1)
        names = FEATURE_NAMES
        if getattr(self, "feature_cols", None):
            X = X[:, self.feature_cols]
            names = tuple(FEATURE_NAMES[i] for i in self.feature_cols)
        scores = score_arrays(
            X,
            isolation_forest=self.isolation_forest,
            dbscan=self.dbscan,
            gmm=self.gmm,
            scaler=self.scaler,
            centroids=self._cluster_centroids,
            weights=ensemble_weights,
        )
        if_score = float(scores["isolation_forest"][0])
        dbscan_score = float(scores["dbscan"][0])
        gmm_score = float(scores["gmm"][0])
        final_score = float(scores["risk"][0])
        is_anomaly = final_score >= settings.alert_threshold_medium

        # Feature attribution: absolute z-scores (a heuristic, not SHAP)
        feature_deviations = np.abs(self.scaler.transform(X)[0])  # type: ignore[union-attr]
        top_indices = np.argsort(feature_deviations)[-5:][::-1]
        important_features = [(names[i], float(feature_deviations[i])) for i in top_indices]

        processing_time = (time.time() - start_time) * 1000

        return {
            "risk_score": float(final_score),
            "isolation_forest_score": float(if_score),
            "dbscan_score": float(dbscan_score),
            "gmm_score": float(gmm_score),
            "is_anomaly": bool(is_anomaly),
            "important_features": important_features,
            "processing_time_ms": float(processing_time),
            "model_version": self.metadata.get("training_date", "unknown"),
        }


# Global singleton instance
_model_loader: ModelLoader | None = None


def get_model_loader() -> ModelLoader:
    """
    Get global model loader instance.

    Returns:
        ModelLoader singleton

    Example:
        >>> loader = get_model_loader()
        >>> loader.load_model("models/ensemble.joblib")
        >>> result = loader.predict(features)
    """
    global _model_loader
    if _model_loader is None:
        _model_loader = ModelLoader()
    return _model_loader


def initialize_model(model_path: Path | str) -> None:
    """
    Initialize model at application startup.

    Args:
        model_path: Path to ensemble model file
    """
    loader = get_model_loader()
    loader.load_model(model_path)
    logger.info("model_initialized", path=str(model_path))
