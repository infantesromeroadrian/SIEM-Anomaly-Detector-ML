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
from backend.ml.features import FeatureEngineer, LogFeatures

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

    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return all(
            [
                self.isolation_forest is not None,
                self.dbscan is not None,
                self.gmm is not None,
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
            ensemble_weights: Custom weights [IF, DBSCAN, GMM]. Defaults to [0.5, 0.3, 0.2]

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
            ensemble_weights = [0.5, 0.3, 0.2]

        start_time = time.time()

        # Convert features to array
        X = features.to_array().reshape(1, -1)
        X_scaled = self.scaler.transform(X)  # type: ignore[union-attr]

        # ========================================================================
        # Isolation Forest Score
        # ========================================================================
        # decision_function: negative for outliers, positive for inliers
        # We convert to 0-1 scale where 1 = anomaly
        if_decision = self.isolation_forest.decision_function(X)[0]  # type: ignore[union-attr]

        # Sigmoid transformation: more negative → higher score
        if_score = 1.0 / (1.0 + np.exp(if_decision * 10))

        # ========================================================================
        # GMM Score
        # ========================================================================
        # score_samples: log-likelihood (higher = more likely)
        # We convert to anomaly score (lower likelihood = higher anomaly)
        gmm_log_likelihood = self.gmm.score_samples(X_scaled)[0]  # type: ignore[union-attr]

        # Normalize: typical range is -20 to 0
        # Lower likelihood → higher score
        gmm_score = 1.0 / (1.0 + np.exp((gmm_log_likelihood + 10) * 0.5))

        # ========================================================================
        # DBSCAN Score
        # ========================================================================
        # DBSCAN doesn't have predict(), so we find nearest cluster centroid
        dbscan_prediction = self._predict_dbscan(X_scaled[0])

        if dbscan_prediction == -1:
            # Outlier - far from all clusters
            dbscan_score = 0.9
        else:
            # Part of cluster - calculate distance to centroid
            if dbscan_prediction in self._cluster_centroids:
                centroid = self._cluster_centroids[dbscan_prediction]
                distance = np.linalg.norm(X_scaled[0] - centroid)
                # Normalize distance to [0, 1]
                dbscan_score = min(distance / 5.0, 1.0)
            else:
                # Cluster not found (shouldn't happen, but handle gracefully)
                dbscan_score = 0.5

        # ========================================================================
        # Ensemble Aggregation
        # ========================================================================
        final_score = (
            ensemble_weights[0] * if_score
            + ensemble_weights[1] * dbscan_score
            + ensemble_weights[2] * gmm_score
        )

        # Determine if anomaly using configurable threshold
        # Default threshold: 0.6 (medium risk)
        # Can be changed via ALERT_THRESHOLD_MEDIUM env var
        is_anomaly = final_score >= settings.alert_threshold_medium

        # ========================================================================
        # Feature Importance (simplified)
        # ========================================================================
        # For Isolation Forest, we can approximate feature importance
        # by checking which features deviate most from mean
        feature_names = [
            "hour_of_day",
            "day_of_week",
            "is_weekend",
            "is_business_hours",
            "login_attempts_per_minute",
            "requests_per_second",
            "unique_ips_last_hour",
            "unique_endpoints_accessed",
            "failed_auth_rate",
            "error_rate_4xx",
            "error_rate_5xx",
            "geographic_distance_km",
            "is_known_country",
            "is_known_ip",
            "bytes_transferred_log",
            "time_since_last_activity_sec",
            "session_duration_sec",
            "payload_entropy",
            "is_privileged_user",
            "is_sensitive_endpoint",
            "is_known_user_agent",
        ]

        # Get feature deviations (absolute z-scores)
        feature_deviations = np.abs(X_scaled[0])
        top_indices = np.argsort(feature_deviations)[-5:][::-1]  # Top 5

        important_features = [(feature_names[i], float(feature_deviations[i])) for i in top_indices]

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

    def _predict_dbscan(self, X_point: np.ndarray) -> int:
        """
        Predict DBSCAN cluster for new point without refitting.

        Finds nearest cluster centroid and checks if point is within eps radius.

        Args:
            X_point: Single scaled data point

        Returns:
            Cluster label (-1 for outlier, >= 0 for cluster)
        """
        if not self._cluster_centroids:
            # No clusters available, classify as outlier
            return -1

        # Find nearest cluster centroid
        min_distance = float("inf")
        nearest_cluster = -1

        for label, centroid in self._cluster_centroids.items():
            distance = np.linalg.norm(X_point - centroid)
            if distance < min_distance:
                min_distance = distance
                nearest_cluster = label

        # Check if point is within eps radius (use 2*eps for lenient threshold)
        if self.dbscan is not None:
            eps_threshold = self.dbscan.eps * 2.0
            if min_distance <= eps_threshold:
                return nearest_cluster

        # Too far from any cluster → outlier
        return -1


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
