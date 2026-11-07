"""
ML Ensemble for anomaly detection.

Combines Isolation Forest, DBSCAN, and GMM for robust anomaly detection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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

#: Isolation Forest only. DBSCAN and GMM stay available as opt-in components, but on the AIT-LDSv2
#: evaluation they added nothing measurable on the held-out protocol (see results/report.md).
DEFAULT_WEIGHTS = (1.0, 0.0, 0.0)


@dataclass
class AnomalyResult:
    """
    Result of anomaly detection analysis.

    Contains individual model scores and aggregated result.
    """

    is_anomaly: bool
    risk_score: float  # 0.0 - 1.0 (aggregated)
    confidence: str  # "low", "medium", "high"

    # Individual model scores
    isolation_forest_score: float
    dbscan_score: float
    gmm_score: float

    # Feature importance (which features contributed most)
    important_features: list[tuple[str, float]]

    # Processing metrics
    processing_time_ms: float
    model_version: str


class AnomalyEnsemble:
    """
    Ensemble of ML models for anomaly detection.

    Combines:
    - Isolation Forest: Fast outlier detection
    - DBSCAN: Density-based clustering
    - GMM: Probabilistic anomaly detection
    """

    def __init__(
        self,
        contamination: float = 0.03,
        n_estimators: int = 100,
        dbscan_eps: float = 1.5,
        dbscan_min_samples: int = 50,
        gmm_n_components: int = 3,
        ensemble_weights: list[float] | None = None,
        random_state: int = 42,
    ) -> None:
        """
        Initialize anomaly ensemble.

        Args:
            contamination: Expected proportion of anomalies (0.0-0.5)
            n_estimators: Number of trees in Isolation Forest
            dbscan_eps: DBSCAN eps parameter
            dbscan_min_samples: DBSCAN min_samples parameter
            gmm_n_components: Number of GMM components
            ensemble_weights: Weights for [IF, DBSCAN, GMM]. Defaults to [1.0, 0.0, 0.0] (Isolation Forest only);
                a component with weight 0 is neither trained nor scored
            random_state: Seed for Isolation Forest and GMM
        """
        self.contamination = contamination
        self.ensemble_weights = ensemble_weights or list(DEFAULT_WEIGHTS)

        # Validate weights
        if not np.isclose(sum(self.ensemble_weights), 1.0):
            msg = f"Ensemble weights must sum to 1.0, got {sum(self.ensemble_weights)}"
            raise ValueError(msg)

        # Initialize models
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,
        )

        self.dbscan = DBSCAN(
            eps=dbscan_eps,
            min_samples=dbscan_min_samples,
            n_jobs=-1,
        )

        self.gmm = GaussianMixture(
            n_components=gmm_n_components,
            covariance_type="full",
            random_state=random_state,
            n_init=10,
        )

        # Scaler for DBSCAN and GMM (IF doesn't need scaling)
        self.scaler = StandardScaler()

        # Feature engineer
        self.feature_engineer = FeatureEngineer()

        # Training state
        self.is_trained = False
        self.model_version = "v1.0.0"
        self.trained_at: datetime | None = None
        self.n_training_samples = 0

        # Store training data for DBSCAN prediction
        self._X_scaled_training: np.ndarray | None = None
        self._cluster_centroids: dict[int, np.ndarray] = {}

        logger.info(
            "anomaly_ensemble_initialized",
            contamination=contamination,
            n_estimators=n_estimators,
            ensemble_weights=self.ensemble_weights,
        )

    def train(self, X: np.ndarray) -> None:
        """
        Train all models in the ensemble.

        Args:
            X: Training data of shape (n_samples, n_features)
        """
        start_time = time.time()

        logger.info("ensemble_training_started", n_samples=X.shape[0])

        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest (uses original features)
        logger.info("training_isolation_forest")
        self.isolation_forest.fit(X)

        n_clusters = n_noise = 0
        gmm_bic = None
        self._X_scaled_training = None
        self._cluster_centroids = {}
        if self.ensemble_weights[1] > 0:
            logger.info("training_dbscan")
            self.dbscan.fit(X_scaled)
            self._X_scaled_training = X_scaled.copy()
            self._compute_cluster_centroids()
            n_clusters = len(set(self.dbscan.labels_)) - (1 if -1 in self.dbscan.labels_ else 0)
            n_noise = int(np.sum(self.dbscan.labels_ == -1))
        if self.ensemble_weights[2] > 0:
            logger.info("training_gmm")
            self.gmm.fit(X_scaled)
            gmm_bic = round(self.gmm.bic(X_scaled), 2)

        self.is_trained = True
        self.trained_at = datetime.now(timezone.utc)
        self.n_training_samples = X.shape[0]

        logger.info(
            "ensemble_training_completed",
            n_samples=X.shape[0],
            training_time_sec=round(time.time() - start_time, 2),
            n_clusters_dbscan=n_clusters,
            n_noise_points=n_noise,
            gmm_bic=gmm_bic,
        )

    def predict(self, features: LogFeatures) -> AnomalyResult:
        """
        Predict if log is anomalous using ensemble.

        Args:
            features: LogFeatures extracted from log

        Returns:
            AnomalyResult with aggregated anomaly detection result

        Raises:
            RuntimeError: If models are not trained
        """
        if not self.is_trained:
            msg = "Models must be trained before prediction"
            raise RuntimeError(msg)

        start_time = time.time()
        X = features.to_array().reshape(1, -1)
        scores = self.score_batch(X)
        if_score = float(scores["isolation_forest"][0])
        dbscan_score = float(scores["dbscan"][0])
        gmm_score = float(scores["gmm"][0])
        final_score = float(scores["risk"][0])

        is_anomaly = final_score >= settings.alert_threshold_medium

        # Confidence based on agreement between models
        score_std = np.std([if_score, dbscan_score, gmm_score])
        if score_std < 0.1:
            confidence = "high"
        elif score_std < 0.2:
            confidence = "medium"
        else:
            confidence = "low"

        important_features = self._get_important_features(X[0])
        processing_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            is_anomaly=is_anomaly,
            risk_score=round(final_score, 3),
            confidence=confidence,
            isolation_forest_score=round(if_score, 3),
            dbscan_score=round(dbscan_score, 3),
            gmm_score=round(gmm_score, 3),
            important_features=important_features,
            processing_time_ms=round(processing_time, 2),
            model_version=self.model_version,
        )

    def score_batch(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """
        Score many feature vectors at once.

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            Dict with per-model scores and the aggregated ``risk`` in [0, 1].

        Raises:
            RuntimeError: If models are not trained.
        """
        if not self.is_trained:
            msg = "Models must be trained before prediction"
            raise RuntimeError(msg)
        return score_arrays(
            X,
            isolation_forest=self.isolation_forest,
            dbscan=self.dbscan,
            gmm=self.gmm,
            scaler=self.scaler,
            centroids=self._cluster_centroids,
            weights=self.ensemble_weights,
        )

    def _compute_cluster_centroids(self) -> None:
        """Compute centroids for each DBSCAN cluster (excluding noise points)."""
        if self._X_scaled_training is None:
            return

        unique_labels = set(self.dbscan.labels_)
        unique_labels.discard(-1)  # Remove noise label

        for label in unique_labels:
            cluster_mask = self.dbscan.labels_ == label
            cluster_points = self._X_scaled_training[cluster_mask]
            self._cluster_centroids[label] = cluster_points.mean(axis=0)

        logger.debug("dbscan_centroids_computed", n_clusters=len(self._cluster_centroids))

    def _get_important_features(
        self, X_point: np.ndarray, top_k: int = 5
    ) -> list[tuple[str, float]]:
        """
        Get most important features for this prediction.

        Args:
            X_point: Feature vector
            top_k: Number of top features to return

        Returns:
            List of (feature_name, importance_score) tuples
        """
        feature_names = FEATURE_NAMES

        # Simple importance: absolute deviation from mean (normalized by std)
        # TODO: Use more sophisticated feature importance (SHAP values)
        z = self.scaler.transform(X_point.reshape(1, -1))[0]
        importances = np.abs(z)

        # Get top k
        top_indices = np.argsort(importances)[-top_k:][::-1]

        return [(feature_names[i], float(importances[i])) for i in top_indices]

    def save(self, path: Path) -> None:
        """
        Save ensemble to disk.

        Args:
            path: Path to save ensemble (directory)
        """
        path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ensemble_path = path / f"ensemble_{timestamp}.joblib"

        # Save all models and metadata
        ensemble_data = {
            "isolation_forest": self.isolation_forest,
            "dbscan": self.dbscan,
            "gmm": self.gmm,
            "scaler": self.scaler,
            "ensemble_weights": self.ensemble_weights,
            "contamination": self.contamination,
            "is_trained": self.is_trained,
            "model_version": self.model_version,
            "trained_at": self.trained_at,
            "n_training_samples": self.n_training_samples,
            "_X_scaled_training": self._X_scaled_training,
            "_cluster_centroids": self._cluster_centroids,
        }

        joblib.dump(ensemble_data, ensemble_path)

        logger.info(
            "ensemble_saved",
            path=str(ensemble_path),
            size_kb=round(ensemble_path.stat().st_size / 1024, 2),
        )

    @classmethod
    def load(cls, path: Path) -> AnomalyEnsemble:
        """
        Load ensemble from disk.

        Args:
            path: Path to ensemble file

        Returns:
            Loaded AnomalyEnsemble instance
        """
        logger.info("loading_ensemble", path=str(path))

        ensemble_data = joblib.load(path)

        # Create instance
        ensemble = cls(
            contamination=ensemble_data["contamination"],
            ensemble_weights=ensemble_data["ensemble_weights"],
        )

        # Restore models
        ensemble.isolation_forest = ensemble_data["isolation_forest"]
        ensemble.dbscan = ensemble_data["dbscan"]
        ensemble.gmm = ensemble_data["gmm"]
        ensemble.scaler = ensemble_data["scaler"]

        # Restore metadata
        ensemble.is_trained = ensemble_data["is_trained"]
        ensemble.model_version = ensemble_data["model_version"]
        ensemble.trained_at = ensemble_data["trained_at"]
        ensemble.n_training_samples = ensemble_data["n_training_samples"]

        # Restore training data for DBSCAN prediction
        ensemble._X_scaled_training = ensemble_data.get("_X_scaled_training")
        ensemble._cluster_centroids = ensemble_data.get("_cluster_centroids", {})

        logger.info(
            "ensemble_loaded",
            model_version=ensemble.model_version,
            trained_at=ensemble.trained_at,
            n_training_samples=ensemble.n_training_samples,
            n_dbscan_clusters=len(ensemble._cluster_centroids),
        )

        return ensemble


# ============================================================================
# Singleton instance (global ensemble)
# ============================================================================
_global_ensemble: AnomalyEnsemble | None = None


def get_ensemble() -> AnomalyEnsemble:
    """
    Get global ensemble instance (singleton).

    Returns:
        Global AnomalyEnsemble instance
    """
    global _global_ensemble

    if _global_ensemble is None:
        _global_ensemble = AnomalyEnsemble(
            contamination=settings.model_contamination,
            n_estimators=settings.model_n_estimators,
            dbscan_eps=settings.dbscan_eps,
            dbscan_min_samples=settings.dbscan_min_samples,
            gmm_n_components=settings.gmm_n_components,
            ensemble_weights=settings.ensemble_weights_list,
        )

        # Try to load existing model
        model_path = settings.model_path
        if model_path.exists():
            # Find latest model
            model_files = sorted(model_path.glob("ensemble_*.joblib"))
            if model_files:
                latest_model = model_files[-1]
                try:
                    _global_ensemble = AnomalyEnsemble.load(latest_model)
                    logger.info("loaded_existing_model", path=str(latest_model))
                except Exception:
                    logger.exception("failed_to_load_model", path=str(latest_model))

    return _global_ensemble
