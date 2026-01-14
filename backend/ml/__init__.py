"""
Machine Learning module for SIEM Anomaly Detector.

Provides ML-based anomaly detection using ensemble of:
- Isolation Forest
- DBSCAN
- Gaussian Mixture Models (GMM)
"""

from __future__ import annotations

__all__ = [
    "AnomalyEnsemble",
    "FeatureEngineer",
]
