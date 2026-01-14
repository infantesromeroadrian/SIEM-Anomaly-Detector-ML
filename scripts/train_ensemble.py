#!/usr/bin/env python3
"""
Train SIEM Anomaly Ensemble with synthetic data.

Generates realistic security log features and trains the ensemble.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ml.ensemble import AnomalyEnsemble  # noqa: E402

print("🚀 SIEM Anomaly Detector - Ensemble Training")
print("=" * 80)


def generate_training_data(
    n_normal: int = 9700, n_anomalous: int = 300
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data for SIEM.

    Features match LogFeatures structure:
    - Temporal: hour, day_of_week, is_weekend, is_business_hours
    - Frequency: login_attempts, requests_per_sec, unique_ips, endpoints
    - Rates: failed_auth_rate, error_4xx, error_5xx
    - Geographic: distance_km, is_known_country, is_known_ip
    - Behavioral: bytes_transferred, time_since_last, session_duration, entropy
    - Context: is_privileged_user, is_sensitive_endpoint, is_known_user_agent

    Total: 21 features

    Args:
        n_normal: Number of normal samples
        n_anomalous: Number of anomalous samples

    Returns:
        Tuple of (X, y) where X is features and y is labels (0=normal, 1=anomaly)
    """
    np.random.seed(42)

    # ========================================================================
    # NORMAL BEHAVIOR
    # ========================================================================
    print(f"\n📊 Generating {n_normal:,} normal samples...")

    # Prepare probability distributions (normalized)
    hour_probs_normal = np.array([0.01] * 6 + [0.075] * 12 + [0.01] * 6)
    hour_probs_normal = hour_probs_normal / hour_probs_normal.sum()

    day_probs_normal = np.array([0.18] * 5 + [0.05] * 2)
    day_probs_normal = day_probs_normal / day_probs_normal.sum()

    normal_data = {
        # Temporal (business hours, weekdays)
        "hour_of_day": np.random.choice(range(24), n_normal, p=hour_probs_normal),
        "day_of_week": np.random.choice(range(7), n_normal, p=day_probs_normal),
        "is_weekend": np.random.choice([0, 1], n_normal, p=[0.7, 0.3]),
        "is_business_hours": np.random.choice([0, 1], n_normal, p=[0.3, 0.7]),
        # Frequency (low activity)
        "login_attempts_per_minute": np.abs(np.random.normal(1.0, 0.5, n_normal)),
        "requests_per_second": np.abs(np.random.normal(0.5, 0.2, n_normal)),
        "unique_ips_last_hour": np.random.randint(1, 20, n_normal),
        "unique_endpoints_accessed": np.random.randint(1, 10, n_normal),
        # Rates (mostly successful)
        "failed_auth_rate": np.abs(np.random.normal(0.05, 0.03, n_normal)),
        "error_rate_4xx": np.abs(np.random.normal(0.02, 0.01, n_normal)),
        "error_rate_5xx": np.abs(np.random.normal(0.01, 0.005, n_normal)),
        # Geographic (known locations)
        "geographic_distance_km": np.abs(np.random.normal(5, 10, n_normal)),
        "is_known_country": np.random.choice([0, 1], n_normal, p=[0.1, 0.9]),
        "is_known_ip": np.random.choice([0, 1], n_normal, p=[0.2, 0.8]),
        # Behavioral (typical usage)
        "bytes_transferred": np.log1p(np.random.gamma(2, 150, n_normal)),
        "time_since_last_activity_sec": np.random.uniform(10, 300, n_normal),
        "session_duration_sec": np.random.uniform(60, 1800, n_normal),
        "payload_entropy": np.random.uniform(3.0, 6.0, n_normal),
        # Context (non-privileged)
        "is_privileged_user": np.random.choice([0, 1], n_normal, p=[0.95, 0.05]),
        "is_sensitive_endpoint": np.random.choice([0, 1], n_normal, p=[0.9, 0.1]),
        "is_known_user_agent": np.random.choice([0, 1], n_normal, p=[0.1, 0.9]),
    }

    # ========================================================================
    # ANOMALOUS BEHAVIOR (Various attack types)
    # ========================================================================
    print(f"⚠️  Generating {n_anomalous:,} anomalous samples...")

    # Prepare probability distributions for anomalies (normalized)
    hour_probs_anomaly = np.array([0.15] * 6 + [0.02] * 12 + [0.05] * 6)
    hour_probs_anomaly = hour_probs_anomaly / hour_probs_anomaly.sum()

    day_probs_anomaly = np.array([0.1] * 5 + [0.25] * 2)
    day_probs_anomaly = day_probs_anomaly / day_probs_anomaly.sum()

    anomalous_data = {
        # Temporal (unusual hours - night attacks)
        "hour_of_day": np.random.choice(range(24), n_anomalous, p=hour_probs_anomaly),
        "day_of_week": np.random.choice(range(7), n_anomalous, p=day_probs_anomaly),
        "is_weekend": np.random.choice([0, 1], n_anomalous, p=[0.3, 0.7]),
        "is_business_hours": np.random.choice([0, 1], n_anomalous, p=[0.8, 0.2]),
        # Frequency (high activity - brute force, DDoS)
        "login_attempts_per_minute": np.random.uniform(10, 30, n_anomalous),
        "requests_per_second": np.random.uniform(5, 20, n_anomalous),
        "unique_ips_last_hour": np.random.randint(1, 5, n_anomalous),
        "unique_endpoints_accessed": np.random.randint(15, 50, n_anomalous),
        # Rates (high failure rates)
        "failed_auth_rate": np.random.uniform(0.7, 1.0, n_anomalous),
        "error_rate_4xx": np.random.uniform(0.5, 1.0, n_anomalous),
        "error_rate_5xx": np.random.uniform(0.3, 0.8, n_anomalous),
        # Geographic (foreign locations)
        "geographic_distance_km": np.random.uniform(200, 2000, n_anomalous),
        "is_known_country": np.random.choice([0, 1], n_anomalous, p=[0.8, 0.2]),
        "is_known_ip": np.random.choice([0, 1], n_anomalous, p=[0.95, 0.05]),
        # Behavioral (suspicious patterns)
        "bytes_transferred": np.log1p(np.random.uniform(5000, 50000, n_anomalous)),
        "time_since_last_activity_sec": np.random.uniform(1, 10, n_anomalous),
        "session_duration_sec": np.random.uniform(1, 30, n_anomalous),
        "payload_entropy": np.random.uniform(7.0, 8.0, n_anomalous),  # High entropy
        # Context (targeting privileged access)
        "is_privileged_user": np.random.choice([0, 1], n_anomalous, p=[0.3, 0.7]),
        "is_sensitive_endpoint": np.random.choice([0, 1], n_anomalous, p=[0.2, 0.8]),
        "is_known_user_agent": np.random.choice([0, 1], n_anomalous, p=[0.9, 0.1]),
    }

    # Combine datasets
    df_normal = pd.DataFrame(normal_data)
    df_anomalous = pd.DataFrame(anomalous_data)

    X_normal = df_normal.values
    X_anomalous = df_anomalous.values

    X = np.vstack([X_normal, X_anomalous])
    y = np.hstack([np.zeros(n_normal), np.ones(n_anomalous)])

    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    print(f"✅ Dataset generated: {X.shape[0]:,} samples, {X.shape[1]} features")
    print(f"   • Normal: {n_normal:,} ({n_normal / len(X):.1%})")
    print(f"   • Anomalous: {n_anomalous:,} ({n_anomalous / len(X):.1%})")

    return X, y


def main() -> None:
    """Main training function."""
    # Generate training data
    X_train, y_train = generate_training_data(n_normal=9700, n_anomalous=300)

    print("\n" + "=" * 80)
    print("🧠 Training ML Ensemble")
    print("=" * 80)

    # Initialize ensemble (eps=5.0 for better real-world data tolerance)
    ensemble = AnomalyEnsemble(
        contamination=0.03,
        n_estimators=100,
        dbscan_eps=5.0,  # Increased from 1.5 to capture real log variability
        dbscan_min_samples=50,
        gmm_n_components=3,
        ensemble_weights=[0.5, 0.3, 0.2],
    )

    # Train ensemble
    print("\n📈 Training models...")
    print("   ├─ Isolation Forest (n_estimators=100, contamination=0.03)")
    print("   ├─ DBSCAN (eps=5.0, min_samples=50) [adjusted for real-world logs]")
    print("   └─ GMM (n_components=3, covariance_type='full')")

    ensemble.train(X_train)

    print(f"\n✅ Training completed!")
    print(f"   • Samples trained: {ensemble.n_training_samples:,}")
    print(f"   • Trained at: {ensemble.trained_at}")

    # Save ensemble
    print("\n💾 Saving ensemble...")
    models_dir = Path("./models")
    models_dir.mkdir(exist_ok=True)

    ensemble.save(models_dir)

    # Find saved model
    model_files = sorted(models_dir.glob("ensemble_*.joblib"))
    if model_files:
        latest_model = model_files[-1]
        print(f"✅ Model saved: {latest_model}")
        print(f"📏 Size: {latest_model.stat().st_size / 1024:.2f} KB")

    # Quick validation
    print("\n" + "=" * 80)
    print("🧪 Quick Validation")
    print("=" * 80)

    # Test on a few normal samples
    print("\n📊 Testing on normal samples...")
    normal_samples = X_train[y_train == 0][:5]

    from backend.ml.features import LogFeatures

    for i, sample in enumerate(normal_samples):
        # Create LogFeatures from array
        features = LogFeatures(
            hour_of_day=int(sample[0]),
            day_of_week=int(sample[1]),
            is_weekend=bool(sample[2]),
            is_business_hours=bool(sample[3]),
            login_attempts_per_minute=float(sample[4]),
            requests_per_second=float(sample[5]),
            unique_ips_last_hour=int(sample[6]),
            unique_endpoints_accessed=int(sample[7]),
            failed_auth_rate=float(sample[8]),
            error_rate_4xx=float(sample[9]),
            error_rate_5xx=float(sample[10]),
            geographic_distance_km=float(sample[11]),
            is_known_country=bool(sample[12]),
            is_known_ip=bool(sample[13]),
            bytes_transferred=float(sample[14]),
            time_since_last_activity_sec=float(sample[15]),
            session_duration_sec=float(sample[16]),
            payload_entropy=float(sample[17]),
            is_privileged_user=bool(sample[18]),
            is_sensitive_endpoint=bool(sample[19]),
            is_known_user_agent=bool(sample[20]),
        )

        result = ensemble.predict(features)
        emoji = "❌" if result.is_anomaly else "✅"
        print(
            f"   {emoji} Sample {i + 1}: risk_score={result.risk_score:.3f}, "
            f"is_anomaly={result.is_anomaly}"
        )

    # Test on anomalous samples
    print("\n⚠️  Testing on anomalous samples...")
    anomalous_samples = X_train[y_train == 1][:5]

    for i, sample in enumerate(anomalous_samples):
        features = LogFeatures(
            hour_of_day=int(sample[0]),
            day_of_week=int(sample[1]),
            is_weekend=bool(sample[2]),
            is_business_hours=bool(sample[3]),
            login_attempts_per_minute=float(sample[4]),
            requests_per_second=float(sample[5]),
            unique_ips_last_hour=int(sample[6]),
            unique_endpoints_accessed=int(sample[7]),
            failed_auth_rate=float(sample[8]),
            error_rate_4xx=float(sample[9]),
            error_rate_5xx=float(sample[10]),
            geographic_distance_km=float(sample[11]),
            is_known_country=bool(sample[12]),
            is_known_ip=bool(sample[13]),
            bytes_transferred=float(sample[14]),
            time_since_last_activity_sec=float(sample[15]),
            session_duration_sec=float(sample[16]),
            payload_entropy=float(sample[17]),
            is_privileged_user=bool(sample[18]),
            is_sensitive_endpoint=bool(sample[19]),
            is_known_user_agent=bool(sample[20]),
        )

        result = ensemble.predict(features)
        emoji = "✅" if result.is_anomaly else "❌"
        print(
            f"   {emoji} Sample {i + 1}: risk_score={result.risk_score:.3f}, "
            f"is_anomaly={result.is_anomaly}"
        )

    print("\n" + "=" * 80)
    print("✅ Training and validation completed successfully!")
    print("=" * 80)
    print("\n💡 Next steps:")
    print("   1. Start API: uvicorn backend.main:app --reload")
    print("   2. Test health: curl http://localhost:8000/api/v1/health")
    print("   3. Analyze log: curl -X POST http://localhost:8000/api/v1/logs/analyze")
    print("   4. View docs: http://localhost:8000/docs")


if __name__ == "__main__":
    main()
