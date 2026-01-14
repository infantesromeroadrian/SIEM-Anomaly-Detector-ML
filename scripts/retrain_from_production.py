#!/usr/bin/env python3
"""
Retrain SIEM Anomaly Detector with production data.

Uses actual logs from PostgreSQL database to retrain the ensemble.
Requires only NORMAL logs (no labels needed for anomaly detection).
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.db.database import get_db_sync  # noqa: E402
from backend.ml.ensemble import AnomalyEnsemble  # noqa: E402

print("🔄 SIEM Anomaly Detector - Production Data Retraining")
print("=" * 80)


def extract_features_from_logs(days_lookback: int = 30, min_samples: int = 1000) -> np.ndarray:
    """
    Extract features from production logs in PostgreSQL.

    Args:
        days_lookback: Number of days to look back for training data
        min_samples: Minimum number of samples required

    Returns:
        Feature matrix (n_samples, 21 features)

    Raises:
        ValueError: If not enough samples found
    """
    print(f"\n📊 Extracting features from last {days_lookback} days...")

    cutoff_date = datetime.now() - timedelta(days=days_lookback)

    # Connect to database
    with get_db_sync() as session:
        # Query logs table (only use logs with risk_score <= 0.6 for normal behavior)
        query = """
            SELECT 
                parsed_fields,
                risk_score,
                created_at
            FROM logs
            WHERE created_at >= :cutoff_date
              AND risk_score IS NOT NULL
              AND risk_score <= 0.6  -- Only normal/low-risk logs
            ORDER BY created_at DESC
            LIMIT 50000
        """

        result = session.execute(query, {"cutoff_date": cutoff_date})
        rows = result.fetchall()

    if len(rows) < min_samples:
        msg = (
            f"Not enough training samples. Found {len(rows)}, need {min_samples}.\n"
            f"Run the system for longer to collect more normal logs."
        )
        raise ValueError(msg)

    print(f"✅ Retrieved {len(rows):,} normal logs from database")

    # Extract features from parsed_fields JSON
    features_list = []

    for row in rows:
        parsed_fields = row.parsed_fields

        # Extract 21 features (match LogFeatures structure)
        try:
            features = [
                # Temporal
                parsed_fields.get("hour_of_day", 12),
                parsed_fields.get("day_of_week", 2),
                parsed_fields.get("is_weekend", 0),
                parsed_fields.get("is_business_hours", 1),
                # Frequency
                parsed_fields.get("login_attempts_per_minute", 0.5),
                parsed_fields.get("requests_per_second", 0.5),
                parsed_fields.get("unique_ips_last_hour", 5),
                parsed_fields.get("unique_endpoints_accessed", 3),
                # Rates
                parsed_fields.get("failed_auth_rate", 0.05),
                parsed_fields.get("error_rate_4xx", 0.02),
                parsed_fields.get("error_rate_5xx", 0.01),
                # Geographic
                parsed_fields.get("geographic_distance_km", 10),
                parsed_fields.get("is_known_country", 1),
                parsed_fields.get("is_known_ip", 1),
                # Behavioral
                parsed_fields.get("bytes_transferred", np.log1p(1000)),
                parsed_fields.get("time_since_last_activity_sec", 60),
                parsed_fields.get("session_duration_sec", 300),
                parsed_fields.get("payload_entropy", 4.5),
                # Context
                parsed_fields.get("is_privileged_user", 0),
                parsed_fields.get("is_sensitive_endpoint", 0),
                parsed_fields.get("is_known_user_agent", 1),
            ]

            features_list.append(features)

        except Exception as e:
            print(f"⚠️  Skipping log due to parsing error: {e}")
            continue

    X = np.array(features_list)

    print(f"✅ Extracted features: {X.shape[0]:,} samples, {X.shape[1]} features")
    print(f"   • Feature range: [{X.min():.2f}, {X.max():.2f}]")
    print(f"   • Mean: {X.mean():.2f}, Std: {X.std():.2f}")

    return X


def main() -> None:
    """Main retraining function."""
    # Extract features from production logs
    try:
        X_train = extract_features_from_logs(days_lookback=30, min_samples=1000)
    except ValueError as e:
        print(f"\n❌ ERROR: {e}")
        print("\n💡 Solution: Send more logs to the system before retraining.")
        sys.exit(1)

    print("\n" + "=" * 80)
    print("🧠 Training ML Ensemble on Production Data")
    print("=" * 80)

    # Initialize ensemble with production-tuned parameters
    ensemble = AnomalyEnsemble(
        contamination=0.05,  # Expect 5% anomalies in production (adjust based on reality)
        n_estimators=200,  # More trees for better accuracy
        dbscan_eps=2.0,  # Wider radius for production diversity
        dbscan_min_samples=100,  # Larger clusters
        gmm_n_components=5,  # More components for complex distribution
        ensemble_weights=[0.5, 0.3, 0.2],  # Same weights as before
    )

    # Train ensemble
    print("\n📈 Training models...")
    print("   ├─ Isolation Forest (n_estimators=200, contamination=0.05)")
    print("   ├─ DBSCAN (eps=2.0, min_samples=100)")
    print("   └─ GMM (n_components=5, covariance_type='full')")

    ensemble.train(X_train)

    print(f"\n✅ Training completed!")
    print(f"   • Samples trained: {ensemble.n_training_samples:,}")
    print(f"   • Trained at: {ensemble.trained_at}")
    print(f"   • DBSCAN clusters: {len(ensemble._cluster_centroids)}")

    # Save ensemble
    print("\n💾 Saving production-trained ensemble...")
    models_dir = Path("./models")
    models_dir.mkdir(exist_ok=True)

    # Backup old model
    old_models = sorted(models_dir.glob("ensemble_*.joblib"))
    if old_models:
        latest_old = old_models[-1]
        backup_dir = models_dir / "backups"
        backup_dir.mkdir(exist_ok=True)
        backup_path = backup_dir / latest_old.name
        latest_old.rename(backup_path)
        print(f"   • Old model backed up: {backup_path.name}")

    # Save new model
    ensemble.save(models_dir)

    # Find saved model
    model_files = sorted(models_dir.glob("ensemble_*.joblib"))
    if model_files:
        latest_model = model_files[-1]
        print(f"\n✅ Model saved: {latest_model.name}")
        print(f"📏 Size: {latest_model.stat().st_size / 1024:.2f} KB")

    print("\n" + "=" * 80)
    print("✅ Retraining completed successfully!")
    print("\n💡 Next steps:")
    print("   1. Restart API to load new model: docker compose restart api")
    print("   2. Monitor detection quality for 24-48 hours")
    print("   3. Adjust ALERT_THRESHOLD_* in .env if needed")
    print("   4. Re-run this script monthly for best results")


if __name__ == "__main__":
    main()
