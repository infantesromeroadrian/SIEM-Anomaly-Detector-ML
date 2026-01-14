#!/usr/bin/env python3
"""Train SIEM Anomaly Ensemble - Fixed version."""

import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

print("🚀 SIEM Anomaly Detector - Ensemble Training")
print("=" * 80)

def generate_training_data(n_normal=9700, n_anomalous=300):
    """Generate synthetic training data."""
    np.random.seed(42)
    
    print(f"\n📊 Generating {n_normal:,} normal samples...")
    
    # Normalize probability arrays
    hour_probs_normal = np.array([0.01] * 6 + [0.08] * 12 + [0.02] * 6, dtype=float)
    hour_probs_normal = hour_probs_normal / hour_probs_normal.sum()
    
    day_probs_normal = np.array([0.18] * 5 + [0.05] * 2, dtype=float)
    day_probs_normal = day_probs_normal / day_probs_normal.sum()
    
    # Normal behavior
    normal_data = {
        "hour_of_day": np.random.choice(range(24), n_normal, p=hour_probs_normal),
        "day_of_week": np.random.choice(range(7), n_normal, p=day_probs_normal),
        "is_weekend": np.random.choice([0, 1], n_normal, p=[0.7, 0.3]),
        "is_business_hours": np.random.choice([0, 1], n_normal, p=[0.3, 0.7]),
        "login_attempts_per_minute": np.abs(np.random.normal(1.0, 0.5, n_normal)),
        "requests_per_second": np.abs(np.random.normal(0.5, 0.2, n_normal)),
        "unique_ips_last_hour": np.random.randint(1, 20, n_normal),
        "unique_endpoints_accessed": np.random.randint(1, 10, n_normal),
        "failed_auth_rate": np.abs(np.random.normal(0.05, 0.03, n_normal)),
        "error_rate_4xx": np.abs(np.random.normal(0.02, 0.01, n_normal)),
        "error_rate_5xx": np.abs(np.random.normal(0.01, 0.005, n_normal)),
        "geographic_distance_km": np.abs(np.random.normal(5, 10, n_normal)),
        "is_known_country": np.random.choice([0, 1], n_normal, p=[0.1, 0.9]),
        "is_known_ip": np.random.choice([0, 1], n_normal, p=[0.2, 0.8]),
        "bytes_transferred": np.log1p(np.random.gamma(2, 150, n_normal)),
        "time_since_last_activity_sec": np.random.uniform(10, 300, n_normal),
        "session_duration_sec": np.random.uniform(60, 1800, n_normal),
        "payload_entropy": np.random.uniform(3.0, 6.0, n_normal),
        "is_privileged_user": np.random.choice([0, 1], n_normal, p=[0.95, 0.05]),
        "is_sensitive_endpoint": np.random.choice([0, 1], n_normal, p=[0.9, 0.1]),
        "is_known_user_agent": np.random.choice([0, 1], n_normal, p=[0.1, 0.9]),
    }
    
    print(f"⚠️  Generating {n_anomalous:,} anomalous samples...")
    
    # Normalize anomalous probabilities
    hour_probs_anom = np.array([0.15] * 6 + [0.02] * 12 + [0.05] * 6, dtype=float)
    hour_probs_anom = hour_probs_anom / hour_probs_anom.sum()
    
    day_probs_anom = np.array([0.1] * 5 + [0.25] * 2, dtype=float)
    day_probs_anom = day_probs_anom / day_probs_anom.sum()
    
    # Anomalous behavior
    anomalous_data = {
        "hour_of_day": np.random.choice(range(24), n_anomalous, p=hour_probs_anom),
        "day_of_week": np.random.choice(range(7), n_anomalous, p=day_probs_anom),
        "is_weekend": np.random.choice([0, 1], n_anomalous, p=[0.3, 0.7]),
        "is_business_hours": np.random.choice([0, 1], n_anomalous, p=[0.8, 0.2]),
        "login_attempts_per_minute": np.random.uniform(10, 30, n_anomalous),
        "requests_per_second": np.random.uniform(5, 20, n_anomalous),
        "unique_ips_last_hour": np.random.randint(1, 5, n_anomalous),
        "unique_endpoints_accessed": np.random.randint(15, 50, n_anomalous),
        "failed_auth_rate": np.random.uniform(0.7, 1.0, n_anomalous),
        "error_rate_4xx": np.random.uniform(0.5, 1.0, n_anomalous),
        "error_rate_5xx": np.random.uniform(0.3, 0.8, n_anomalous),
        "geographic_distance_km": np.random.uniform(200, 2000, n_anomalous),
        "is_known_country": np.random.choice([0, 1], n_anomalous, p=[0.8, 0.2]),
        "is_known_ip": np.random.choice([0, 1], n_anomalous, p=[0.95, 0.05]),
        "bytes_transferred": np.log1p(np.random.uniform(5000, 50000, n_anomalous)),
        "time_since_last_activity_sec": np.random.uniform(1, 10, n_anomalous),
        "session_duration_sec": np.random.uniform(1, 30, n_anomalous),
        "payload_entropy": np.random.uniform(7.0, 8.0, n_anomalous),
        "is_privileged_user": np.random.choice([0, 1], n_anomalous, p=[0.3, 0.7]),
        "is_sensitive_endpoint": np.random.choice([0, 1], n_anomalous, p=[0.2, 0.8]),
        "is_known_user_agent": np.random.choice([0, 1], n_anomalous, p=[0.9, 0.1]),
    }
    
    df_normal = pd.DataFrame(normal_data)
    df_anomalous = pd.DataFrame(anomalous_data)
    
    X = np.vstack([df_normal.values, df_anomalous.values])
    y = np.hstack([np.zeros(n_normal), np.ones(n_anomalous)])
    
    indices = np.random.permutation(len(X))
    X, y = X[indices], y[indices]
    
    print(f"✅ Dataset: {X.shape[0]:,} samples, {X.shape[1]} features")
    print(f"   • Normal: {n_normal:,} ({n_normal/len(X):.1%})")
    print(f"   • Anomalous: {n_anomalous:,} ({n_anomalous/len(X):.1%})")
    
    return X, y

# Generate data
X_train, y_train = generate_training_data()

# Train
print("\n" + "=" * 80)
print("🧠 Training ML Ensemble")
print("=" * 80)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)

print("\n   ├─ Isolation Forest...")
iso_forest = IsolationForest(contamination=0.03, n_estimators=100, random_state=42, n_jobs=-1)
iso_forest.fit(X_train)

print("   ├─ DBSCAN...")
dbscan = DBSCAN(eps=1.5, min_samples=50, n_jobs=-1)
dbscan.fit(X_scaled)
n_clusters = len(set(dbscan.labels_)) - (1 if -1 in dbscan.labels_ else 0)
print(f"   │   └─ Clusters: {n_clusters}, Outliers: {(dbscan.labels_ == -1).sum()}")

print("   └─ GMM...")
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=42)
gmm.fit(X_scaled)
print(f"       └─ BIC: {gmm.bic(X_scaled):.2f}")

# Save
print("\n💾 Saving...")
Path("./models").mkdir(exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
model_path = Path(f"./models/ensemble_{timestamp}.joblib")

joblib.dump({
    'isolation_forest': iso_forest,
    'dbscan': dbscan,
    'gmm': gmm,
    'scaler': scaler,
    'metadata': {
        'version': 'v1.0.0',
        'trained_at': str(datetime.now()),
        'n_samples': len(X_train)
    }
}, model_path)

print(f"✅ Saved: {model_path} ({model_path.stat().st_size / 1024:.2f} KB)")

# Validate
print("\n" + "=" * 80)
print("🧪 Validation")
print("=" * 80)

for label, name in [(0, "Normal"), (1, "Anomalous")]:
    samples = X_train[y_train == label][:5]
    print(f"\n{name} samples:")
    for i, sample in enumerate(samples):
        if_score = 1.0 / (1.0 + np.exp(iso_forest.decision_function([sample])[0] * 10))
        gmm_score = 1.0 / (1.0 + np.exp((gmm.score_samples(scaler.transform([sample]))[0] + 10) * 0.5))
        final = 0.5 * if_score + 0.2 * gmm_score + 0.3 * 0.5
        emoji = "✅" if (final >= 0.6) == (label == 1) else "❌"
        print(f"   {emoji} Sample {i+1}: score={final:.3f}, is_anomaly={final >= 0.6}")

print("\n" + "=" * 80)
print("✅ Training complete!")
print("=" * 80)
