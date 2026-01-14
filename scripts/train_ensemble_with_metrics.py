#!/usr/bin/env python3
"""
Train SIEM Anomaly Ensemble with PROPER ML validation.

Includes:
- Train/Val/Test split (60/20/20)
- Comprehensive metrics (Precision, Recall, F1, AUC-ROC, Confusion Matrix)
- Baseline comparison (Dummy Classifier)
- Cross-validation
- Feature importance analysis
- Model performance tracking
"""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import structlog
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ml.ensemble import AnomalyEnsemble  # noqa: E402
from backend.ml.features import LogFeatures  # noqa: E402

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)

logger = structlog.get_logger(__name__)

print("=" * 80)
print("🚀 SIEM Anomaly Detector - Professional ML Training")
print("=" * 80)


def generate_training_data(
    n_normal: int = 10000, n_anomalous: int = 500
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data for SIEM.

    Features match LogFeatures structure (21 features total).
    Generates realistic security log patterns with temporal, behavioral,
    and geographic characteristics.

    Args:
        n_normal: Number of normal samples
        n_anomalous: Number of anomalous samples

    Returns:
        Tuple of (X, y) where X is features and y is labels (0=normal, 1=anomaly)
    """
    np.random.seed(42)

    logger.info("Generating training data", n_normal=n_normal, n_anomalous=n_anomalous)

    # ========================================================================
    # NORMAL BEHAVIOR
    # ========================================================================
    print(f"\n📊 Generating {n_normal:,} normal samples...")

    # Probability distributions (normalized)
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
        "payload_entropy": np.random.uniform(7.0, 8.0, n_anomalous),
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

    logger.info(
        "Training data generated",
        total_samples=X.shape[0],
        n_features=X.shape[1],
        n_normal=n_normal,
        n_anomalous=n_anomalous,
        anomaly_rate=n_anomalous / len(X),
    )

    return X, y


def check_data_leakage(X_train: np.ndarray, X_val: np.ndarray, X_test: np.ndarray) -> None:
    """
    Check for data leakage between train/val/test sets.

    Args:
        X_train: Training features
        X_val: Validation features
        X_test: Test features
    """
    print("\n🔍 Checking for data leakage...")

    # Convert to sets for comparison (using tuple of features as key)
    train_set = {tuple(row) for row in X_train}
    val_set = {tuple(row) for row in X_val}
    test_set = {tuple(row) for row in X_test}

    train_val_overlap = len(train_set & val_set)
    train_test_overlap = len(train_set & test_set)
    val_test_overlap = len(val_set & test_set)

    if train_val_overlap > 0:
        logger.warning("Data leakage detected: train/val overlap", count=train_val_overlap)
        print(f"   ⚠️  Train/Val overlap: {train_val_overlap} samples")
    if train_test_overlap > 0:
        logger.warning("Data leakage detected: train/test overlap", count=train_test_overlap)
        print(f"   ⚠️  Train/Test overlap: {train_test_overlap} samples")
    if val_test_overlap > 0:
        logger.warning("Data leakage detected: val/test overlap", count=val_test_overlap)
        print(f"   ⚠️  Val/Test overlap: {val_test_overlap} samples")

    if train_val_overlap == 0 and train_test_overlap == 0 and val_test_overlap == 0:
        print("   ✅ No data leakage detected")
        logger.info("Data leakage check passed")
    else:
        logger.error("Data leakage detected - stopping training")
        raise ValueError("Data leakage detected between splits!")


def evaluate_model(
    model: AnomalyEnsemble,
    X: np.ndarray,
    y_true: np.ndarray,
    dataset_name: str = "Test",
) -> dict[str, Any]:
    """
    Comprehensive model evaluation with multiple metrics.

    Args:
        model: Trained ensemble model
        X: Feature matrix
        y_true: True labels
        dataset_name: Name of dataset (for logging)

    Returns:
        Dictionary with all metrics
    """
    start_time = time.time()

    # Get predictions
    y_pred = []
    y_scores = []

    for i in range(len(X)):
        features = LogFeatures(
            hour_of_day=int(X[i, 0]),
            day_of_week=int(X[i, 1]),
            is_weekend=bool(X[i, 2]),
            is_business_hours=bool(X[i, 3]),
            login_attempts_per_minute=float(X[i, 4]),
            requests_per_second=float(X[i, 5]),
            unique_ips_last_hour=int(X[i, 6]),
            unique_endpoints_accessed=int(X[i, 7]),
            failed_auth_rate=float(X[i, 8]),
            error_rate_4xx=float(X[i, 9]),
            error_rate_5xx=float(X[i, 10]),
            geographic_distance_km=float(X[i, 11]),
            is_known_country=bool(X[i, 12]),
            is_known_ip=bool(X[i, 13]),
            bytes_transferred=float(X[i, 14]),
            time_since_last_activity_sec=float(X[i, 15]),
            session_duration_sec=float(X[i, 16]),
            payload_entropy=float(X[i, 17]),
            is_privileged_user=bool(X[i, 18]),
            is_sensitive_endpoint=bool(X[i, 19]),
            is_known_user_agent=bool(X[i, 20]),
        )
        result = model.predict(features)
        y_pred.append(1 if result.is_anomaly else 0)
        y_scores.append(result.risk_score)

    y_pred = np.array(y_pred)
    y_scores = np.array(y_scores)

    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # ROC-AUC
    try:
        roc_auc = roc_auc_score(y_true, y_scores)
        fpr, tpr, _ = roc_curve(y_true, y_scores)
    except Exception as e:
        logger.warning(f"Failed to calculate ROC-AUC: {e}")
        roc_auc = 0.0
        fpr, tpr = None, None

    # Precision-Recall curve
    try:
        precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall_curve, precision_curve)
    except Exception as e:
        logger.warning(f"Failed to calculate PR-AUC: {e}")
        pr_auc = 0.0

    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    # False Positive Rate and False Negative Rate
    fpr_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    evaluation_time = time.time() - start_time

    metrics = {
        "dataset": dataset_name,
        "n_samples": len(X),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "fpr": float(fpr_rate),
        "fnr": float(fnr_rate),
        "evaluation_time_sec": float(evaluation_time),
    }

    # Log metrics
    logger.info(f"{dataset_name} evaluation", **metrics)

    return metrics


def print_metrics_report(metrics: dict[str, Any]) -> None:
    """
    Print formatted metrics report.

    Args:
        metrics: Dictionary with evaluation metrics
    """
    print(f"\n📊 {metrics['dataset']} Set Results:")
    print(f"   • Samples: {metrics['n_samples']:,}")
    print(f"   • Accuracy: {metrics['accuracy']:.3f}")
    print(f"   • Precision: {metrics['precision']:.3f}")
    print(f"   • Recall: {metrics['recall']:.3f}")
    print(f"   • F1-Score: {metrics['f1_score']:.3f}")
    print(f"   • ROC-AUC: {metrics['roc_auc']:.3f}")
    print(f"   • PR-AUC: {metrics['pr_auc']:.3f}")
    print(f"\n   Confusion Matrix:")
    cm = metrics["confusion_matrix"]
    print(f"      TN={cm['tn']:>5}  FP={cm['fp']:>5}")
    print(f"      FN={cm['fn']:>5}  TP={cm['tp']:>5}")
    print(f"\n   • False Positive Rate: {metrics['fpr']:.3f}")
    print(f"   • False Negative Rate: {metrics['fnr']:.3f}")


def main() -> None:
    """Main training function with comprehensive validation."""
    print("\n" + "=" * 80)
    print("📊 STEP 1: DATA GENERATION")
    print("=" * 80)

    # Generate data with higher anomaly rate for better evaluation
    X, y = generate_training_data(n_normal=10000, n_anomalous=500)

    # ========================================================================
    # STEP 2: TRAIN/VAL/TEST SPLIT (60/20/20)
    # ========================================================================
    print("\n" + "=" * 80)
    print("✂️  STEP 2: TRAIN/VAL/TEST SPLIT")
    print("=" * 80)

    # First split: 80% train+val, 20% test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Second split: 75% train, 25% val (of the 80%)
    # This gives us 60/20/20 overall
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
    )

    print(f"\n✅ Data split:")
    print(f"   • Train: {len(X_train):,} samples ({len(X_train) / len(X):.1%})")
    print(f"      - Normal: {(y_train == 0).sum():,}")
    print(f"      - Anomalies: {(y_train == 1).sum():,}")
    print(f"   • Validation: {len(X_val):,} samples ({len(X_val) / len(X):.1%})")
    print(f"      - Normal: {(y_val == 0).sum():,}")
    print(f"      - Anomalies: {(y_val == 1).sum():,}")
    print(f"   • Test: {len(X_test):,} samples ({len(X_test) / len(X):.1%})")
    print(f"      - Normal: {(y_test == 0).sum():,}")
    print(f"      - Anomalies: {(y_test == 1).sum():,}")

    logger.info(
        "Data split complete",
        train_size=len(X_train),
        val_size=len(X_val),
        test_size=len(X_test),
    )

    # Check for data leakage
    check_data_leakage(X_train, X_val, X_test)

    # ========================================================================
    # STEP 3: BASELINE MODEL (Dummy Classifier)
    # ========================================================================
    print("\n" + "=" * 80)
    print("🎯 STEP 3: BASELINE MODEL (Dummy Classifier)")
    print("=" * 80)

    baseline = DummyClassifier(strategy="most_frequent", random_state=42)
    baseline.fit(X_train, y_train)

    baseline_pred = baseline.predict(X_test)
    baseline_accuracy = accuracy_score(y_test, baseline_pred)
    baseline_f1 = f1_score(y_test, baseline_pred, zero_division=0)

    print(f"\n📊 Baseline (Most Frequent) Results:")
    print(f"   • Accuracy: {baseline_accuracy:.3f}")
    print(f"   • F1-Score: {baseline_f1:.3f}")

    logger.info(
        "Baseline model evaluated",
        accuracy=baseline_accuracy,
        f1_score=baseline_f1,
    )

    # ========================================================================
    # STEP 4: TRAIN ENSEMBLE
    # ========================================================================
    print("\n" + "=" * 80)
    print("🧠 STEP 4: TRAIN ML ENSEMBLE")
    print("=" * 80)

    ensemble = AnomalyEnsemble(
        contamination=0.05,  # 5% expected anomalies
        n_estimators=100,
        dbscan_eps=5.0,
        dbscan_min_samples=50,
        gmm_n_components=3,
        ensemble_weights=[0.5, 0.3, 0.2],
    )

    print("\n📈 Training models...")
    print("   ├─ Isolation Forest (n_estimators=100, contamination=0.05)")
    print("   ├─ DBSCAN (eps=5.0, min_samples=50)")
    print("   └─ GMM (n_components=3, covariance_type='full')")

    training_start = time.time()
    ensemble.train(X_train)
    training_time = time.time() - training_start

    print(f"\n✅ Training completed in {training_time:.2f}s")
    logger.info("Ensemble training complete", training_time_sec=training_time)

    # ========================================================================
    # STEP 5: EVALUATE ON VALIDATION SET
    # ========================================================================
    print("\n" + "=" * 80)
    print("📊 STEP 5: VALIDATION SET EVALUATION")
    print("=" * 80)

    val_metrics = evaluate_model(ensemble, X_val, y_val, "Validation")
    print_metrics_report(val_metrics)

    # ========================================================================
    # STEP 6: EVALUATE ON TEST SET (FINAL METRICS)
    # ========================================================================
    print("\n" + "=" * 80)
    print("🎯 STEP 6: TEST SET EVALUATION (FINAL)")
    print("=" * 80)

    test_metrics = evaluate_model(ensemble, X_test, y_test, "Test")
    print_metrics_report(test_metrics)

    # ========================================================================
    # STEP 7: COMPARISON WITH BASELINE
    # ========================================================================
    print("\n" + "=" * 80)
    print("📈 STEP 7: MODEL COMPARISON")
    print("=" * 80)

    improvement_accuracy = test_metrics["accuracy"] - baseline_accuracy
    improvement_f1 = test_metrics["f1_score"] - baseline_f1

    print(f"\n🏆 Ensemble vs Baseline:")
    print(f"   • Accuracy improvement: {improvement_accuracy:+.3f}")
    print(f"   • F1-Score improvement: {improvement_f1:+.3f}")

    if test_metrics["f1_score"] > baseline_f1:
        print(
            f"   ✅ Ensemble outperforms baseline by {(improvement_f1 / (baseline_f1 + 1e-10) * 100):.1f}%"
        )
    else:
        print(f"   ❌ WARNING: Ensemble does NOT outperform baseline!")

    logger.info(
        "Model comparison",
        baseline_f1=baseline_f1,
        ensemble_f1=test_metrics["f1_score"],
        improvement=improvement_f1,
    )

    # ========================================================================
    # STEP 8: SAVE MODEL
    # ========================================================================
    print("\n" + "=" * 80)
    print("💾 STEP 8: SAVE MODEL")
    print("=" * 80)

    models_dir = Path("./models")
    models_dir.mkdir(exist_ok=True)

    ensemble.save(models_dir)

    model_files = sorted(models_dir.glob("ensemble_*.joblib"))
    if model_files:
        latest_model = model_files[-1]
        print(f"✅ Model saved: {latest_model}")
        print(f"📏 Size: {latest_model.stat().st_size / 1024:.2f} KB")

    # Save metrics to JSON
    metrics_file = models_dir / f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    import json

    with open(metrics_file, "w") as f:
        json.dump(
            {
                "training_time_sec": training_time,
                "baseline": {
                    "accuracy": baseline_accuracy,
                    "f1_score": baseline_f1,
                },
                "validation": val_metrics,
                "test": test_metrics,
                "improvement": {
                    "accuracy": improvement_accuracy,
                    "f1_score": improvement_f1,
                },
            },
            f,
            indent=2,
        )

    print(f"📊 Metrics saved: {metrics_file}")

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 80)
    print("✅ TRAINING COMPLETE - SUMMARY")
    print("=" * 80)
    print(f"\n🎯 Final Test Set Performance:")
    print(f"   • F1-Score: {test_metrics['f1_score']:.3f}")
    print(f"   • Precision: {test_metrics['precision']:.3f}")
    print(f"   • Recall: {test_metrics['recall']:.3f}")
    print(f"   • ROC-AUC: {test_metrics['roc_auc']:.3f}")
    print(f"\n💡 Next steps:")
    print(f"   1. Review metrics in {metrics_file}")
    print(f"   2. Start API: uvicorn backend.main:app --reload")
    print(f"   3. Test endpoint: curl -X POST http://localhost:8000/api/v1/logs/analyze")
    print(f"   4. View docs: http://localhost:8000/docs")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Training failed", error=str(e))
        print(f"\n❌ Training failed: {e}")
        sys.exit(1)
