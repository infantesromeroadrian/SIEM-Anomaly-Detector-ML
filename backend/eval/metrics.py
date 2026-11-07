"""Detection metrics at a fixed operating point plus threshold-free summaries."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def choose_threshold(val_scores: np.ndarray, quantile: float) -> float:
    """
    Pick the alert threshold from benign validation scores only.

    The threshold is the ``quantile`` of the validation score distribution, i.e.
    the operating point with roughly ``1 - quantile`` false-positive rate on
    benign validation traffic. The test set plays no role.
    """
    return float(np.quantile(val_scores, quantile))


def evaluate(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    labels: Sequence[frozenset[str]],
    attack_types: Sequence[str],
    subset_mask: np.ndarray | None = None,
) -> dict[str, object]:
    """
    Compute precision/recall/F1/PR-AUC/ROC-AUC/FPR and recall per attack type.

    ``subset_mask`` marks events (in test order) whose attack lines are reported
    separately as ``recall_low_rate_attacks``.
    """
    y_true = np.asarray(y_true).astype(bool)
    pred = scores > threshold
    tp = int(np.sum(pred & y_true))
    fp = int(np.sum(pred & ~y_true))
    fn = int(np.sum(~pred & y_true))
    tn = int(np.sum(~pred & ~y_true))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    per_type: dict[str, dict[str, float | int]] = {}
    for t in attack_types:
        mask = np.array([t in lab for lab in labels])
        n = int(mask.sum())
        per_type[t] = {
            "n": n,
            "recall": float(pred[mask].mean()) if n else float("nan"),
        }
    low_rate: dict[str, float | int] = {"n": 0, "recall": float("nan")}
    if subset_mask is not None:
        sub = np.asarray(subset_mask).astype(bool) & y_true
        low_rate = {
            "n": int(sub.sum()),
            "recall": float(pred[sub].mean()) if sub.any() else float("nan"),
        }
    both_classes = 0 < y_true.sum() < len(y_true)
    return {
        "threshold": threshold,
        "n": int(len(y_true)),
        "n_attack": int(y_true.sum()),
        "prevalence": float(y_true.mean()),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc": float(average_precision_score(y_true, scores)) if both_classes else None,
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else None,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "recall_by_attack_type": per_type,
        "recall_low_rate_attacks": low_rate,
    }


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion ``k / n``."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (float(max(0.0, centre - half)), float(min(1.0, centre + half)))
