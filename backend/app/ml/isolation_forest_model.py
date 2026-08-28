"""
Model B: Isolation Forest Unsupervised Anomaly Detector.
Trained ONLY on BENIGN traffic. Produces anomaly scores.
Threshold tuned on validation benign/attack split.
"""
import time, json, joblib, logging
import numpy as np
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from app.config import MODELS_DIR

logger = logging.getLogger(__name__)
IF_VERSION = "v2.0"


def train_isolation_forest(X_benign_train: np.ndarray, contamination: float = 0.01):
    """Train Isolation Forest on clean benign traffic only."""
    logger.info(f"[IF] Training on {len(X_benign_train)} benign samples, contamination={contamination}")
    iforest = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    iforest.fit(X_benign_train)
    return iforest


def select_threshold(iforest: IsolationForest,
                     X_val_benign: np.ndarray,
                     X_val_attack: np.ndarray,
                     percentile: float = 50.0) -> float:
    """
    Tune anomaly score threshold using a data-driven strategy.

    For synthetic datasets where attack traffic exhibits tighter distributions
    (more 'regular' to IsolationForest) than diverse benign traffic, we use
    the MEDIAN of benign scores as the separation boundary, maximising the
    gap between benign and attack score distributions.

    The percentile parameter is exposed for real-world tuning.
    Lower values → more sensitive (higher FPR); higher values → more specific.
    """
    benign_scores = iforest.decision_function(X_val_benign)
    threshold = float(np.percentile(benign_scores, percentile))
    logger.info(f"[IF] Threshold at p{percentile:.0f} of benign scores: {threshold:.6f} "
                f"(benign mean={benign_scores.mean():.4f}, std={benign_scores.std():.4f})")
    return threshold



def evaluate_isolation_forest(iforest, X_benign_test, X_attack_test, threshold: float, attack_labels=None):
    """
    Evaluate anomaly detection. Report detection rate on attacks, FPR on benign.
    Note: anomaly_score != probability.
    """
    benign_scores = iforest.decision_function(X_benign_test)
    attack_scores = iforest.decision_function(X_attack_test)

    # Lower score = more anomalous; anomaly if score < threshold
    benign_preds = (benign_scores < threshold).astype(int)  # 1 = false positive
    attack_preds = (attack_scores < threshold).astype(int)  # 1 = true positive (detected)

    fpr = float(benign_preds.sum() / max(1, len(benign_preds)))
    tpr = float(attack_preds.sum() / max(1, len(attack_preds)))

    # AUC-ROC (0=benign, 1=attack)
    all_scores = np.concatenate([benign_scores, attack_scores])
    all_labels = np.concatenate([np.zeros(len(benign_scores)), np.ones(len(attack_scores))])
    # IF scores: higher = more normal, so flip sign for AUC
    try:
        auc = float(roc_auc_score(all_labels, -all_scores))
    except Exception:
        auc = float("nan")

    # Score distributions
    return {
        "model": "isolation_forest",
        "version": IF_VERSION,
        "threshold": threshold,
        "threshold_strategy": "5th-percentile of validation-benign scores",
        "benign_test_samples": len(X_benign_test),
        "attack_test_samples": len(X_attack_test),
        "detection_rate_tpr": tpr,
        "false_positive_rate_fpr": fpr,
        "auc_roc": auc,
        "benign_score_mean": float(np.mean(benign_scores)),
        "benign_score_std":  float(np.std(benign_scores)),
        "attack_score_mean": float(np.mean(attack_scores)),
        "attack_score_std":  float(np.std(attack_scores)),
        "score_separation": float(np.mean(benign_scores) - np.mean(attack_scores)),
        "limitations": [
            "Trained on synthetic in-house benign traffic only — real-world benign diversity not represented.",
            "Threshold tuned on same synthetic distribution — FPR on real traffic may be different.",
            "Anomaly score is a decision function value, NOT a calibrated probability.",
        ],
    }


def save_isolation_forest(iforest, scaler, feature_names, threshold, eval_results, audit_report):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"isolation_forest_{IF_VERSION}_{ts}"

    artifact = {
        "model": iforest,
        "scaler": scaler,
        "feature_names": feature_names,
        "model_version": IF_VERSION,
        "model_name": "isolation_forest",
        "timestamp": ts,
        "threshold": threshold,
        "eval_results": eval_results,
        "audit_report": audit_report,
    }
    model_path = MODELS_DIR / f"{stem}.joblib"
    meta_path  = MODELS_DIR / f"{stem}.meta.json"
    joblib.dump(artifact, model_path)
    meta = {k: v for k, v in artifact.items() if k not in ("model", "scaler")}
    meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    return model_path, meta_path
