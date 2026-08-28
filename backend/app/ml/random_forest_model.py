"""
Model A: Random Forest Supervised Classifier.
Trained on BENIGN, DDOS, PORT_SCAN (classes with sufficient samples).
"""
import time, json, joblib, logging
import numpy as np
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (classification_report, confusion_matrix,
                              precision_score, recall_score, f1_score)
from sklearn.utils.class_weight import compute_class_weight
from app.config import MODELS_DIR

logger = logging.getLogger(__name__)
RF_VERSION = "v2.0"


def train_random_forest(X_train, y_train, feature_names, audit_report):
    classes = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight_dict = dict(zip(classes, weights))
    logger.info(f"[RF] Class weights: {class_weight_dict}")

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    # 5-fold stratified CV
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = cross_validate(
        rf, X_train, y_train, cv=cv,
        scoring=["accuracy", "f1_macro", "precision_macro", "recall_macro"],
        return_train_score=True
    )
    rf.fit(X_train, y_train)
    return rf, cv_results, class_weight_dict


def evaluate_random_forest(rf, X_test, y_test, feature_names, class_weight_dict):
    classes_sorted = sorted(rf.classes_)

    # Latency benchmark
    latencies = []
    for _ in range(200):
        t0 = time.perf_counter()
        rf.predict(X_test[:1])
        latencies.append((time.perf_counter() - t0) * 1000)
    median_lat = float(np.median(latencies))
    p99_lat = float(np.percentile(latencies, 99))

    y_pred = rf.predict(X_test)
    proba  = rf.predict_proba(X_test)

    cm = confusion_matrix(y_test, y_pred, labels=classes_sorted)
    report = classification_report(y_test, y_pred, labels=classes_sorted,
                                   zero_division=0, output_dict=True)

    # Per-class FPR
    fpr = {}
    for i, cls in enumerate(classes_sorted):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        fpr[cls] = float(fp / max(1, fp + tn))

    # Top feature importances
    importances = rf.feature_importances_
    top10_idx = np.argsort(importances)[::-1][:10]
    top10 = {feature_names[i]: float(importances[i]) for i in top10_idx}

    return {
        "model": "random_forest",
        "version": RF_VERSION,
        "classes": classes_sorted,
        "test_samples": len(y_test),
        "class_distribution_test": dict(Counter(y_test)),
        "macro_precision": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_recall":    float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_f1":        float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "per_class_report": report,
        "confusion_matrix": cm.tolist(),
        "per_class_fpr": fpr,
        "top10_feature_importances": top10,
        "inference_latency_median_ms": median_lat,
        "inference_latency_p99_ms": p99_lat,
    }


def save_random_forest(rf, scaler, feature_names, cv_results, eval_results, audit_report):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"random_forest_{RF_VERSION}_{ts}"

    artifact = {
        "model": rf,
        "scaler": scaler,
        "feature_names": feature_names,
        "label_map": {cls: i for i, cls in enumerate(sorted(rf.classes_))},
        "model_version": RF_VERSION,
        "model_name": "random_forest",
        "timestamp": ts,
        "trainable_classes": list(rf.classes_),
        "cv_accuracy_mean": float(cv_results["test_accuracy"].mean()),
        "cv_accuracy_std":  float(cv_results["test_accuracy"].std()),
        "cv_f1_mean": float(cv_results["test_f1_macro"].mean()),
        "cv_f1_std":  float(cv_results["test_f1_macro"].std()),
        "eval_results": eval_results,
        "audit_report": audit_report,
    }
    model_path = MODELS_DIR / f"{stem}.joblib"
    meta_path  = MODELS_DIR / f"{stem}.meta.json"
    joblib.dump(artifact, model_path)
    meta = {k: v for k, v in artifact.items() if k not in ("model", "scaler")}
    meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    return model_path, meta_path
