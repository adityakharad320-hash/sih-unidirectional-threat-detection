"""
evaluate.py — Model Evaluation on Held-Out Test Split

Uses actual held-out split. Reports actual precision, recall, F1, confusion
matrix, false-positive rate, and inference latency. Never fabricates numbers.
"""
import sys
import time
import json
import numpy as np
import joblib
from pathlib import Path
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from training.preprocessing import build_training_dataset
from app.config import MODELS_DIR


def find_latest_model(name_prefix: str):
    candidates = sorted(MODELS_DIR.glob(f"{name_prefix}_*.joblib"), reverse=True)
    if not candidates:
        raise FileNotFoundError(f"No model found with prefix: {name_prefix}")
    return candidates[0]


def compute_fpr(cm, class_idx):
    """Compute per-class false positive rate from confusion matrix."""
    fp = cm[:, class_idx].sum() - cm[class_idx, class_idx]
    tn = cm.sum() - cm[class_idx, :].sum() - cm[:, class_idx].sum() + cm[class_idx, class_idx]
    denom = fp + tn
    return float(fp / denom) if denom > 0 else 0.0


def evaluate_model(model_artifact, X_test, y_test, feature_names, label_map, model_name):
    model = model_artifact["model"]
    scaler = model_artifact["scaler"]
    is_xgb = "xgboost" in model_name.lower()

    X_scaled = scaler.transform(X_test)

    # Latency benchmark: run 100 predictions, take median
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        _ = model.predict(X_scaled[:1])
        latencies.append((time.perf_counter() - t0) * 1000)
    median_latency_ms = float(np.median(latencies))

    # Full test set predictions
    t0 = time.perf_counter()
    if is_xgb:
        inv_map = {v: k for k, v in label_map.items()}
        y_pred_int = model.predict(X_scaled)
        y_pred_proba = model.predict_proba(X_scaled)
        y_pred = np.array([inv_map[int(p)] for p in y_pred_int])
    else:
        y_pred = model.predict(X_scaled)
        y_pred_proba = model.predict_proba(X_scaled)

    total_infer_ms = (time.perf_counter() - t0) * 1000
    classes = sorted(label_map.keys())

    # Metrics
    precision = precision_score(y_test, y_pred, average="macro", zero_division=0)
    recall = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=classes)

    print(f"\n{'=' * 70}")
    print(f"EVALUATION: {model_name.upper()}")
    print(f"{'=' * 70}")
    print(f"  Test samples:     {len(X_test)}")
    print(f"  Class dist:       {Counter(y_test)}")
    print(f"  Macro Precision:  {precision:.4f}")
    print(f"  Macro Recall:     {recall:.4f}")
    print(f"  Macro F1-Score:   {f1:.4f}")
    print(f"  Single-item latency (median):  {median_latency_ms:.3f} ms")
    print(f"  Full test batch ({len(X_test)} items): {total_infer_ms:.2f} ms")

    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, labels=classes, zero_division=0, digits=4))

    print(f"  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"  Classes: {classes}")
    for i, row in enumerate(cm):
        print(f"    [{classes[i]:<12}]: {row}")

    print(f"\n  Per-Class False Positive Rate:")
    for i, cls in enumerate(classes):
        fpr = compute_fpr(cm, i)
        print(f"    {cls:<15}: FPR = {fpr:.4f}")

    # Top feature importances (RF only)
    if not is_xgb and hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        top_idx = np.argsort(importances)[::-1][:10]
        print(f"\n  Top 10 Feature Importances:")
        for idx in top_idx:
            print(f"    {feature_names[idx]:<35}: {importances[idx]:.4f}")

    return {
        "model_name": model_name,
        "test_samples": len(X_test),
        "macro_precision": precision,
        "macro_recall": recall,
        "macro_f1": f1,
        "median_latency_ms": median_latency_ms,
        "confusion_matrix": cm.tolist(),
        "classes": classes
    }


def main():
    X_scaled, y, _, X_raw, feature_names, audit_report = build_training_dataset()

    # Stratified 80/20 train-test split on the raw (unscaled) data
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train: {X_train_raw.shape[0]} | Test: {X_test_raw.shape[0]}")
    print(f"Test class distribution: {Counter(y_test)}")
    print(f"\n[WARN] dns_dga and c2_beacon NOT in test set (insufficient data)")
    print(f"[WARN] exfiltration class: NOT SUPPORTED in this model version")

    results = {}
    for prefix in ["random_forest", "xgboost"]:
        artifact_path = find_latest_model(prefix)
        artifact = joblib.load(artifact_path)
        label_map = artifact["label_map"]
        # evaluate_model will use artifact's own scaler to transform X_test_raw
        res = evaluate_model(artifact, X_test_raw, y_test, feature_names, label_map, prefix)
        results[prefix] = res

    print("\n=== SIDE-BY-SIDE MACRO F1 COMPARISON ===")
    for name, res in results.items():
        print(f"  {name:<20}: F1={res['macro_f1']:.4f}  Latency={res['median_latency_ms']:.3f}ms")

    print("\n=== CLASSES NOT EVALUATED (Insufficient Data) ===")
    for cls, cnt in audit_report["heuristic_only_classes"].items():
        print(f"  {cls}: {cnt} sample(s) — Heuristic rules apply, no RF/XGB metrics available")
    print(f"  exfiltration: No labeled data — NOT SUPPORTED in model v1")


if __name__ == "__main__":
    main()
