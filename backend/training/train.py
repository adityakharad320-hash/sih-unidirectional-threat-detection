"""
train.py — Supervised Classifier Training for Module 3

Trains Random Forest and XGBoost classifiers on labeled flow feature vectors.

IMPORTANT:
- Only trains on classes with >= MIN_SAMPLES_FOR_TRAINING samples.
- Uses stratified k-fold cross-validation.
- Applies class_weight to handle imbalance where supported.
- Saves versioned model artifacts.
- Never fabricates metrics.
"""
import sys
import json
import time
import hashlib
import joblib
import numpy as np
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from training.preprocessing import build_training_dataset
from app.config import MODELS_DIR

MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_VERSION = "v1.0"


def compute_class_weights(y):
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    return dict(zip(classes, weights))


def train_random_forest(X, y):
    print("\n[RF] Training Random Forest Classifier...")
    class_weights = compute_class_weights(y)
    print(f"  Class weights (balanced): {class_weights}")

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    start = time.perf_counter()
    cv_results = cross_validate(
        rf, X, y, cv=cv,
        scoring=["accuracy", "f1_macro", "precision_macro", "recall_macro"],
        return_train_score=True
    )
    cv_elapsed = time.perf_counter() - start

    print(f"  CV Accuracy:   {cv_results['test_accuracy'].mean():.4f} (+/- {cv_results['test_accuracy'].std():.4f})")
    print(f"  CV F1 (macro): {cv_results['test_f1_macro'].mean():.4f} (+/- {cv_results['test_f1_macro'].std():.4f})")
    print(f"  CV Time:       {cv_elapsed:.2f}s")

    # Final fit on full dataset
    t0 = time.perf_counter()
    rf.fit(X, y)
    fit_time = time.perf_counter() - t0
    print(f"  Final fit time: {fit_time:.3f}s")

    return rf, cv_results


def train_xgboost(X, y):
    print("\n[XGB] Training XGBoost Classifier...")

    # Encode string labels to int
    classes = sorted(np.unique(y))
    label_map = {c: i for i, c in enumerate(classes)}
    y_int = np.array([label_map[c] for c in y])

    # Compute sample weights for class balance
    class_weights = compute_class_weights(y)
    sample_weights = np.array([class_weights[c] for c in y])

    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    start = time.perf_counter()
    # Sklearn 1.4+: pass sample_weight via params dict per estimator
    cv_results = cross_validate(
        xgb_model, X, y_int, cv=cv,
        params={"sample_weight": sample_weights},
        scoring=["accuracy", "f1_macro", "precision_macro", "recall_macro"],
        return_train_score=True
    )
    cv_elapsed = time.perf_counter() - start


    print(f"  CV Accuracy:   {cv_results['test_accuracy'].mean():.4f} (+/- {cv_results['test_accuracy'].std():.4f})")
    print(f"  CV F1 (macro): {cv_results['test_f1_macro'].mean():.4f} (+/- {cv_results['test_f1_macro'].std():.4f})")
    print(f"  CV Time:       {cv_elapsed:.2f}s")

    t0 = time.perf_counter()
    xgb_model.fit(X, y_int, sample_weight=sample_weights)
    fit_time = time.perf_counter() - t0
    print(f"  Final fit time: {fit_time:.3f}s")

    return xgb_model, cv_results, label_map


def save_model(model, name: str, scaler, feature_names: list, label_map: dict,
               cv_results: dict, audit_report: dict, model_version: str = MODEL_VERSION):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_name = f"{name}_{model_version}_{timestamp}"
    artifact_path = MODELS_DIR / f"{artifact_name}.joblib"

    payload = {
        "model": model,
        "scaler": scaler,
        "feature_names": feature_names,
        "label_map": label_map,
        "model_version": model_version,
        "model_name": name,
        "timestamp": timestamp,
        "cv_accuracy_mean": float(cv_results["test_accuracy"].mean()),
        "cv_f1_mean": float(cv_results["test_f1_macro"].mean()),
        "trainable_classes": list(label_map.keys()),
        "audit_report": audit_report,
    }
    joblib.dump(payload, artifact_path)

    # Write metadata sidecar
    meta_path = MODELS_DIR / f"{artifact_name}.meta.json"
    meta = {k: v for k, v in payload.items() if k not in ("model", "scaler")}
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"  Saved: {artifact_path}")
    print(f"  Metadata: {meta_path}")
    return artifact_path


def main():
    print("=" * 70)
    print("MODULE 3: ML TRAINING PIPELINE")
    print("=" * 70)

    X, y, scaler, X_raw, feature_names, audit_report = build_training_dataset()

    print("\n[DATA] Preprocessing complete.")
    print(f"  Samples: {X.shape[0]}  |  Features: {X.shape[1]}")
    print(f"  Class distribution: {Counter(y)}")
    print(f"\n[WARN] Classes NOT trained (heuristic-only): {list(audit_report['heuristic_only_classes'].keys())}")
    print(f"[WARN] Classes NOT supported in this model:   {audit_report['unsupported_classes']}")

    # ── Random Forest ────────────────────────────────────────────────────────
    rf, rf_cv = train_random_forest(X, y)
    rf_classes = sorted(np.unique(y))
    rf_label_map = {c: i for i, c in enumerate(rf_classes)}
    save_model(rf, "random_forest", scaler, feature_names, rf_label_map, rf_cv, audit_report)

    # ── XGBoost ──────────────────────────────────────────────────────────────
    xgb_model, xgb_cv, xgb_label_map = train_xgboost(X, y)
    save_model(xgb_model, "xgboost", scaler, feature_names, xgb_label_map, xgb_cv, audit_report)

    print("\n[DONE] Training complete. Models saved to:", MODELS_DIR)
    print("=" * 70)


if __name__ == "__main__":
    main()
