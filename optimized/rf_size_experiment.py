"""
Random Forest Architecture & Tree Count Scaling Experiment.

Implements Requirement 13:
- Evaluates tree sizes: 10, 25, 50, 100 trees.
- Measures single-sample latency (p50, p95, p99, mean), model file size.
- Evaluates statistical detection metrics: Precision, Recall, Macro F1, False Positive Rate (FPR).
- Saves machine-readable report to benchmarks/results/rf_size_experiment.json.
"""
import sys
import time
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.ml.dataset_builder import build_labeled_dataframe
from app.ml.preprocessing import get_trainable_subset, stratified_flow_split, build_matrices


def run_rf_size_experiment() -> Dict[str, Any]:
    print("=" * 90)
    print("RANDOM FOREST TREE SIZE SCALING EXPERIMENT (10, 25, 50, 100 TREES)")
    print("=" * 90)

    # 1. Build and split dataset exactly as in production training
    print("[1/3] Loading dataset & generating stratified train/test split ...")
    df_full = build_labeled_dataframe()
    df_trainable = get_trainable_subset(df_full)
    train_df, test_df = stratified_flow_split(df_trainable, test_frac=0.20, random_state=42)
    X_train, X_test, y_train, y_test, scaler, feature_names = build_matrices(train_df, test_df)

    print(f"  Training samples: {len(X_train)} | Test samples: {len(X_test)} | Features: {len(feature_names)}")

    tree_configs = [10, 25, 50, 100]
    results = {}

    print("\n[2/3] Training and profiling models across tree budgets ...")

    for n_trees in tree_configs:
        print(f"  * Training RF with {n_trees:>3} trees ...")
        rf = RandomForestClassifier(
            n_estimators=n_trees,
            max_depth=16,
            random_state=42,
            n_jobs=1,
            class_weight="balanced"
        )
        rf.fit(X_train, y_train)

        # ── Measure Single-Sample Inference Latency ──
        # Warmup
        for _ in range(50):
            _ = rf.predict_proba(X_test[:1])

        latencies_ms = []
        for i in range(len(X_test)):
            row = X_test[i:i+1]
            t0 = time.perf_counter_ns()
            _ = rf.predict_proba(row)
            t1 = time.perf_counter_ns()
            latencies_ms.append((t1 - t0) / 1_000_000.0)

        # ── Evaluate Classification Quality on Held-out Test Set ──
        y_pred = rf.predict(X_test)
        classes = sorted(list(set(y_test)))
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
        
        # Calculate FPR on benign traffic specifically
        cm = confusion_matrix(y_test, y_pred, labels=classes)
        benign_idx = classes.index("BENIGN") if "BENIGN" in classes else -1
        benign_fpr = 0.0
        if benign_idx >= 0:
            fp = sum(cm[i][benign_idx] for i in range(len(classes)) if i != benign_idx)
            tn = sum(cm[i][j] for i in range(len(classes)) for j in range(len(classes)) if i != benign_idx and j != benign_idx)
            benign_fpr = float(fp / max(1, fp + tn))

        # Size estimation
        import pickle
        dumped_bytes = len(pickle.dumps(rf))
        size_kb = dumped_bytes / 1024.0

        results[f"{n_trees}_trees"] = {
            "n_estimators": n_trees,
            "macro_precision": round(float(precision), 4),
            "macro_recall": round(float(recall), 4),
            "macro_f1": round(float(f1), 4),
            "benign_fpr": round(float(benign_fpr), 4),
            "model_size_kb": round(float(size_kb), 1),
            "latency_p50_ms": round(float(np.percentile(latencies_ms, 50)), 4),
            "latency_p95_ms": round(float(np.percentile(latencies_ms, 95)), 4),
            "latency_p99_ms": round(float(np.percentile(latencies_ms, 99)), 4),
            "latency_mean_ms": round(float(np.mean(latencies_ms)), 4)
        }

    # 3. Print Comparison Table
    print("\n" + "=" * 90)
    print(f"{'Trees':<8} | {'F1-Macro':<10} | {'Precision':<10} | {'Recall':<10} | {'Benign FPR':<10} | {'p50 Latency':<12} | {'Model Size':<10}")
    print("-" * 90)
    for k, v in results.items():
        print(
            f"{v['n_estimators']:<8} | "
            f"{v['macro_f1']:<10.4f} | "
            f"{v['macro_precision']:<10.4f} | "
            f"{v['macro_recall']:<10.4f} | "
            f"{v['benign_fpr']:<10.4f} | "
            f"{v['latency_p50_ms']:>8.3f} ms  | "
            f"{v['model_size_kb']:>7.1f} KB"
        )
    print("=" * 90)

    # Save to benchmarks/results/rf_size_experiment.json
    results_dir = ROOT_DIR / "benchmarks" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    json_path = results_dir / "rf_size_experiment.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[Artifact Created] Saved experiment report to: {json_path}")
    return results


if __name__ == "__main__":
    run_rf_size_experiment()
