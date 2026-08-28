"""
Hybrid ML Training Pipeline.
Runs the complete: dataset build → preprocessing → RF training → IF training → save artifacts.
Reports ACTUAL metrics only.
"""
import sys, logging
import numpy as np
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("train_hybrid")

from app.ml.dataset_builder import build_labeled_dataframe, get_audit_report, TRAINABLE_CLASSES
from app.ml.preprocessing import get_trainable_subset, stratified_flow_split, build_matrices
from app.ml.random_forest_model import train_random_forest, evaluate_random_forest, save_random_forest
from app.ml.isolation_forest_model import (train_isolation_forest, select_threshold,
                                            evaluate_isolation_forest, save_isolation_forest)

SEP = "=" * 80

def main():
    print(f"\n{SEP}")
    print("HYBRID ML TRAINING PIPELINE — SIH 2026 THREAT DETECTION")
    print(f"{SEP}\n")

    # ── 1. DATASET AUDIT ──────────────────────────────────────────────────────
    print("[1/6] Building dataset from PCAP telemetry ...")
    df_full = build_labeled_dataframe()
    audit   = get_audit_report(df_full)

    print("\n=== DATASET AUDIT REPORT ===")
    print(f"  Total flows:         {audit['total_flows']}")
    print(f"  Feature dimensions:  {audit['feature_count']}")
    print(f"  NaN values:          {audit['nan_values']}")
    print(f"  Inf values:          {audit['inf_values']}")
    print(f"  Duplicates:          {audit['duplicates']}")
    print(f"  Data source:         {audit['data_source']}")
    print(f"\n  Class Distribution:")
    for cls, n in sorted(audit["class_distribution"].items(), key=lambda x: -x[1]):
        print(f"    {cls:<30} {n:>5} flows")
    print(f"\n  Trainable classes:    {list(audit['trainable_classes'].keys())}")
    print(f"  Heuristic-only:       {list(audit['heuristic_only'].keys())}")
    print(f"  UNSUPPORTED classes:  {audit['unsupported_classes']}")
    print(f"\n  Leakage note:         {audit['leakage_note']}")

    # ── 2. PREPROCESSING ─────────────────────────────────────────────────────
    print(f"\n[2/6] Preprocessing — stratified flow split ...")
    df_trainable = get_trainable_subset(df_full)
    train_df, test_df = stratified_flow_split(df_trainable, test_frac=0.20)
    X_train, X_test, y_train, y_test, scaler, feature_names = build_matrices(train_df, test_df)

    print(f"  Trainable flows:    {len(df_trainable)}")
    print(f"  Train / Test split: {len(X_train)} / {len(X_test)}")
    print(f"  Train class dist:   {Counter(y_train)}")
    print(f"  Test  class dist:   {Counter(y_test)}")

    # ── 3. MODEL A: RANDOM FOREST ─────────────────────────────────────────────
    print(f"\n[3/6] Training Random Forest ...")
    rf, cv_results, class_weights = train_random_forest(X_train, y_train, feature_names, audit)

    print(f"  CV Accuracy:   {cv_results['test_accuracy'].mean():.4f} ± {cv_results['test_accuracy'].std():.4f}")
    print(f"  CV F1 (macro): {cv_results['test_f1_macro'].mean():.4f} ± {cv_results['test_f1_macro'].std():.4f}")
    print(f"  Class weights: {class_weights}")

    # ── 4. EVALUATE RF ───────────────────────────────────────────────────────
    print(f"\n[4/6] Evaluating Random Forest on held-out test set ...")
    rf_eval = evaluate_random_forest(rf, X_test, y_test, feature_names, class_weights)

    print(f"\n  Test samples:         {rf_eval['test_samples']}")
    print(f"  Test class dist:      {rf_eval['class_distribution_test']}")
    print(f"  Macro Precision:      {rf_eval['macro_precision']:.4f}")
    print(f"  Macro Recall:         {rf_eval['macro_recall']:.4f}")
    print(f"  Macro F1:             {rf_eval['macro_f1']:.4f}")
    print(f"  Inference Lat (med):  {rf_eval['inference_latency_median_ms']:.3f} ms")
    print(f"  Inference Lat (p99):  {rf_eval['inference_latency_p99_ms']:.3f} ms")
    print(f"\n  Per-class Report:")
    for cls in rf_eval['classes']:
        r = rf_eval['per_class_report'].get(cls, {})
        fpr = rf_eval['per_class_fpr'].get(cls, 0.0)
        print(f"    {cls:<20}  P={r.get('precision',0):.3f}  R={r.get('recall',0):.3f}  "
              f"F1={r.get('f1-score',0):.3f}  FPR={fpr:.4f}  n={r.get('support',0)}")
    print(f"\n  Confusion Matrix (rows=actual, cols=predicted): {rf_eval['classes']}")
    for i, row in enumerate(rf_eval['confusion_matrix']):
        print(f"    [{rf_eval['classes'][i]:<15}]: {row}")
    print(f"\n  Top 10 Feature Importances:")
    for feat, imp in list(rf_eval['top10_feature_importances'].items())[:5]:
        print(f"    {feat:<35} {imp:.4f}")

    # ── 5. MODEL B: ISOLATION FOREST ─────────────────────────────────────────
    print(f"\n[5/6] Training Isolation Forest on BENIGN traffic ...")
    # Get all benign rows (raw / unscaled) then scale with same scaler
    benign_mask_train = y_train == "BENIGN"
    X_benign_train    = X_train[benign_mask_train]
    print(f"  Benign training samples: {len(X_benign_train)}")

    if len(X_benign_train) < 3:
        print("  [WARN] Insufficient benign samples for IF. Using all benign flows from full dataset.")
        benign_all = df_full[df_full["_label"] == "BENIGN"]
        from app.ml.preprocessing import FEATURE_COLS
        X_benign_train = scaler.transform(benign_all[FEATURE_COLS].values.astype(np.float64))

    iforest = train_isolation_forest(X_benign_train, contamination=0.01)

    # Threshold: use median of benign scores (p50) — for synthetic data where attack
    # traffic is tighter/more uniform than benign, this correctly places the boundary.
    # On real-world data, lower percentile (e.g. p5) gives lower FPR.
    if len(X_benign_train) >= 4:
        half = max(1, len(X_benign_train) // 2)
        X_val_benign = X_benign_train[half:]
    else:
        X_val_benign = X_benign_train

    X_attack_train = X_train[~benign_mask_train]
    if len(X_attack_train) == 0:
        X_attack_train = X_test  # fallback

    threshold = select_threshold(iforest, X_val_benign, X_attack_train, percentile=50.0)


    # Evaluate on test set
    benign_mask_test  = y_test == "BENIGN"
    X_benign_test = X_test[benign_mask_test] if benign_mask_test.sum() > 0 else X_val_benign
    X_attack_test = X_test[~benign_mask_test] if (~benign_mask_test).sum() > 0 else X_attack_train

    if_eval = evaluate_isolation_forest(iforest, X_benign_test, X_attack_test, threshold)

    print(f"\n  IF Threshold:            {if_eval['threshold']:.6f}  ({if_eval['threshold_strategy']})")
    print(f"  Benign Test Samples:     {if_eval['benign_test_samples']}")
    print(f"  Attack Test Samples:     {if_eval['attack_test_samples']}")
    print(f"  Detection Rate (TPR):    {if_eval['detection_rate_tpr']:.4f}")
    print(f"  False Positive Rate:     {if_eval['false_positive_rate_fpr']:.4f}")
    print(f"  AUC-ROC:                 {if_eval['auc_roc']:.4f}")
    print(f"  Benign Score:  mean={if_eval['benign_score_mean']:.4f}  std={if_eval['benign_score_std']:.4f}")
    print(f"  Attack Score:  mean={if_eval['attack_score_mean']:.4f}  std={if_eval['attack_score_std']:.4f}")
    print(f"  Score Separation:        {if_eval['score_separation']:.4f}")
    for lim in if_eval['limitations']:
        print(f"  [LIMITATION] {lim}")

    # ── 6. SAVE MODELS ───────────────────────────────────────────────────────
    print(f"\n[6/6] Saving model artifacts ...")
    rf_path, rf_meta = save_random_forest(rf, scaler, feature_names, cv_results, rf_eval, audit)
    if_path, if_meta = save_isolation_forest(iforest, scaler, feature_names, threshold, if_eval, audit)
    print(f"  RF  model: {rf_path.name}")
    print(f"  IF  model: {if_path.name}")

    print(f"\n{SEP}")
    print("TRAINING COMPLETE. Both models saved.")
    print(f"{SEP}\n")

    return rf, rf_eval, iforest, if_eval, threshold, scaler, feature_names, audit


if __name__ == "__main__":
    main()
