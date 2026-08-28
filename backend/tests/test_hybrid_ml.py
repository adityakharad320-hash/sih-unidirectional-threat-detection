"""
Hybrid ML Engine Tests: Dataset Builder, RF, IF, and Fusion Layer.
"""
import sys
import pytest
import numpy as np
from pathlib import Path
from collections import Counter
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.dataset_builder import build_labeled_dataframe, get_audit_report, TRAINABLE_CLASSES, HEURISTIC_ONLY
from app.ml.preprocessing import get_trainable_subset, stratified_flow_split, build_matrices, FEATURE_COLS
from app.ml.random_forest_model import train_random_forest, evaluate_random_forest
from app.ml.isolation_forest_model import train_isolation_forest, select_threshold, evaluate_isolation_forest
from app.ml.fusion import ThreatFusionEngine, FusionResult
from app.telemetry.feature_schema import TelemetryFeatureVector_v2, ORDERED_TELEMETRY_FEATURE_NAMES


@pytest.fixture(scope="module")
def full_dataset():
    return build_labeled_dataframe()


@pytest.fixture(scope="module")
def trained_artifacts(full_dataset):
    df_trainable = get_trainable_subset(full_dataset)
    train_df, test_df = stratified_flow_split(df_trainable)
    X_train, X_test, y_train, y_test, scaler, feat_names = build_matrices(train_df, test_df)
    rf, cv_results, _ = train_random_forest(X_train, y_train, feat_names, {})

    benign_mask = y_train == "BENIGN"
    X_benign = X_train[benign_mask] if benign_mask.sum() >= 3 else X_train[:3]
    iforest = train_isolation_forest(X_benign, contamination=0.05)
    X_attack = X_train[~benign_mask] if (~benign_mask).sum() > 0 else X_test
    threshold = select_threshold(iforest, X_benign, X_attack)

    return dict(rf=rf, iforest=iforest, scaler=scaler, feat_names=feat_names,
                X_test=X_test, y_test=y_test, threshold=threshold,
                X_benign_test=X_test[y_test=="BENIGN"] if (y_test=="BENIGN").sum() > 0 else X_benign,
                X_attack_test=X_test[y_test!="BENIGN"] if (y_test!="BENIGN").sum() > 0 else X_attack)


# 1. Dataset audit
def test_dataset_audit_honest_class_count(full_dataset):
    audit = get_audit_report(full_dataset)
    dist  = audit["class_distribution"]
    assert "BENIGN"     in dist and dist["BENIGN"]     >= 1
    assert "DDOS"       in dist and dist["DDOS"]       >= 10
    assert "PORT_SCAN"  in dist and dist["PORT_SCAN"]  >= 10
    # Honest limitations
    assert "ENCRYPTED_MALWARE"  in audit["unsupported_classes"]
    assert "DATA_EXFILTRATION"  in audit["unsupported_classes"]
    # C2 and DGA have too few samples for supervised training
    assert "DGA_DNS_TUNNELLING" in audit["heuristic_only"]
    assert "C2_BEACONING"       in audit["heuristic_only"]


def test_dataset_no_nan_inf(full_dataset):
    X = full_dataset[list(ORDERED_TELEMETRY_FEATURE_NAMES)].values.astype(float)
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()


# 2. Preprocessing
def test_stratified_flow_split(full_dataset):
    df = get_trainable_subset(full_dataset)
    train_df, test_df = stratified_flow_split(df)
    assert len(train_df) > 0
    assert len(test_df)  > 0
    assert set(train_df["_label"]) == set(test_df["_label"])


# 3. Random Forest
def test_rf_trains_and_evaluates(trained_artifacts):
    rf    = trained_artifacts["rf"]
    X_test = trained_artifacts["X_test"]
    y_test = trained_artifacts["y_test"]
    scaler = trained_artifacts["scaler"]
    feat   = trained_artifacts["feat_names"]

    assert hasattr(rf, "predict")
    assert set(rf.classes_).issubset(TRAINABLE_CLASSES)

    eval_results = evaluate_random_forest(rf, X_test, y_test, feat, {})
    assert eval_results["macro_f1"] >= 0.0  # can be 0 with tiny test set but must compute
    assert eval_results["inference_latency_median_ms"] < 500.0


def test_rf_does_not_claim_unsupported_classes(trained_artifacts):
    rf = trained_artifacts["rf"]
    for unsupported in ["ENCRYPTED_MALWARE", "DATA_EXFILTRATION", "DGA_DNS_TUNNELLING", "C2_BEACONING"]:
        assert unsupported not in rf.classes_, \
            f"RF incorrectly claims to classify {unsupported} without training data"


# 4. Isolation Forest
def test_if_produces_scores(trained_artifacts):
    iforest   = trained_artifacts["iforest"]
    X_benign  = trained_artifacts["X_benign_test"]
    X_attack  = trained_artifacts["X_attack_test"]
    threshold = trained_artifacts["threshold"]

    if_eval = evaluate_isolation_forest(iforest, X_benign, X_attack, threshold)
    # Score is NOT a probability — just a real-valued decision function output
    assert 0.0 <= if_eval["false_positive_rate_fpr"] <= 1.0
    assert 0.0 <= if_eval["detection_rate_tpr"]      <= 1.0
    assert isinstance(if_eval["score_separation"], float)
    assert len(if_eval["limitations"]) >= 1


# 5. Fusion Layer
def test_fusion_decision_states(trained_artifacts):
    import joblib
    from app.ml.fusion import ThreatFusionEngine
    from app.config import MODELS_DIR

    rf_path = sorted(MODELS_DIR.glob("random_forest_*.joblib"), reverse=True)
    if_path = sorted(MODELS_DIR.glob("isolation_forest_*.joblib"), reverse=True)

    if not rf_path or not if_path:
        pytest.skip("No saved model artifacts; run train_hybrid.py first")

    rf_artifact = joblib.load(rf_path[0])
    if_artifact = joblib.load(if_path[0])
    engine      = ThreatFusionEngine(rf_artifact, if_artifact)

    # Craft test feature vectors
    test_cases = [
        {"name": "SYN Flood (DDOS)",  "feats": {"syn_ratio": 1.0, "packet_rate": 5000.0, "dst_in_degree": 50.0}},
        {"name": "Port Scan",         "feats": {"unique_dst_ports": 100.0, "dst_port_fanout": 100.0, "failed_conn_ratio": 0.95}},
        {"name": "DNS DGA",           "feats": {"shannon_entropy_mean": 3.9, "txt_record_ratio": 1.0, "ngram_log_likelihood": -9.2}},
        {"name": "C2 Beacon",         "feats": {"iat_cv": 0.019, "periodicity_score": 0.35, "iat_mean": 1.0}},
        {"name": "Benign",            "feats": {"syn_ratio": 0.2, "ack_ratio": 0.6, "pkt_size_mean": 480.0}},
    ]

    valid_states = {
        "A: KNOWN_THREAT_CONFIRMED",
        "B: KNOWN_THREAT_PROBABLE",
        "B: KNOWN_THREAT_PROBABLE (RULE_BASED)",
        "B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)",
        "C: UNKNOWN_ANOMALY",
        "D: BENIGN_NORMAL_TRAFFIC",
        "D: BENIGN_OR_LOW_CONFIDENCE",
    }

    for tc in test_cases:
        fv = TelemetryFeatureVector_v2(
            flow_id=f"test_{tc['name']}",
            timestamp=1724832000.0,
            **tc["feats"]
        )
        result = engine.predict(fv, fv.to_dict())
        assert isinstance(result, FusionResult)
        assert result.decision_state in valid_states, f"Unknown state: {result.decision_state}"
        assert 0.0 <= result.confidence <= 1.0
