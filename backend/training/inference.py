"""
inference.py — Real-Time Inference Interface for Module 3

Accepts FeatureVector_v1 from Module 2. Runs:
  1. Supervised RF/XGBoost classifier for {benign, syn_flood, port_scan}
  2. Heuristic rule engine for {dns_dga, c2_beacon}
Produces: prediction, confidence, model_version, detection_method.

IMPORTANT:
- Never claims detection for untrained classes.
- Heuristic detections clearly labeled as RULE_BASED.
- Supervised detections labeled as MODEL_BASED.
"""
import sys
import time
import json
import numpy as np
import joblib
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core.feature_schema import FeatureVector_v1, ORDERED_FEATURE_NAMES
from app.config import MODELS_DIR

# ── Inference Output Schema ───────────────────────────────────────────────────
class InferenceResult(BaseModel):
    flow_id: str
    timestamp: float
    prediction: str
    confidence: float          # [0.0, 1.0] — model probability or heuristic score
    model_version: str
    detection_method: str      # "MODEL_BASED" | "RULE_BASED" | "NO_DETECTION"
    top_class_probabilities: dict  # {class_name: probability}
    inference_latency_ms: float
    warnings: list[str]

# ── Heuristic Thresholds (Documented in FEATURE_CATALOG.md) ──────────────────
HEURISTIC_RULES = {
    "dns_dga": {
        "dns_entropy_mean": (">", 3.5),
        "dns_txt_record_ratio": (">", 0.6),
        "dns_ngram_score": ("<", -5.0),
    },
    "c2_beacon": {
        "iat_cv": ("<", 0.15),
        "iat_mean": (">", 0.1),
        "fft_peak_magnitude": (">", 0.05),
    }
}

def _apply_heuristic(features_dict: dict, rule_class: str) -> tuple[bool, float]:
    """Returns (triggered, confidence_score) for a heuristic rule class."""
    rules = HEURISTIC_RULES.get(rule_class, {})
    if not rules:
        return False, 0.0

    triggered = 0
    for feat_name, (op, threshold) in rules.items():
        val = features_dict.get(feat_name, 0.0)
        if op == ">" and val > threshold:
            triggered += 1
        elif op == "<" and val < threshold:
            triggered += 1

    score = triggered / len(rules)
    return score >= 0.67, round(score, 4)  # 2/3 rules must match

class ThreatInferenceEngine:
    """
    Unified inference engine for supervised classifier + heuristic rules.
    """
    def __init__(self, model_name: str = "random_forest"):
        self._load_model(model_name)

    def _load_model(self, model_name: str):
        candidates = sorted(MODELS_DIR.glob(f"{model_name}_*.joblib"), reverse=True)
        if not candidates:
            raise FileNotFoundError(f"No trained model found: {model_name}")
        artifact = joblib.load(candidates[0])
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_names = artifact["feature_names"]
        self.label_map = artifact["label_map"]
        self.inv_label_map = {v: k for k, v in self.label_map.items()}
        self.model_version = artifact["model_version"]
        self.model_name = artifact["model_name"]
        self.trainable_classes = artifact["trainable_classes"]
        self.is_xgb = "xgboost" in self.model_name.lower()
        print(f"[Inference] Loaded {self.model_name} ({self.model_version}) — trainable classes: {self.trainable_classes}")

    def predict(self, feature_vector: FeatureVector_v1) -> InferenceResult:
        t0 = time.perf_counter()
        warnings = []
        features_dict = feature_vector.to_dict()

        # Build dense array aligned to training feature order
        X_raw = np.array([features_dict.get(f, 0.0) for f in self.feature_names], dtype=np.float64).reshape(1, -1)
        X_scaled = self.scaler.transform(X_raw)

        # ── Supervised classification ─────────────────────────────────────────
        if self.is_xgb:
            y_int = self.model.predict(X_scaled)[0]
            y_pred_str = self.inv_label_map.get(int(y_int), "unknown")
            proba = self.model.predict_proba(X_scaled)[0]
        else:
            y_pred_str = self.model.predict(X_scaled)[0]
            proba = self.model.predict_proba(X_scaled)[0]

        classes = self.model.classes_ if not self.is_xgb else sorted(self.label_map.keys())
        if self.is_xgb:
            proba_dict = {self.inv_label_map.get(i, str(i)): float(p) for i, p in enumerate(proba)}
        else:
            proba_dict = {cls: float(p) for cls, p in zip(classes, proba)}

        supervised_confidence = float(max(proba))

        # ── Heuristic override for DNS/DGA and C2 Beaconing ──────────────────
        dns_triggered, dns_score = _apply_heuristic(features_dict, "dns_dga")
        c2_triggered, c2_score = _apply_heuristic(features_dict, "c2_beacon")

        if dns_triggered and dns_score > supervised_confidence:
            prediction = "dns_dga"
            confidence = dns_score
            method = "RULE_BASED"
            warnings.append("dns_dga detected via heuristic rules (insufficient training data for model-based detection)")
        elif c2_triggered and c2_score > supervised_confidence:
            prediction = "c2_beacon"
            confidence = c2_score
            method = "RULE_BASED"
            warnings.append("c2_beacon detected via heuristic rules (insufficient training data for model-based detection)")
        else:
            prediction = y_pred_str
            confidence = supervised_confidence
            method = "MODEL_BASED"

        latency_ms = (time.perf_counter() - t0) * 1000

        return InferenceResult(
            flow_id=feature_vector.flow_id,
            timestamp=feature_vector.timestamp,
            prediction=prediction,
            confidence=round(confidence, 4),
            model_version=f"{self.model_name}_{self.model_version}",
            detection_method=method,
            top_class_probabilities={k: round(v, 4) for k, v in sorted(proba_dict.items(), key=lambda x: -x[1])},
            inference_latency_ms=round(latency_ms, 4),
            warnings=warnings
        )


if __name__ == "__main__":
    # Quick smoke test
    engine = ThreatInferenceEngine("random_forest")

    test_cases = [
        {"name": "SYN Flood", "features": {"syn_ratio": 1.0, "packet_rate": 1000.0, "ack_ratio": 0.0}},
        {"name": "Port Scan", "features": {"unique_dst_ports": 100.0, "dst_port_fanout": 100.0, "syn_ratio": 1.0}},
        {"name": "DNS DGA", "features": {"dns_entropy_mean": 3.8, "dns_txt_record_ratio": 1.0, "dns_ngram_score": -9.2}},
        {"name": "C2 Beacon", "features": {"iat_cv": 0.019, "iat_mean": 1.0, "fft_peak_magnitude": 0.285}},
        {"name": "Benign", "features": {"syn_ratio": 0.3, "ack_ratio": 0.5, "pkt_size_mean": 512.0}},
    ]

    print("\n=== INFERENCE SMOKE TEST ===")
    for tc in test_cases:
        fv = FeatureVector_v1(
            flow_id=f"test_{tc['name']}",
            timestamp=1724832000.0,
            **tc["features"]
        )
        result = engine.predict(fv)
        print(f"\n[{tc['name']}]")
        print(f"  Prediction:     {result.prediction}")
        print(f"  Confidence:     {result.confidence:.4f}")
        print(f"  Method:         {result.detection_method}")
        print(f"  Model Version:  {result.model_version}")
        print(f"  Latency:        {result.inference_latency_ms:.3f} ms")
        if result.warnings:
            print(f"  Warnings:       {result.warnings}")
        print(f"  Top Probs:      {result.top_class_probabilities}")
