"""
Model Fusion & Behavioral Detection Layer.

Combines:
  1. Supervised Random Forest Classifier (Classes + Probabilities)
  2. Unsupervised Isolation Forest Anomaly Detector (Decision function score)
  3. Deterministic Behavioral Detectors (6 Threat Categories with Explainable Evidence)

Fusion Logic:
─────────────────────────────────────────────────────────────────────────────
Decision States:
  A: KNOWN_THREAT_CONFIRMED   — High RF confidence (>=0.75) + IF Anomaly flag / Reinforced by Behavioral Detector
  B: KNOWN_THREAT_PROBABLE    — High RF confidence OR Strong Behavioral Detector trigger
  C: UNKNOWN_ANOMALY          — Anomaly detected without confident known classification
  D: BENIGN_NORMAL_TRAFFIC    — Normal traffic with low anomaly score and no detector triggers
─────────────────────────────────────────────────────────────────────────────
"""
import math
import logging
from pathlib import Path
import numpy as np
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from app.config import MODELS_DIR
from app.detectors.models import BehavioralDetectionResult, BehavioralDetectorsConfig
from app.detectors.behavioral_engine import BehavioralDetectionEngine

logger = logging.getLogger(__name__)

RF_CONFIDENCE_THRESHOLD = 0.75

class FusionResult(BaseModel):
    flow_id: str
    timestamp: float
    # Primary decision
    decision_state: str       # A/B/C/D with label
    threat_label: str         # Final threat class
    confidence: float         # [0.0, 1.0]
    
    # Model Outputs
    rf_prediction: str
    rf_confidence: float
    rf_class_probabilities: Dict[str, float]
    
    if_anomaly_score: float   # Raw decision_function value (NOT a probability)
    if_is_anomalous: bool
    if_threshold: float
    
    # Deterministic Behavioral Detectors
    behavioral_results: List[BehavioralDetectionResult] = Field(default_factory=list)
    behavioral_triggered_count: int = 0
    primary_behavioral_reason: Optional[str] = None
    
    # Metadata & Explainability
    detection_method: str     # "HYBRID" | "MODEL_SUPERVISED" | "MODEL_ANOMALY" | "BEHAVIORAL_RULE"
    inference_latency_ms: float
    warnings: List[str] = Field(default_factory=list)

class ThreatFusionEngine:
    def __init__(
        self,
        rf_artifact: dict,
        if_artifact: dict,
        behavioral_config: Optional[BehavioralDetectorsConfig] = None
    ):
        self.rf_model = rf_artifact["model"]
        self.rf_scaler = rf_artifact["scaler"]
        self.rf_classes = list(self.rf_model.classes_)
        self.rf_version = rf_artifact.get("model_version", "v2.0")

        self.if_model = if_artifact["model"]
        self.if_scaler = if_artifact["scaler"]
        self.if_threshold = if_artifact["threshold"]
        self.if_version = if_artifact.get("model_version", "v2.0")

        # Ensure single-sample in-process inference (avoids multiprocessing IPC overhead per row)
        self.rf_model.n_jobs = 1
        self.if_model.n_jobs = 1

        self.feature_names = rf_artifact["feature_names"]
        self.behavioral_engine = BehavioralDetectionEngine(behavioral_config)

        # ── Fast ONNX Runtime Integration ─────────────────────────────────────
        # Initialize ONNX inference session once at startup if weights exist
        self.onnx_session = None
        self.onnx_input_name = None
        onnx_file = MODELS_DIR / "random_forest_v2.0.onnx"
        if onnx_file.exists():
            try:
                import onnxruntime as ort
                sess_opts = ort.SessionOptions()
                sess_opts.intra_op_num_threads = 1
                sess_opts.inter_op_num_threads = 1
                sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self.onnx_session = ort.InferenceSession(str(onnx_file), sess_opts, providers=["CPUExecutionProvider"])
                self.onnx_input_name = self.onnx_session.get_inputs()[0].name
                logger.info(f"[ThreatFusionEngine] Loaded production ONNX model: {onnx_file}")
            except Exception as e:
                logger.warning(f"[ThreatFusionEngine] Failed to load ONNX runtime ({e}); using Scikit-Learn fallback.")

    def predict(self, feature_vector, features_dict: Optional[dict] = None) -> FusionResult:
        import time
        t0 = time.perf_counter()
        warnings = []

        fid = getattr(feature_vector, "flow_id", "unknown")
        ts = getattr(feature_vector, "timestamp", 0.0)

        if features_dict is None:
            features_dict = feature_vector.to_dict() if hasattr(feature_vector, "to_dict") else {}

        # ── 1. Random Forest Inference (ONNX accelerated with Sklearn fallback) ─
        X_raw = np.array([features_dict.get(f, 0.0) for f in self.feature_names], dtype=np.float64).reshape(1, -1)
        X_rf = self.rf_scaler.transform(X_raw)

        if self.onnx_session is not None:
            outputs = self.onnx_session.run(None, {self.onnx_input_name: X_rf.astype(np.float32)})
            rf_pred = str(outputs[0][0])
            prob_vec = outputs[1][0]
            max_idx = int(np.argmax(prob_vec))
            rf_conf = float(prob_vec[max_idx])
            rf_proba_dict = {cls: round(float(p), 4) for cls, p in zip(self.rf_classes, prob_vec)}
        else:
            rf_proba = self.rf_model.predict_proba(X_rf)[0]
            max_idx = int(np.argmax(rf_proba))
            rf_pred = str(self.rf_classes[max_idx])
            rf_conf = float(rf_proba[max_idx])
            rf_proba_dict = {cls: round(float(p), 4) for cls, p in zip(self.rf_classes, rf_proba)}

        # ── 2. Deterministic Behavioral Detectors ─────────────────────────────
        det_results = self.behavioral_engine.evaluate_all(feature_vector)
        triggered_dets = [d for d in det_results if d.triggered]
        primary_reason = triggered_dets[0].human_readable_reason if triggered_dets else None

        # ── 3. Selective Isolation Forest Escalation ──────────────────────────
        # Bypass expensive IF on high-confidence supervised decisions or verified normal flows
        can_bypass_if = (
            (rf_pred != "BENIGN" and rf_conf >= RF_CONFIDENCE_THRESHOLD) or
            (rf_pred == "BENIGN" and rf_conf >= 0.85 and len(triggered_dets) == 0)
        )
        if can_bypass_if:
            if_score = 0.0
            if_anomalous = False
        else:
            X_if = self.if_scaler.transform(X_raw)
            if_score = float(self.if_model.decision_function(X_if)[0])
            if_anomalous = bool(if_score < self.if_threshold)

        # Category mappings from behavioral triggers
        behavioral_threat_map = {
            "DDoS": "DDOS",
            "Port Scanning": "PORT_SCAN",
            "DNS / DGA": "DGA_DNS_TUNNELLING",
            "C2 Beaconing": "C2_BEACONING",
            "Data Exfiltration": "DATA_EXFILTRATION",
            "Encrypted Malware": "ENCRYPTED_MALWARE"
        }

        # ── 4. Unified Fusion Decision Matrix ─────────────────────────────────
        # Sort triggered detectors by specific threat severity so specific anomalies
        # (exfil, c2, dga, port scan) take precedence over generic volumetric DDoS
        priority_order = {
            "DATA_EXFILTRATION": 1,
            "C2_BEACONING": 2,
            "DGA_DNS_TUNNELLING": 3,
            "PORT_SCAN": 4,
            "ENCRYPTED_MALWARE": 5,
            "DDOS": 6
        }
        sorted_triggered = sorted(
            triggered_dets,
            key=lambda d: priority_order.get(behavioral_threat_map.get(d.category, d.category), 99)
        )

        behavioral_override_cat = None
        behavioral_override_score = 0.0
        for td in sorted_triggered:
            mapped_cat = behavioral_threat_map.get(td.category, td.category)
            # If supervised model is not confident, or predicts benign, let strong behavioral rule take precedence
            if rf_conf < RF_CONFIDENCE_THRESHOLD or rf_pred == "BENIGN" or mapped_cat == rf_pred:
                behavioral_override_cat = mapped_cat
                behavioral_override_score = td.score
                warnings.append(f"{td.category} detected via deterministic behavioral rule: {td.human_readable_reason}")
                break

        if behavioral_override_cat:
            threat_label = behavioral_override_cat
            decision_state = "B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)"
            confidence = max(0.85, behavioral_override_score)
            detection_method = "BEHAVIORAL_RULE"

        elif rf_pred != "BENIGN" and rf_conf >= RF_CONFIDENCE_THRESHOLD:
            threat_label = rf_pred
            matching_behavioral = any(behavioral_threat_map.get(d.category) == rf_pred for d in triggered_dets)
            if if_anomalous or matching_behavioral:
                decision_state = "A: KNOWN_THREAT_CONFIRMED"
                confidence = min(1.0, max(rf_conf, 0.92))
                detection_method = "HYBRID"
            else:
                decision_state = "B: KNOWN_THREAT_PROBABLE"
                confidence = rf_conf
                detection_method = "MODEL_SUPERVISED"

        elif if_anomalous or len(triggered_dets) > 0:
            threat_label = "UNKNOWN_ANOMALY"
            decision_state = "C: UNKNOWN_ANOMALY"
            raw_sep = abs(if_score - self.if_threshold)
            confidence = round(min(1.0, 0.60 + raw_sep / 0.5), 4)
            detection_method = "MODEL_ANOMALY"
            warnings.append("Anomalous behavioral profile detected without confident known category match.")

        else:
            threat_label = "BENIGN"
            decision_state = "D: BENIGN_NORMAL_TRAFFIC"
            confidence = round(rf_conf if rf_pred == "BENIGN" else (1.0 - rf_conf), 4)
            detection_method = "MODEL_SUPERVISED"

        latency_ms = round((time.perf_counter() - t0) * 1000, 4)

        return FusionResult(
            flow_id=fid,
            timestamp=ts,
            decision_state=decision_state,
            threat_label=threat_label,
            confidence=round(confidence, 4),
            rf_prediction=rf_pred,
            rf_confidence=round(rf_conf, 4),
            rf_class_probabilities=rf_proba_dict,
            if_anomaly_score=round(if_score, 6),
            if_is_anomalous=if_anomalous,
            if_threshold=round(self.if_threshold, 6),
            behavioral_results=det_results,
            behavioral_triggered_count=len(triggered_dets),
            primary_behavioral_reason=primary_reason,
            detection_method=detection_method,
            inference_latency_ms=latency_ms,
            warnings=warnings
        )
