"""
Optimized Dual-Backend Inference Engine.

Key Architectural Innovations:
1. Inlined Linear Scaling: Replaces scikit-learn single-row transform overhead with (X - mean) * scale_inv.
2. Dual Backend: Supports both Scikit-Learn and ONNX Runtime backends seamlessly.
3. Selective Random Forest: Runs RF only when triggered by gate, risk shifts, or micro-window timer.
4. Selective Isolation Forest Escalation: Runs IF only when RF confidence is ambiguous or potential anomaly.
5. Adaptive Risk Scheduling: Tunes flow inference frequency (LOW: 1.0s, MEDIUM: 0.25s, HIGH: immediate).
"""
import time
import joblib
import logging
import numpy as np
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from app.config import MODELS_DIR
from optimized.gate import GateDecision, GateResult
from optimized.flow_tracker import OptimizedFlowState

logger = logging.getLogger("optimized_inference")


class InferenceBackend(str, Enum):
    SKLEARN = "SKLEARN"
    ONNX = "ONNX"


def _load_latest_artifact(prefix: str) -> dict:
    candidates = sorted(MODELS_DIR.glob(f"{prefix}_*.joblib"), reverse=True)
    if not candidates:
        raise FileNotFoundError(f"No saved model with prefix '{prefix}' in {MODELS_DIR}")
    return joblib.load(candidates[0])


class OptimizedInferenceEngine:
    """
    High-throughput ML inference manager.
    """
    def __init__(
        self,
        backend: InferenceBackend = InferenceBackend.SKLEARN,
        rf_confidence_threshold: float = 0.80,
        low_risk_interval_sec: float = 1.0,
        med_risk_interval_sec: float = 0.25,
        micro_window_pkts: int = 30
    ):
        self.backend_type = backend
        self.rf_confidence_threshold = rf_confidence_threshold
        self.low_risk_interval_sec = low_risk_interval_sec
        self.med_risk_interval_sec = med_risk_interval_sec
        self.micro_window_pkts = micro_window_pkts

        # Load baseline weights
        self.rf_artifact = _load_latest_artifact("random_forest")
        self.if_artifact = _load_latest_artifact("isolation_forest")

        self.rf_model = self.rf_artifact["model"]
        self.rf_classes = list(self.rf_model.classes_)
        self.feature_names = self.rf_artifact["feature_names"]

        self.if_model = self.if_artifact["model"]
        self.if_threshold = float(self.if_artifact["threshold"])

        # Optimize thread pools for single-row inference
        self.rf_model.n_jobs = 1
        self.if_model.n_jobs = 1

        # Pre-extract scaler vectors for inlined linear scaling
        rf_scaler = self.rf_artifact["scaler"]
        self.rf_mean = np.array(rf_scaler.mean_, dtype=np.float64)
        self.rf_scale_inv = np.array(1.0 / np.maximum(1e-7, rf_scaler.scale_), dtype=np.float64)

        if_scaler = self.if_artifact["scaler"]
        self.if_mean = np.array(if_scaler.mean_, dtype=np.float64)
        self.if_scale_inv = np.array(1.0 / np.maximum(1e-7, if_scaler.scale_), dtype=np.float64)

        # ONNX Runtime Session (Lazy initialized or fallback to Sklearn)
        self.onnx_session = None
        if backend == InferenceBackend.ONNX:
            self._init_onnx_session()

        # Invocation telemetry counters
        self.rf_eval_count: int = 0
        self.if_eval_count: int = 0
        self.rf_bypass_count: int = 0
        self.if_bypass_count: int = 0

    def _init_onnx_session(self):
        onnx_file = MODELS_DIR / "random_forest_v2.0.onnx"
        if not onnx_file.exists():
            logger.warning(f"ONNX model file not found at {onnx_file}. Falling back to SKLEARN.")
            self.backend_type = InferenceBackend.SKLEARN
            return
        try:
            import onnxruntime as ort
            sess_options = ort.SessionOptions()
            sess_options.intra_op_num_threads = 1
            sess_options.inter_op_num_threads = 1
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self.onnx_session = ort.InferenceSession(str(onnx_file), sess_options)
            self.onnx_input_name = self.onnx_session.get_inputs()[0].name
            logger.info("ONNX Runtime session initialized successfully.")
        except Exception as e:
            logger.warning(f"Failed to initialize ONNX session: {e}. Falling back to SKLEARN.")
            self.backend_type = InferenceBackend.SKLEARN

    def inlined_scale_rf(self, X_raw: np.ndarray) -> np.ndarray:
        """Single-pass O(D) inlined scaling without scikit-learn validation overhead."""
        return (X_raw - self.rf_mean) * self.rf_scale_inv

    def inlined_scale_if(self, X_raw: np.ndarray) -> np.ndarray:
        """Single-pass O(D) inlined scaling without scikit-learn validation overhead."""
        return (X_raw - self.if_mean) * self.if_scale_inv

    def should_trigger_inference(self, state: OptimizedFlowState, gate_res: GateResult, current_ts: float) -> bool:
        """
        Determines if ML inference should run on this packet using adaptive micro-windows.
        """
        # Critical attack or suspicious gate trigger -> immediate ML evaluation
        if gate_res.decision in (GateDecision.CRITICAL_RULE, GateDecision.SUSPICIOUS):
            return True

        # First packet of flow -> evaluate once
        if state.last_inference_ts == 0.0:
            return True

        # Micro-window packet count threshold
        pkts_since = (state.orig_pkts + state.resp_pkts) - state.last_inference_pkts
        if pkts_since >= self.micro_window_pkts:
            return True

        # Adaptive time-based threshold based on current flow risk level
        time_since = current_ts - state.last_inference_ts
        if state.risk_level == "HIGH":
            interval = 0.05
        elif state.risk_level == "MEDIUM":
            interval = self.med_risk_interval_sec
        else:
            interval = self.low_risk_interval_sec

        return time_since >= interval

    def predict_selective(
        self,
        state: OptimizedFlowState,
        vector_54: np.ndarray,
        gate_res: GateResult,
        current_ts: float,
        force_infer: bool = False
    ) -> Tuple[str, float, Dict[str, float], float, bool, bool]:
        """
        Executes selective ML inference:
        Returns:
            (rf_pred, rf_conf, rf_probabilities, if_score, if_anomalous, escalated_to_if)
        """
        needs_infer = force_infer or self.should_trigger_inference(state, gate_res, current_ts)

        if not needs_infer:
            self.rf_bypass_count += 1
            self.if_bypass_count += 1
            # Return safe default or cached benign
            return "BENIGN", 0.95, {"BENIGN": 0.95}, 0.0, False, False

        # ── 1. RANDOM FOREST INFERENCE ────────────────────────────────────────
        t0 = time.perf_counter_ns()
        X_rf = self.inlined_scale_rf(vector_54).reshape(1, -1)
        self.rf_eval_count += 1

        if self.backend_type == InferenceBackend.ONNX and self.onnx_session is not None:
            # ONNX Runtime inference (C++ vectorized decision trees)
            inputs = {self.onnx_input_name: X_rf.astype(np.float32)}
            outputs = self.onnx_session.run(None, inputs)
            rf_pred = str(outputs[0][0])
            prob_vec = outputs[1][0]  # shape (num_classes,) float32
            rf_proba_dict = {cls: round(float(p), 4) for cls, p in zip(self.rf_classes, prob_vec)}
            max_idx = int(np.argmax(prob_vec))
            rf_conf = float(prob_vec[max_idx])
        else:
            # Scikit-learn inference
            rf_proba = self.rf_model.predict_proba(X_rf)[0]
            max_idx = int(np.argmax(rf_proba))
            rf_pred = str(self.rf_classes[max_idx])
            rf_conf = float(rf_proba[max_idx])
            rf_proba_dict = {cls: round(float(p), 4) for cls, p in zip(self.rf_classes, rf_proba)}

        # Update flow state inference markers
        state.last_inference_ts = current_ts
        state.last_inference_pkts = state.orig_pkts + state.resp_pkts

        # ── 2. SELECTIVE ISOLATION FOREST ESCALATION ──────────────────────────
        # Bypass IF if RF is highly confident in known threat or normal traffic
        can_bypass_if = (
            (rf_pred != "BENIGN" and rf_conf >= self.rf_confidence_threshold) or
            (rf_pred == "BENIGN" and rf_conf >= 0.85 and gate_res.decision == GateDecision.PASS_NORMAL)
        )

        if can_bypass_if and not force_infer:
            self.if_bypass_count += 1
            if_score = 0.0
            if_anomalous = False
            escalated_to_if = False
        else:
            # Escalate to Isolation Forest
            self.if_eval_count += 1
            X_if = self.inlined_scale_if(vector_54).reshape(1, -1)
            if_score = float(self.if_model.decision_function(X_if)[0])
            if_anomalous = bool(if_score < self.if_threshold)
            escalated_to_if = True

        # Update risk level on state
        if rf_pred != "BENIGN" or if_anomalous or gate_res.decision == GateDecision.CRITICAL_RULE:
            state.risk_level = "HIGH"
        elif gate_res.decision == GateDecision.SUSPICIOUS or rf_conf < 0.70:
            state.risk_level = "MEDIUM"
        else:
            state.risk_level = "LOW"

        return rf_pred, rf_conf, rf_proba_dict, if_score, if_anomalous, escalated_to_if
