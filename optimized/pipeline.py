"""
High-Performance Streaming Pipeline Orchestrator.

Integrates:
- Fast behavioral gate (Stage 1 screening)
- Incremental Welford flow tracking
- Tiered selective feature extraction
- Dual-backend selective inference engine
- Streamlined decision fusion
- 30s sliding alert deduplication
"""
import time
import asyncio
import logging
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable, Tuple

from app.telemetry.schema import NormalizedBaseEvent
from app.alerts.engine import AlertEngine, EvidenceGenerator
from app.alerts.models import SecurityAlert_v2, AlertSeverity
from app.ml.fusion import FusionResult

from optimized.gate import FastBehavioralGate, GateDecision
from optimized.flow_tracker import OptimizedTelemetryTracker
from optimized.feature_pipeline import OptimizedFeatureExtractor
from optimized.inference_engine import OptimizedInferenceEngine, InferenceBackend
from optimized.fusion import OptimizedFusionEngine, OptimizedFusionResult

logger = logging.getLogger("optimized_pipeline")


class OptimizedPipelineOrchestrator:
    def __init__(
        self,
        backend: InferenceBackend = InferenceBackend.SKLEARN,
        dedup_window_sec: float = 30.0,
        broadcast_callback: Optional[Callable] = None
    ):
        self.tracker = OptimizedTelemetryTracker()
        self.gate = FastBehavioralGate()
        self.feature_extractor = OptimizedFeatureExtractor()
        self.inference_engine = OptimizedInferenceEngine(backend=backend)
        self.fusion_engine = OptimizedFusionEngine()
        self.alert_engine = AlertEngine(dedup_window_sec=dedup_window_sec)
        self.broadcast_callback = broadcast_callback

        # Reusable contiguous NumPy buffer (54 dimensions)
        self._feat_buf = np.zeros(54, dtype=np.float64)

        # Performance counters & timers
        self.processed_events: int = 0
        self.e2e_latencies_ms: List[float] = []
        self.gate_latencies_ms: List[float] = []
        self.feat_latencies_ms: List[float] = []
        self.ml_latencies_ms: List[float] = []
        self.alert_latencies_ms: List[float] = []

    def process_event(self, event: NormalizedBaseEvent) -> Tuple[Optional[SecurityAlert_v2], bool]:
        """
        Process a single normalized telemetry event synchronously at microsecond speed.
        Returns (alert, is_new_alert).
        """
        t_start = time.perf_counter_ns()
        self.processed_events += 1

        # 1. Incremental flow state update
        state = self.tracker.process_event(event)

        # 2. Fast Behavioral Screening Gate (Stage 1)
        t_g0 = time.perf_counter_ns()
        gate_res = self.gate.screen_flow(state, self.tracker.graph_tracker)
        t_g1 = time.perf_counter_ns()
        self.gate_latencies_ms.append((t_g1 - t_g0) / 1_000_000.0)

        # 3. Selective Feature Vector Extraction
        t_f0 = time.perf_counter_ns()
        needs_tier3 = (gate_res.decision != GateDecision.PASS_NORMAL)
        vector_54 = self.feature_extractor.extract_vector(
            state,
            self.tracker.graph_tracker,
            out_buf=self._feat_buf,
            compute_tier3=needs_tier3
        )
        t_f1 = time.perf_counter_ns()
        self.feat_latencies_ms.append((t_f1 - t_f0) / 1_000_000.0)

        # 4. Selective ML Inference (Random Forest + Conditional Isolation Forest)
        t_m0 = time.perf_counter_ns()
        rf_pred, rf_conf, rf_proba, if_score, if_anom, esc_if = self.inference_engine.predict_selective(
            state,
            vector_54,
            gate_res,
            current_ts=event.timestamp
        )
        t_m1 = time.perf_counter_ns()
        self.ml_latencies_ms.append((t_m1 - t_m0) / 1_000_000.0)

        # 5. Streamlined Decision Fusion
        t_a0 = time.perf_counter_ns()
        # Only instantiate Pydantic vector if threat or suspicious
        vector_pydantic = None
        if gate_res.decision != GateDecision.PASS_NORMAL or rf_pred != "BENIGN" or if_anom:
            vector_pydantic = self.feature_extractor.to_pydantic_vector(state, vector_54)

        opt_fusion = self.fusion_engine.resolve(
            flow_id=state.flow_id,
            timestamp=event.timestamp,
            vector_pydantic=vector_pydantic,
            gate_res=gate_res,
            rf_pred=rf_pred,
            rf_conf=rf_conf,
            rf_proba_dict=rf_proba,
            if_score=if_score,
            if_anomalous=if_anom,
            escalated_to_if=esc_if
        )

        # 6. Alert Registration & Deduplication
        alert = None
        is_new = False
        if opt_fusion.is_threat:
            # Build baseline-compatible FusionResult for AlertEngine
            compat_fusion = FusionResult(
                flow_id=state.flow_id,
                timestamp=event.timestamp,
                decision_state=opt_fusion.decision_state,
                threat_label=opt_fusion.threat_label,
                confidence=opt_fusion.confidence,
                rf_prediction=opt_fusion.rf_prediction,
                rf_confidence=opt_fusion.rf_confidence,
                rf_class_probabilities=opt_fusion.rf_probabilities,
                if_anomaly_score=opt_fusion.if_anomaly_score,
                if_is_anomalous=opt_fusion.if_is_anomalous,
                if_threshold=self.inference_engine.if_threshold,
                detection_method=opt_fusion.detection_method,
                inference_latency_ms=0.0
            )
            if vector_pydantic is None:
                vector_pydantic = self.feature_extractor.to_pydantic_vector(state, vector_54)

            alert, is_new = self.alert_engine.process_detection(vector_pydantic, compat_fusion)

            if is_new and self.broadcast_callback:
                try:
                    if asyncio.iscoroutinefunction(self.broadcast_callback):
                        asyncio.create_task(self.broadcast_callback(alert))
                    else:
                        self.broadcast_callback(alert)
                except Exception:
                    pass

        t_a1 = time.perf_counter_ns()
        self.alert_latencies_ms.append((t_a1 - t_a0) / 1_000_000.0)

        t_end = time.perf_counter_ns()
        self.e2e_latencies_ms.append((t_end - t_start) / 1_000_000.0)

        return alert, is_new

    def get_metrics_summary(self) -> Dict[str, Any]:
        def p_calc(arr):
            if not arr:
                return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
            np_a = np.array(arr)
            return {
                "p50": round(float(np.percentile(np_a, 50)), 4),
                "p95": round(float(np.percentile(np_a, 95)), 4),
                "p99": round(float(np.percentile(np_a, 99)), 4),
                "mean": round(float(np.mean(np_a)), 4)
            }

        return {
            "processed_events": self.processed_events,
            "active_flows": len(self.tracker.active_flows),
            "alerts_created": len(self.alert_engine._alerts),
            "rf_evals": self.inference_engine.rf_eval_count,
            "if_evals": self.inference_engine.if_eval_count,
            "rf_bypassed": self.inference_engine.rf_bypass_count,
            "if_bypassed": self.inference_engine.if_bypass_count,
            "e2e_latency_ms": p_calc(self.e2e_latencies_ms),
            "gate_latency_ms": p_calc(self.gate_latencies_ms),
            "feat_latency_ms": p_calc(self.feat_latencies_ms),
            "ml_latency_ms": p_calc(self.ml_latencies_ms),
            "alert_latency_ms": p_calc(self.alert_latencies_ms)
        }
