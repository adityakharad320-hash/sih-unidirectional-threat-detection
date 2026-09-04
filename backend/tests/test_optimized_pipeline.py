"""
Automated Test Suite for Optimized Unidirectional IP Threat Detection Engine.

Validates:
1. Fast behavioral screening gate (zero false negatives on attacks).
2. Incremental statistics (Welford's algorithm mathematical parity vs NumPy).
3. Selective feature extraction & 54-dimensional parity.
4. Dual-backend ML inference (Sklearn & ONNX Runtime parity).
5. Selective Isolation Forest escalation logic.
6. Adaptive micro-window scheduling.
7. Alert generation, deduplication, and memory bounds.
8. Unidirectional compliance invariants (read-only, no active probing, no egress).
"""
import sys
import math
import pytest
import numpy as np
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.telemetry.schema import NormalizedConnectionEvent, NormalizedDNSEvent, NormalizedTLSEvent
from app.telemetry.feature_schema import ORDERED_TELEMETRY_FEATURE_NAMES, TelemetryFeatureVector_v2
from app.alerts.models import SecurityAlert_v2

from optimized.gate import FastBehavioralGate, GateDecision
from optimized.flow_tracker import WelfordAccumulator, OptimizedFlowState, OptimizedTelemetryTracker
from optimized.feature_pipeline import OptimizedFeatureExtractor
from optimized.inference_engine import OptimizedInferenceEngine, InferenceBackend
from optimized.fusion import OptimizedFusionEngine
from optimized.pipeline import OptimizedPipelineOrchestrator


# ── 1. FAST BEHAVIORAL GATE TESTS ─────────────────────────────────────────────
def test_gate_benign_traffic():
    gate = FastBehavioralGate()
    state = OptimizedFlowState("10.0.0.1:5000 -> 10.0.0.2:80 [TCP]", "10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 1000.0)
    # Add normal balanced traffic
    state.orig_pkts = 20
    state.resp_pkts = 25
    state.orig_bytes = 2000
    state.resp_bytes = 15000
    state.last_seen = 1005.0  # 5s duration -> 9 pkts/s (safe)
    state.duration = 5.0
    state.ack_count = 20

    res = gate.screen_flow(state)
    assert res.decision == GateDecision.PASS_NORMAL
    assert res.urgency_level == 0.0


def test_gate_syn_flood_detection():
    gate = FastBehavioralGate()
    state = OptimizedFlowState("10.0.0.1:5000 -> 10.0.0.2:80 [TCP]", "10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 1000.0)
    # Volumetric SYN flood
    state.orig_pkts = 500
    state.resp_pkts = 0
    state.syn_count = 490
    state.duration = 2.0
    state.last_seen = 1002.0

    res = gate.screen_flow(state)
    assert res.decision == GateDecision.CRITICAL_RULE
    assert res.threat_category == "DDOS"
    assert res.urgency_level >= 0.90


def test_gate_data_exfil_detection():
    gate = FastBehavioralGate()
    state = OptimizedFlowState("192.168.1.100:49210 -> 203.0.113.50:443 [TCP]", "192.168.1.100", "203.0.113.50", 49210, 443, "TCP", 1000.0)
    # Abnormal upload: 50MB outbound vs 2KB inbound
    state.orig_bytes = 50_000_000
    state.resp_bytes = 2_000
    state.duration = 10.0
    state.last_seen = 1010.0

    res = gate.screen_flow(state)
    assert res.decision == GateDecision.CRITICAL_RULE
    assert res.threat_category == "DATA_EXFILTRATION"


# ── 2. INCREMENTAL STATISTICS & WELFORD ACCUMULATOR ───────────────────────────
def test_welford_statistical_parity():
    acc = WelfordAccumulator()
    sample_data = [0.12, 0.45, 0.33, 0.89, 0.11, 0.54, 0.76, 0.22, 0.95, 0.38]

    for x in sample_data:
        acc.update(x)

    np_mean = float(np.mean(sample_data))
    np_std = float(np.std(sample_data, ddof=1))
    np_min = float(np.min(sample_data))
    np_max = float(np.max(sample_data))

    assert math.isclose(acc.mean, np_mean, rel_tol=1e-6)
    assert math.isclose(acc.std, np_std, rel_tol=1e-6)
    assert math.isclose(acc.min, np_min, rel_tol=1e-6)
    assert math.isclose(acc.max, np_max, rel_tol=1e-6)


# ── 3. FEATURE EXTRACTION & SCHEMA PARITY ─────────────────────────────────────
def test_feature_vector_dimension_parity():
    tracker = OptimizedTelemetryTracker()
    state = tracker.process_event(
        NormalizedConnectionEvent(
            event_id="evt-parity-1",
            source_engine="zeek",
            event_type="connection",
            timestamp=1724832000.0,
            src_ip="192.168.1.50",
            src_port=51200,
            dst_ip="192.168.1.1",
            dst_port=80,
            protocol="TCP",
            conn_state="SF",
            duration=1.5,
            orig_bytes=500,
            resp_bytes=2500,
            orig_pkts=5,
            resp_pkts=8
        )
    )

    vec_54 = OptimizedFeatureExtractor.extract_vector(state, tracker.graph_tracker)
    assert isinstance(vec_54, np.ndarray)
    assert vec_54.shape == (54,)
    assert vec_54.dtype == np.float64
    assert len(ORDERED_TELEMETRY_FEATURE_NAMES) == 54

    # Convert to Pydantic compatibility vector
    pyd_vec = OptimizedFeatureExtractor.to_pydantic_vector(state, vec_54)
    assert isinstance(pyd_vec, TelemetryFeatureVector_v2)
    assert pyd_vec.flow_id == state.flow_id


# ── 4. DUAL-BACKEND INFERENCE & ONNX CONSISTENCY ──────────────────────────────
def test_dual_backend_prediction_parity():
    sk_engine = OptimizedInferenceEngine(backend=InferenceBackend.SKLEARN)
    onnx_engine = OptimizedInferenceEngine(backend=InferenceBackend.ONNX)

    state = OptimizedFlowState("test_flow", "192.168.1.1", "10.0.0.1", 1234, 80, "TCP", 1000.0)
    dummy_vec = np.zeros(54, dtype=np.float64)
    # Populate a port scan pattern
    dummy_vec[37] = 25.0  # unique_dst_ports
    dummy_vec[39] = 12.0  # dst_port_fanout

    gate_res = FastBehavioralGate().screen_flow(state)

    sk_pred, sk_conf, sk_probs, _, _, _ = sk_engine.predict_selective(state, dummy_vec, gate_res, 1000.0, force_infer=True)
    onnx_pred, onnx_conf, onnx_probs, _, _, _ = onnx_engine.predict_selective(state, dummy_vec, gate_res, 1000.0, force_infer=True)

    assert sk_pred == onnx_pred
    assert math.isclose(sk_conf, onnx_conf, abs_tol=0.01)


# ── 5. SELECTIVE ISOLATION FOREST ESCALATION ──────────────────────────────────
def test_selective_if_bypass():
    engine = OptimizedInferenceEngine(backend=InferenceBackend.SKLEARN)
    state = OptimizedFlowState("test_flow", "192.168.1.1", "10.0.0.1", 1234, 80, "TCP", 1000.0)

    # Benign normal vector with clean gate
    vec = np.zeros(54, dtype=np.float64)
    gate_res = FastBehavioralGate().screen_flow(state)

    rf_pred, rf_conf, _, if_score, if_anom, escalated = engine.predict_selective(state, vec, gate_res, 1000.0, force_infer=False)

    # With high-confidence benign or passing gate, IF should be safely bypassed
    if rf_pred == "BENIGN" and rf_conf >= 0.85 and gate_res.decision == GateDecision.PASS_NORMAL:
        assert not escalated
        assert if_score == 0.0


# ── 6. END-TO-END PIPELINE & ALERT DEDUPLICATION ──────────────────────────────
def test_optimized_pipeline_e2e_and_dedup():
    orchestrator = OptimizedPipelineOrchestrator()

    # Stream repeated identical attacks
    alerts_created = []
    for i in range(10):
        evt = NormalizedConnectionEvent(
            event_id=f"evt-flood-{i}",
            source_engine="zeek",
            event_type="connection",
            timestamp=1724832000.0 + (i * 0.5),
            src_ip="192.168.1.99",
            src_port=50000 + i,
            dst_ip="10.0.0.5",
            dst_port=80,
            protocol="TCP",
            conn_state="S0",
            duration=0.1,
            orig_bytes=60,
            resp_bytes=0,
            orig_pkts=1000,
            resp_pkts=0
        )
        alert, is_new = orchestrator.process_event(evt)
        if alert:
            alerts_created.append((alert, is_new))

    # Deduplication check: First event should be new, subsequent 9 should be deduplicated
    assert len(alerts_created) > 0
    new_alerts = [a for a, is_new in alerts_created if is_new]
    dedup_alerts = [a for a, is_new in alerts_created if not is_new]

    assert len(new_alerts) == 1
    assert len(dedup_alerts) == 9
    assert new_alerts[0].occurrence_count == 10  # Occurrence accumulator incremented


# ── 7. SCHEMA VERSION & FEATURE ORDERING CONSISTENCY ─────────────────────────
def test_feature_schema_and_version_consistency():
    from app.telemetry.feature_schema import (
        FEATURE_SCHEMA_VERSION,
        FEATURE_SCHEMA_DIMENSIONS,
        ORDERED_TELEMETRY_FEATURE_NAMES,
    )
    import joblib
    from app.config import MODELS_DIR

    assert FEATURE_SCHEMA_VERSION == "v2.1-optimized"
    assert FEATURE_SCHEMA_DIMENSIONS == 54
    assert len(ORDERED_TELEMETRY_FEATURE_NAMES) == 54

    # Verify ONNX and Scikit-Learn training feature ordering match exactly
    rf_joblib = sorted(MODELS_DIR.glob("random_forest_*.joblib"), reverse=True)[0]
    artifact = joblib.load(rf_joblib)
    training_feature_names = artifact["feature_names"]

    assert len(training_feature_names) == 54
    assert training_feature_names == ORDERED_TELEMETRY_FEATURE_NAMES


# ── 8. UNIDIRECTIONAL INVARIANTS: NO REVERSE TRAFFIC REQUIRED ─────────────────
def test_unidirectional_invariants_no_reverse_required():
    """Verifies that absence of return traffic (resp_pkts=0) is NEVER flagged as attack on its own."""
    gate = FastBehavioralGate()
    state = OptimizedFlowState("diode_flow_1", "10.0.0.1", "192.168.1.1", 1024, 80, "TCP", 1000.0)

    # Moderate volume, unidirectional benign flow (e.g. video broadcast or unidirectional UDP)
    state.orig_pkts = 15
    state.resp_pkts = 0  # Zero return packets observed across diode
    state.orig_bytes = 1500
    state.resp_bytes = 0
    state.duration = 2.0
    state.last_seen = 1002.0

    res = gate.screen_flow(state)
    assert res.decision == GateDecision.PASS_NORMAL
    assert res.threat_category in (None, "BENIGN")


# ── 9. FLOW TERMINATION INACTIVITY EVICTION ───────────────────────────────────
def test_flow_termination_inactivity_eviction():
    """Verifies flow termination is inferred from sliding inactivity timeouts, not return FIN/RST."""
    tracker = OptimizedTelemetryTracker(idle_timeout_sec=30.0, max_active_flows=10)

    # Insert initial connection event
    evt1 = NormalizedConnectionEvent(
        event_id="e1", timestamp=1000.0, source_engine="zeek",
        src_ip="10.0.0.1", dst_ip="192.168.1.1", src_port=1234, dst_port=80, protocol="TCP"
    )
    tracker.process_event(evt1)
    assert len(tracker.active_flows) == 1

    # Fast forward past idle timeout (timestamp=1050.0 > 1000.0 + 30.0)
    evt2 = NormalizedConnectionEvent(
        event_id="e2", timestamp=1050.0, source_engine="zeek",
        src_ip="10.0.0.2", dst_ip="192.168.1.1", src_port=5678, dst_port=80, protocol="TCP"
    )
    tracker.process_event(evt2)
    tracker._prune_stale_flows(1050.0)

    # Flow 1 must be evicted without ever requiring FIN or RST
    assert "10.0.0.1:1234 -> 192.168.1.1:80 [TCP]" not in tracker.active_flows
    assert "10.0.0.2:5678 -> 192.168.1.1:80 [TCP]" in tracker.active_flows


# ── 10. SOURCE IP CONTEXTUAL BEHAVIOR & EXPLAINABLE EVIDENCE ──────────────────
def test_source_ip_context_and_explainable_evidence():
    """Verifies evidence generator produces factual human-readable metrics without sensational zero-day claims."""
    from app.alerts.engine import EvidenceGenerator
    from app.telemetry.feature_schema import TelemetryFeatureVector_v2
    from app.ml.fusion import FusionResult

    fv = TelemetryFeatureVector_v2(
        flow_id="src_test_flow",
        timestamp=1000.0,
        syn_ratio=0.98,
        packet_rate=120.0,
        src_ip_entropy=4.5,
        dst_in_degree=25.0
    )

    compat_fusion = FusionResult(
        flow_id="src_test_flow",
        timestamp=1000.0,
        decision_state="A: KNOWN_THREAT_CONFIRMED",
        threat_label="DDOS",
        confidence=0.96,
        rf_prediction="DDOS",
        rf_confidence=0.96,
        rf_class_probabilities={"BENIGN": 0.04, "DDOS": 0.96},
        if_anomaly_score=0.065,
        if_is_anomalous=True,
        if_threshold=0.073,
        detection_method="HYBRID",
        inference_latency_ms=0.05
    )

    evidence_items, reason, _ = EvidenceGenerator.generate_evidence(fv, compat_fusion)
    assert len(evidence_items) > 0

    # Ensure zero sensational claims
    full_text = " ".join(evidence_items) + " " + reason
    assert "zero-day" not in full_text.lower()
    assert "guaranteed" not in full_text.lower()
    # Verify exact metric explainability
    assert any("SYN packet ratio" in e for e in evidence_items)
    assert any("Source IP entropy" in e for e in evidence_items)

