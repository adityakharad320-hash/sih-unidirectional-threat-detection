"""
Unit Tests for Security Alert Engine, Evidence Generator, and Deduplicator.
"""
import pytest
import time
from app.alerts.models import SecurityAlert_v2, AlertSeverity, AlertStatistics
from app.alerts.engine import AlertEngine, EvidenceGenerator
from app.ml.fusion import FusionResult
from app.detectors.models import BehavioralDetectionResult
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

def test_evidence_generation_port_scan():
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.50:51722 -> 192.168.1.1:69 [TCP]",
        timestamp=1724832000.0,
        unique_dst_ports=35.0,
        dst_port_fanout=12.5,
        failed_conn_ratio=0.92,
        conn_attempts=35.0
    )
    fusion = FusionResult(
        flow_id=fv.flow_id,
        timestamp=fv.timestamp,
        decision_state="A: KNOWN_THREAT_CONFIRMED",
        threat_label="PORT_SCAN",
        confidence=0.92,
        rf_prediction="PORT_SCAN",
        rf_confidence=0.92,
        rf_class_probabilities={"PORT_SCAN": 0.92, "BENIGN": 0.08},
        if_anomaly_score=0.039,
        if_is_anomalous=True,
        if_threshold=0.073,
        detection_method="HYBRID",
        inference_latency_ms=1.5
    )
    evidence, primary_reason, snapshot = EvidenceGenerator.generate_evidence(fv, fusion)
    assert len(evidence) >= 2
    assert any("35 distinct ports" in e for e in evidence)
    assert any("12.50 ports/sec" in e for e in evidence)
    assert snapshot["unique_dst_ports"] == 35.0

def test_alert_severity_resolution():
    fv_ddos = TelemetryFeatureVector_v2(
        flow_id="test_ddos",
        timestamp=1.0,
        packet_rate=600.0,
        dst_in_degree=25.0
    )
    sev_ddos = AlertEngine.resolve_severity("DDOS", 0.95, fv_ddos)
    assert sev_ddos == AlertSeverity.CRITICAL

    fv_scan = TelemetryFeatureVector_v2(
        flow_id="test_scan",
        timestamp=1.0,
        unique_dst_ports=30.0,
        dst_port_fanout=15.0
    )
    sev_scan = AlertEngine.resolve_severity("PORT_SCAN", 0.88, fv_scan)
    assert sev_scan == AlertSeverity.HIGH

    fv_benign = TelemetryFeatureVector_v2(flow_id="test_benign", timestamp=1.0)
    sev_benign = AlertEngine.resolve_severity("BENIGN", 0.99, fv_benign)
    assert sev_benign == AlertSeverity.INFO

def test_alert_deduplication_and_correlation():
    engine = AlertEngine(dedup_window_sec=10.0)
    base_ts = 1724832000.0

    fv1 = TelemetryFeatureVector_v2(
        flow_id="172.16.4.32:65519 -> 10.0.0.1:80 [TCP]",
        timestamp=base_ts,
        packet_rate=500.0,
        syn_ratio=1.0
    )
    fusion1 = FusionResult(
        flow_id=fv1.flow_id,
        timestamp=base_ts,
        decision_state="A: KNOWN_THREAT_CONFIRMED",
        threat_label="DDOS",
        confidence=0.90,
        rf_prediction="DDOS",
        rf_confidence=0.90,
        rf_class_probabilities={"DDOS": 0.90},
        if_anomaly_score=0.05,
        if_is_anomalous=True,
        if_threshold=0.073,
        detection_method="HYBRID",
        inference_latency_ms=1.0
    )

    # First event -> Creates new alert
    alert1, is_new1 = engine.process_detection(fv1, fusion1)
    assert is_new1 is True
    assert alert1.occurrence_count == 1

    # Second event 2 seconds later for same source, dest, and threat -> Deduplicated!
    fv2 = TelemetryFeatureVector_v2(
        flow_id="172.16.4.32:65520 -> 10.0.0.1:80 [TCP]",
        timestamp=base_ts + 2.0,
        packet_rate=520.0,
        syn_ratio=1.0
    )
    alert2, is_new2 = engine.process_detection(fv2, fusion1)
    assert is_new2 is False
    assert alert2.alert_id == alert1.alert_id
    assert alert2.occurrence_count == 2
    assert alert2.last_seen == base_ts + 2.0

    # Verify statistics
    stats = engine.get_statistics()
    assert stats.total_alerts == 1
    assert stats.total_events_processed == 2
    assert stats.deduplication_savings_ratio == 0.50
