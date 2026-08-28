"""
Comprehensive Test Suite for Deterministic Behavioral Detectors.
Covers:
  - Normal / Benign traffic (assert no triggers)
  - Clear attack traffic across all 6 threat categories
  - Boundary conditions (below vs above configurable thresholds)
"""
import pytest
from app.detectors.models import BehavioralDetectorsConfig, BehavioralDetectionResult
from app.detectors.behavioral_engine import BehavioralDetectionEngine
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

@pytest.fixture
def engine():
    config = BehavioralDetectorsConfig(
        ddos_packet_rate_thresh=100.0,
        ddos_syn_ratio_thresh=0.80,
        ddos_src_entropy_thresh=2.50,
        scan_unique_ports_thresh=10.0,
        scan_port_fanout_thresh=2.0,
        dns_entropy_thresh=3.40,
        dns_txt_ratio_thresh=0.50,
        c2_iat_cv_thresh=0.15,
        c2_periodicity_thresh=0.08,
        exfil_out_in_ratio_thresh=8.0,
        exfil_asym_score_thresh=0.75,
        exfil_min_outbound_bytes=5000.0
    )
    return BehavioralDetectionEngine(config)

# ── 1. Normal / Benign Traffic Tests ─────────────────────────────────────────
def test_normal_benign_traffic_no_triggers(engine):
    fv_normal = TelemetryFeatureVector_v2(
        flow_id="192.168.1.100:54321 -> 142.250.190.46:443 [TCP]",
        timestamp=1724832000.0,
        packet_rate=5.0,
        syn_ratio=0.10,
        ack_ratio=0.90,
        src_ip_entropy=0.0,
        unique_src_count=1.0,
        unique_dst_ports=1.0,
        dst_port_fanout=0.1,
        failed_conn_ratio=0.0,
        shannon_entropy_mean=2.1,
        query_len_mean=12.0,
        txt_record_ratio=0.0,
        ngram_log_likelihood=-2.5,
        iat_mean=1.5,
        iat_cv=0.85,  # High variance (human browsing)
        periodicity_score=0.01,
        outbound_bytes=1200.0,
        inbound_bytes=15000.0,
        out_in_byte_ratio=0.08,
        asymmetric_traffic_score=-0.85,
        tls_version_num=1.3,
        has_tls_sni=1.0
    )
    results = engine.evaluate_all(fv_normal)
    triggered = [r for r in results if r.triggered]
    assert len(triggered) == 0, f"Normal traffic should not trigger any detector: {[r.detector_name for r in triggered]}"

# ── 2. Clear Attack Traffic Tests ─────────────────────────────────────────────
def test_clear_ddos_syn_flood(engine):
    fv_ddos = TelemetryFeatureVector_v2(
        flow_id="172.16.4.32:65519 -> 10.0.0.1:80 [TCP]",
        timestamp=1724832000.0,
        syn_ratio=1.0,
        src_ip_entropy=4.91,
        unique_src_count=50.0,
        dst_in_degree=50.0,
        packet_rate=500.0
    )
    res = engine.evaluate_ddos(fv_ddos)
    assert res.triggered is True
    assert res.score >= 0.90
    assert "Distributed SYN flood pattern" in res.human_readable_reason
    assert "syn_ratio" in res.supporting_evidence

def test_clear_port_scan(engine):
    fv_scan = TelemetryFeatureVector_v2(
        flow_id="192.168.1.50:51722 -> 192.168.1.1:69 [TCP]",
        timestamp=1724832000.0,
        unique_dst_ports=30.0,
        dst_port_fanout=15.0,
        failed_conn_ratio=0.90
    )
    res = engine.evaluate_port_scan(fv_scan)
    assert res.triggered is True
    assert res.score >= 0.90
    assert "Vertical port scan" in res.human_readable_reason
    assert res.supporting_evidence["unique_dst_ports"] == 30.0

def test_clear_dns_dga_and_tunnel(engine):
    fv_dga = TelemetryFeatureVector_v2(
        flow_id="192.168.1.75:51696 -> 8.8.8.8:53 [UDP]",
        timestamp=1724832000.0,
        shannon_entropy_mean=3.78,
        query_len_mean=28.0,
        txt_record_ratio=1.0,
        ngram_log_likelihood=-9.21
    )
    res = engine.evaluate_dns_dga(fv_dga)
    assert res.triggered is True
    assert res.score >= 0.90
    assert "Algorithmic domain name (DGA)" in res.human_readable_reason or "TXT record ratio" in res.human_readable_reason

def test_clear_c2_beaconing(engine):
    fv_c2 = TelemetryFeatureVector_v2(
        flow_id="10.0.5.12:49152 -> 198.51.100.42:8443 [TCP]",
        timestamp=1724832000.0,
        iat_mean=1.002,
        iat_cv=0.015,  # Ultra rigid
        periodicity_score=0.35,
        repeated_conn_count=15.0
    )
    res = engine.evaluate_c2_beaconing(fv_c2)
    assert res.triggered is True
    assert res.score >= 0.85
    assert "Automated C2 beaconing signal" in res.human_readable_reason

def test_clear_data_exfiltration(engine):
    fv_exfil = TelemetryFeatureVector_v2(
        flow_id="192.168.1.105:54321 -> 203.0.113.50:443 [TCP]",
        timestamp=1724832000.0,
        outbound_bytes=50_000_000.0,
        inbound_bytes=25_000.0,
        out_in_byte_ratio=2000.0,
        asymmetric_traffic_score=0.999,
        outbound_rate=500_000.0
    )
    res = engine.evaluate_data_exfiltration(fv_exfil)
    assert res.triggered is True
    assert res.score >= 0.90
    assert "Heavy data exfiltration pattern" in res.human_readable_reason

def test_clear_encrypted_malware_direct_ip(engine):
    fv_enc = TelemetryFeatureVector_v2(
        flow_id="192.168.1.105:54321 -> 198.51.100.5:443 [TCP]",
        timestamp=1724832000.0,
        tls_version_num=1.3,
        has_tls_sni=0.0,  # Missing SNI on port 443
        directionality_ratio=0.95,
        pkt_size_entropy=0.5
    )
    res = engine.evaluate_encrypted_traffic(fv_enc)
    assert res.triggered is True
    assert "Direct IP TLS connection" in res.human_readable_reason

# ── 3. Boundary Condition Tests ───────────────────────────────────────────────
def test_ddos_boundary_conditions(engine):
    # Just below threshold (syn_ratio 0.79 < 0.80, entropy 2.40 < 2.50)
    fv_below = TelemetryFeatureVector_v2(
        flow_id="test_below",
        timestamp=1.0,
        syn_ratio=0.79,
        src_ip_entropy=2.40,
        packet_rate=99.0
    )
    assert engine.evaluate_ddos(fv_below).triggered is False

    # At or above threshold (syn_ratio 0.80, entropy 2.50)
    fv_above = TelemetryFeatureVector_v2(
        flow_id="test_above",
        timestamp=1.0,
        syn_ratio=0.80,
        src_ip_entropy=2.50
    )
    assert engine.evaluate_ddos(fv_above).triggered is True

def test_port_scan_boundary_conditions(engine):
    # Below threshold (unique ports 9 < 10, fanout 1.9 < 2.0)
    fv_below = TelemetryFeatureVector_v2(
        flow_id="test_below",
        timestamp=1.0,
        unique_dst_ports=9.0,
        dst_port_fanout=1.9
    )
    assert engine.evaluate_port_scan(fv_below).triggered is False

    # Above threshold (unique ports 10 >= 10)
    fv_above = TelemetryFeatureVector_v2(
        flow_id="test_above",
        timestamp=1.0,
        unique_dst_ports=10.0,
        dst_port_fanout=2.0
    )
    assert engine.evaluate_port_scan(fv_above).triggered is True

def test_dns_entropy_boundary_conditions(engine):
    # Below threshold (entropy 3.39 < 3.40)
    fv_below = TelemetryFeatureVector_v2(
        flow_id="test_below",
        timestamp=1.0,
        shannon_entropy_mean=3.39,
        query_len_mean=25.0,
        ngram_log_likelihood=-4.0
    )
    assert engine.evaluate_dns_dga(fv_below).triggered is False

    # Above threshold (entropy 3.41 >= 3.40, len >= 15.0)
    fv_above = TelemetryFeatureVector_v2(
        flow_id="test_above",
        timestamp=1.0,
        shannon_entropy_mean=3.41,
        query_len_mean=25.0,
        ngram_log_likelihood=-4.0
    )
    assert engine.evaluate_dns_dga(fv_above).triggered is True
