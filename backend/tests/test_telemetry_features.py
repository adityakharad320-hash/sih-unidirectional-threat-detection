"""
Comprehensive Unit & Pipeline Tests for Telemetry Feature Engineering Layer.
"""
import pytest
import numpy as np
from pathlib import Path
from app.telemetry.schema import (
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent
)
from app.telemetry.telemetry_flow_tracker import TelemetryFlowState, StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.telemetry.feature_schema import TelemetryFeatureVector_v2, ORDERED_TELEMETRY_FEATURE_NAMES
from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.config import SAMPLES_DIR

def test_feature_vector_schema_properties():
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.100:54321 -> 10.0.0.1:80 [TCP]",
        timestamp=1724832000.0,
        packet_rate=500.0,
        syn_ratio=1.0,
        shannon_entropy_mean=3.95
    )
    d = fv.to_dict()
    assert d["packet_rate"] == 500.0
    assert d["syn_ratio"] == 1.0
    assert d["shannon_entropy_mean"] == 3.95
    
    arr = fv.to_numpy()
    assert isinstance(arr, np.ndarray)
    assert len(arr) == len(ORDERED_TELEMETRY_FEATURE_NAMES)
    assert not np.isnan(arr).any()

def test_dga_character_distribution_features():
    # Test DGA domain with high entropy and unusual consonants
    dga_domain = "xq89zlkj4v91a0c8.badc2.org"
    entropy = TelemetryFeatureExtractor.shannon_entropy(dga_domain)
    ngram = TelemetryFeatureExtractor.calculate_dga_ngram_score(dga_domain)
    
    assert entropy > 3.5
    assert ngram < -5.0  # Strongly negative log-likelihood for random consonant strings

def test_c2_beaconing_periodicity_and_jitter():
    base_ts = 1724832000.0
    # 10 pulses spaced by 1.0s with +/- 0.01s jitter
    timestamps = [base_ts + i * 1.0 + np.random.uniform(-0.01, 0.01) for i in range(15)]
    
    iat_min, iat_max, iat_mean, iat_std, iat_cv, periodicity = TelemetryFeatureExtractor.calculate_temporal_beaconing_features(
        timestamps
    )
    assert 0.95 <= iat_mean <= 1.05
    assert iat_cv < 0.05  # Rigid periodicity
    assert periodicity > 0.1

def test_graph_degrees_and_fanout():
    tracker = StreamingTelemetryTracker()
    now = 1724832000.0
    
    # Simulate a port scanner contacting 20 different ports
    for port in range(20, 40):
        event = NormalizedConnectionEvent(
            event_id=f"conn_{port}",
            timestamp=now,
            source_engine="zeek",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=50000 + port,
            dst_port=port,
            protocol="TCP",
            conn_state="S0",
            orig_pkts=1,
            orig_bytes=54
        )
        state = tracker.process_event(event)
        
    fv = TelemetryFeatureExtractor.extract_features(state, tracker)
    assert fv.unique_dst_ports == 20.0
    assert fv.failed_conn_ratio == 1.0  # All S0
    assert fv.src_out_degree >= 1.0

def test_full_pipeline_syn_flood_telemetry_features(tmp_path):
    syn_pcap = SAMPLES_DIR / "syn_flood.pcap"
    out_dir = tmp_path / "syn_flood_telemetry"
    
    # 1. Replay PCAP to Zeek / Suricata logs
    PcapReplayRunner.replay_pcap_to_telemetry(syn_pcap, out_dir)
    
    # 2. Ingest normalized events into streaming tracker
    streamer = TelemetryStreamer(out_dir)
    tracker = StreamingTelemetryTracker()
    
    fvs = []
    for event in streamer.stream_all_events():
        state = tracker.process_event(event)
        fvs.append(TelemetryFeatureExtractor.extract_features(state, tracker))
        
    assert len(fvs) > 0
    # Distributed SYN flood attributes (spoofed sources targeting single destination)
    assert any(fv.syn_ratio >= 0.5 for fv in fvs)
    assert any(fv.dst_in_degree >= 10.0 for fv in fvs)
    assert any(fv.src_ip_entropy > 2.0 for fv in fvs)
    assert not any(np.isnan(fv.to_numpy()).any() for fv in fvs)

def test_full_pipeline_dga_dns_telemetry_features(tmp_path):
    dga_pcap = SAMPLES_DIR / "dga_dns_tunnel.pcap"
    out_dir = tmp_path / "dga_telemetry"
    
    PcapReplayRunner.replay_pcap_to_telemetry(dga_pcap, out_dir)
    streamer = TelemetryStreamer(out_dir)
    tracker = StreamingTelemetryTracker()
    
    last_fv = None
    for event in streamer.stream_all_events():
        state = tracker.process_event(event)
        last_fv = TelemetryFeatureExtractor.extract_features(state, tracker)
        
    assert last_fv is not None
    assert last_fv.shannon_entropy_mean > 3.0
    assert last_fv.txt_record_ratio == 1.0
