"""
Automated Test Suite for Controlled Traffic Scenarios.
Verifies that all 6 PCAP scenarios produce correct, genuine threat alerts through the full pipeline.
"""
import pytest
from pathlib import Path
from app.utils.traffic_scenarios import ControlledTrafficGenerator
from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.ml.hybrid_inference import HybridInferenceEngine
from app.alerts.engine import AlertEngine
from app.alerts.models import AlertSeverity

@pytest.fixture(scope="module")
def hybrid_engine():
    return HybridInferenceEngine()

@pytest.fixture(scope="module")
def generated_pcaps(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("controlled_pcaps")
    return ControlledTrafficGenerator.generate_all_scenarios(out_dir)

def _run_pcap_pipeline(pcap_path: Path, hybrid_engine, tmp_path: Path):
    out_dir = tmp_path / pcap_path.stem
    PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, out_dir)
    
    streamer = TelemetryStreamer(out_dir)
    tracker = StreamingTelemetryTracker()
    alert_engine = AlertEngine()
    alerts = []

    for event in streamer.stream_all_events():
        state = tracker.process_event(event)
        fv = TelemetryFeatureExtractor.extract_features(state, tracker)
        fusion = hybrid_engine.predict(fv)
        alert, is_new = alert_engine.process_detection(fv, fusion)
        if is_new and alert.threat_class != "BENIGN":
            alerts.append(alert)

    return alerts

def test_scenario_benign(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["BENIGN"], hybrid_engine, tmp_path)
    # Benign traffic should not generate high/critical threat alerts
    threat_alerts = [a for a in alerts if a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)]
    assert len(threat_alerts) == 0

def test_scenario_syn_flood(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["SYN_FLOOD"], hybrid_engine, tmp_path)
    assert len(alerts) >= 1
    top = alerts[0]
    assert top.threat_class in ("DDOS", "UNKNOWN_ANOMALY")
    assert top.confidence_score >= 0.60
    assert len(top.supporting_evidence) >= 1

def test_scenario_port_scan(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["PORT_SCAN"], hybrid_engine, tmp_path)
    assert len(alerts) >= 1
    top = alerts[0]
    assert top.threat_class in ("PORT_SCAN", "UNKNOWN_ANOMALY")
    assert top.confidence_score >= 0.60

def test_scenario_dns_dga_tunnel(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["DGA_DNS_TUNNEL"], hybrid_engine, tmp_path)
    assert len(alerts) >= 1
    top = alerts[0]
    assert top.threat_class in ("DGA_DNS_TUNNELLING", "UNKNOWN_ANOMALY")

def test_scenario_c2_beaconing(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["C2_BEACONING"], hybrid_engine, tmp_path)
    assert len(alerts) >= 1
    top = alerts[0]
    assert top.threat_class in ("C2_BEACONING", "UNKNOWN_ANOMALY")

def test_scenario_data_exfiltration(generated_pcaps, hybrid_engine, tmp_path):
    alerts = _run_pcap_pipeline(generated_pcaps["DATA_EXFILTRATION"], hybrid_engine, tmp_path)
    assert len(alerts) >= 1
    top = alerts[0]
    assert top.threat_class in ("DATA_EXFILTRATION", "UNKNOWN_ANOMALY")
