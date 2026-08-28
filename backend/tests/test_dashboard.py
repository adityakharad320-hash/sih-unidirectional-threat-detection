"""
Unit Tests for Streamlit Dashboard Components & API Client.
"""
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent.parent
backend_dir = root_dir / "backend"
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
from dashboard.api_client import DashboardApiClient
from app.telemetry.feature_schema import TelemetryFeatureVector_v2
from app.ml.fusion import FusionResult
from app.alerts.engine import AlertEngine
from app.main import global_alert_engine

@pytest.fixture
def client():
    # Pre-populate global alert engine with sample alerts
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.50:51722 -> 192.168.1.1:69 [TCP]",
        timestamp=1724832000.0,
        unique_dst_ports=25.0,
        dst_port_fanout=10.0
    )
    fusion = FusionResult(
        flow_id=fv.flow_id,
        timestamp=fv.timestamp,
        decision_state="A: KNOWN_THREAT_CONFIRMED",
        threat_label="PORT_SCAN",
        confidence=0.95,
        rf_prediction="PORT_SCAN",
        rf_confidence=0.95,
        rf_class_probabilities={"PORT_SCAN": 0.95},
        if_anomaly_score=0.03,
        if_is_anomalous=True,
        if_threshold=0.073,
        detection_method="HYBRID",
        inference_latency_ms=1.2
    )
    global_alert_engine.process_detection(fv, fusion)
    return DashboardApiClient()

def test_dashboard_api_client_system_status(client):
    status = client.get_system_status()
    assert "status" in status
    assert "organization" in status

def test_dashboard_api_client_get_alerts(client):
    alerts = client.get_alerts(limit=10)
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    first = alerts[0]
    assert "alert_id" in first
    assert "threat_class" in first

def test_dashboard_api_client_get_statistics(client):
    stats = client.get_statistics()
    assert "total_alerts" in stats
    assert "severity_breakdown" in stats
    assert stats["total_alerts"] >= 1
