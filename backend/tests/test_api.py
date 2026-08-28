"""
FastAPI REST & WebSocket Endpoints Test Suite.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app, global_alert_engine
from app.alerts.models import SecurityAlert_v2, AlertSeverity
from app.alerts.engine import AlertEngine
from app.ml.fusion import FusionResult
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

@pytest.fixture
def client():
    # Pre-populate global alert engine with test alerts
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
    return TestClient(app)

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert data["organization"] == "National Technical Research Organisation (NTRO)"

def test_get_alerts_endpoint(client):
    response = client.get("/alerts?limit=10")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    
    first = alerts[0]
    assert "alert_id" in first
    assert "threat_class" in first
    assert "confidence_score" in first
    assert "severity" in first
    assert "supporting_evidence" in first

def test_get_alert_by_id_endpoint(client):
    alerts = client.get("/alerts").json()
    first_id = alerts[0]["alert_id"]
    
    response = client.get(f"/alerts/{first_id}")
    assert response.status_code == 200
    alert = response.json()
    assert alert["alert_id"] == first_id

def test_get_alert_not_found(client):
    response = client.get("/alerts/ALT-INVALID-9999")
    assert response.status_code == 404

def test_get_statistics_endpoint(client):
    response = client.get("/statistics")
    assert response.status_code == 200
    stats = response.json()
    assert "total_alerts" in stats
    assert "severity_breakdown" in stats
    assert "threat_class_breakdown" in stats
    assert stats["total_alerts"] >= 1

def test_websocket_stream(client):
    with client.websocket_connect("/ws/alerts") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"
