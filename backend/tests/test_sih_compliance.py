"""
Automated Pytest Suite for SIH 2026 Compliance Constraints & Schema Parity.
"""
import pytest
import numpy as np
from app.telemetry.feature_schema import TelemetryFeatureVector_v2
from app.ml.preprocessing import FEATURE_COLS
from app.alerts.models import SecurityAlert_v2, AlertSeverity

def test_feature_schema_parity_training_vs_inference():
    """Assert 100% exact match between Training feature names and Inference feature names."""
    train_cols = list(FEATURE_COLS)
    dummy_fv = TelemetryFeatureVector_v2(flow_id="compliance_test", timestamp=1.0)
    inf_cols = list(dummy_fv.to_dict().keys())

    assert len(train_cols) == 54
    assert len(inf_cols) == 54
    assert train_cols == inf_cols

def test_alert_schema_mandatory_sih_fields():
    """Assert SecurityAlert_v2 includes all required SIH fields."""
    alert = SecurityAlert_v2(
        alert_id="ALT-20260828-TEST1234",
        timestamp=1724832000.0,
        timestamp_iso="2026-08-28T16:00:00.000Z",
        flow_id="192.168.1.100:54321 -> 10.0.0.1:80 [TCP]",
        threat_class="DDOS",
        confidence_score=0.95,
        severity=AlertSeverity.CRITICAL,
        primary_reason="SYN flood detected",
        anomaly_score=0.045,
        if_is_anomalous=True,
        supporting_evidence=["SYN packet ratio: 100.0%"],
        detection_method="HYBRID",
        first_seen=1724832000.0,
        last_seen=1724832000.0
    )
    data = alert.model_dump()
    mandatory_fields = [
        "alert_id", "timestamp", "flow_id", "threat_class",
        "confidence_score", "severity", "supporting_evidence"
    ]
    for field in mandatory_fields:
        assert field in data
        assert data[field] is not None
