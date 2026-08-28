"""
Versioned Security Alert Data Models and Statistics Schema.
"""
import enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SecurityAlert_v2(BaseModel):
    """
    Standardized SIH 2026 Security Alert (Schema Version 2.0).
    Captures factual observed evidence, confidence with explicit semantics,
    and correlation metadata.
    """
    alert_id: str = Field(description="Unique alert identifier e.g. ALT-YYYYMMDD-XXXX")
    schema_version: str = "v2.0"
    timestamp: float = Field(description="Epoch timestamp in seconds")
    timestamp_iso: str = Field(description="ISO-8601 formatted UTC timestamp")
    flow_id: str = Field(description="Unidirectional / Bidirectional 5-tuple identifier")
    
    # Core Classification & Threat Attribution
    threat_class: str = Field(description="Threat category: DDOS, PORT_SCAN, DGA_DNS_TUNNELLING, C2_BEACONING, DATA_EXFILTRATION, ENCRYPTED_MALWARE, UNKNOWN_ANOMALY, BENIGN")
    confidence_score: float = Field(description="Normalized threat confidence score [0.0 - 1.0]")
    severity: AlertSeverity = Field(description="Impact severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    
    # Human-Readable & Factual Supporting Evidence
    supporting_evidence: List[str] = Field(default_factory=list, description="Factual evidence strings derived strictly from observed features")
    primary_reason: str = Field(description="Summary explanation for SOC operators")
    
    # Internal ML & Behavioral Telemetry Context
    classifier_probability: Optional[float] = Field(default=None, description="Supervised classifier probability for predicted class")
    rf_class_probabilities: Dict[str, float] = Field(default_factory=dict, description="Class probabilities breakdown from Random Forest")
    anomaly_score: float = Field(description="Raw Isolation Forest decision function score (NOT a calibrated probability)")
    if_is_anomalous: bool = Field(description="Whether Isolation Forest flagged the flow as anomalous")
    triggered_detectors: List[str] = Field(default_factory=list, description="List of deterministic behavioral detector names that triggered")
    feature_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Snapshot of key discriminative feature values")
    
    # Correlation & Deduplication Tracking
    occurrence_count: int = Field(default=1, description="Number of correlated flow events collapsed into this alert")
    first_seen: float = Field(description="Epoch timestamp of initial flow event")
    last_seen: float = Field(description="Epoch timestamp of most recent flow event")
    
    # Model Attribution
    model_version: str = "v2.0"
    feature_schema_version: str = "2.0.0"
    detection_method: str = "HYBRID"  # "HYBRID" | "MODEL_SUPERVISED" | "MODEL_ANOMALY" | "BEHAVIORAL_RULE"

class AlertStatistics(BaseModel):
    """Real-time aggregated security statistics."""
    total_alerts: int
    total_events_processed: int
    deduplication_savings_ratio: float  # (1 - alerts / events)
    severity_breakdown: Dict[str, int]
    threat_class_breakdown: Dict[str, int]
    detection_method_breakdown: Dict[str, int]
    active_threats_count: int
    last_updated_iso: str
