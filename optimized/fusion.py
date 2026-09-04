"""
Streamlined Decision Fusion Layer.

Maps behavioral triggers, gate results, RF probabilities, and IF scores
into definitive, explainable threat decisions without redundant allocations.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from app.detectors.models import BehavioralDetectionResult
from optimized.gate import GateDecision, GateResult


@dataclass(slots=True)
class OptimizedFusionResult:
    flow_id: str
    timestamp: float
    decision_state: str
    threat_label: str
    confidence: float
    detection_method: str
    rf_prediction: str
    rf_confidence: float
    rf_probabilities: Dict[str, float]
    if_anomaly_score: float
    if_is_anomalous: bool
    escalated_to_if: bool
    behavioral_triggered: bool
    primary_reason: Optional[str] = None
    is_threat: bool = False


class OptimizedFusionEngine:
    """
    High-performance decision matrix evaluator.
    """
    def __init__(self, behavioral_engine=None):
        from app.detectors.behavioral_engine import BehavioralDetectionEngine
        self.behavioral_engine = behavioral_engine or BehavioralDetectionEngine()

    def resolve(
        self,
        flow_id: str,
        timestamp: float,
        vector_pydantic,
        gate_res: GateResult,
        rf_pred: str,
        rf_conf: float,
        rf_proba_dict: Dict[str, float],
        if_score: float,
        if_anomalous: bool,
        escalated_to_if: bool
    ) -> OptimizedFusionResult:
        # Fast path 1: Gate matched a critical attack rule
        if gate_res.decision == GateDecision.CRITICAL_RULE and gate_res.threat_category:
            return OptimizedFusionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                decision_state="B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)",
                threat_label=gate_res.threat_category,
                confidence=max(0.90, gate_res.urgency_level),
                detection_method="BEHAVIORAL_RULE",
                rf_prediction=rf_pred,
                rf_confidence=rf_conf,
                rf_probabilities=rf_proba_dict,
                if_anomaly_score=if_score,
                if_is_anomalous=if_anomalous,
                escalated_to_if=escalated_to_if,
                behavioral_triggered=True,
                primary_reason=" | ".join(gate_res.flagged_reasons),
                is_threat=True
            )

        # Evaluate full behavioral detectors if not cleanly normal
        triggered_dets = []
        if gate_res.decision != GateDecision.PASS_NORMAL:
            det_results = self.behavioral_engine.evaluate_all(vector_pydantic)
            triggered_dets = [d for d in det_results if d.triggered]

        primary_reason = triggered_dets[0].human_readable_reason if triggered_dets else None

        behavioral_threat_map = {
            "DDoS": "DDOS",
            "Port Scanning": "PORT_SCAN",
            "DNS / DGA": "DGA_DNS_TUNNELLING",
            "C2 Beaconing": "C2_BEACONING",
            "Data Exfiltration": "DATA_EXFILTRATION",
            "Encrypted Malware": "ENCRYPTED_MALWARE"
        }

        # Check for behavioral rule overrides
        behavioral_override_cat = None
        behavioral_override_score = 0.0
        for td in triggered_dets:
            mapped_cat = behavioral_threat_map.get(td.category, td.category)
            if rf_conf < 0.75 or rf_pred == "BENIGN" or mapped_cat == rf_pred:
                behavioral_override_cat = mapped_cat
                behavioral_override_score = td.score
                break

        if behavioral_override_cat:
            return OptimizedFusionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                decision_state="B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)",
                threat_label=behavioral_override_cat,
                confidence=max(0.85, behavioral_override_score),
                detection_method="BEHAVIORAL_RULE",
                rf_prediction=rf_pred,
                rf_confidence=rf_conf,
                rf_probabilities=rf_proba_dict,
                if_anomaly_score=if_score,
                if_is_anomalous=if_anomalous,
                escalated_to_if=escalated_to_if,
                behavioral_triggered=True,
                primary_reason=primary_reason or " | ".join(gate_res.flagged_reasons),
                is_threat=True
            )

        # Supervised RF known attack
        if rf_pred != "BENIGN" and rf_conf >= 0.75:
            matching_beh = any(behavioral_threat_map.get(d.category) == rf_pred for d in triggered_dets)
            if if_anomalous or matching_beh:
                dec_state = "A: KNOWN_THREAT_CONFIRMED"
                conf = min(1.0, max(rf_conf, 0.92))
                method = "HYBRID"
            else:
                dec_state = "B: KNOWN_THREAT_PROBABLE"
                conf = rf_conf
                method = "MODEL_SUPERVISED"

            return OptimizedFusionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                decision_state=dec_state,
                threat_label=rf_pred,
                confidence=conf,
                detection_method=method,
                rf_prediction=rf_pred,
                rf_confidence=rf_conf,
                rf_probabilities=rf_proba_dict,
                if_anomaly_score=if_score,
                if_is_anomalous=if_anomalous,
                escalated_to_if=escalated_to_if,
                behavioral_triggered=len(triggered_dets) > 0,
                primary_reason=primary_reason or f"Supervised classifier identified {rf_pred} with {rf_conf*100:.1f}% confidence.",
                is_threat=True
            )

        # Anomaly Detection Trigger
        if if_anomalous:
            return OptimizedFusionResult(
                flow_id=flow_id,
                timestamp=timestamp,
                decision_state="C: UNKNOWN_ANOMALY",
                threat_label="UNKNOWN_ANOMALY",
                confidence=min(1.0, 0.60 + max(0.0, -if_score) * 2.0),
                detection_method="MODEL_ANOMALY",
                rf_prediction=rf_pred,
                rf_confidence=rf_conf,
                rf_probabilities=rf_proba_dict,
                if_anomaly_score=if_score,
                if_is_anomalous=True,
                escalated_to_if=True,
                behavioral_triggered=False,
                primary_reason=f"Unsupervised isolation anomaly detected: score {if_score:.4f}.",
                is_threat=True
            )

        # Benign Normal Traffic
        return OptimizedFusionResult(
            flow_id=flow_id,
            timestamp=timestamp,
            decision_state="D: BENIGN_NORMAL_TRAFFIC",
            threat_label="BENIGN",
            confidence=max(0.90, rf_conf),
            detection_method="MODEL_SUPERVISED",
            rf_prediction=rf_pred,
            rf_confidence=rf_conf,
            rf_probabilities=rf_proba_dict,
            if_anomaly_score=if_score,
            if_is_anomalous=False,
            escalated_to_if=escalated_to_if,
            behavioral_triggered=False,
            primary_reason="Normal traffic within baseline parameters.",
            is_threat=False
        )
