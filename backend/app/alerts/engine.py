"""
Security Alert & Explainability Engine.

Responsibilities:
1. Evidence Generation: Extracts factual observed features into human-readable evidence.
2. Severity Resolution: Deterministic risk matrix based on threat type, confidence, and volume.
3. Sliding-Window Deduplication: Suppresses flood duplicates and aggregates occurrences.
4. Alert Store: Thread-safe in-memory alert registry with filtering and statistics.
"""
import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter

from app.alerts.models import SecurityAlert_v2, AlertSeverity, AlertStatistics
from app.ml.fusion import FusionResult
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

class EvidenceGenerator:
    """
    Transforms TelemetryFeatureVector_v2 and FusionResult into factual,
    human-readable evidence strings without inventing numbers.
    """
    @classmethod
    def generate_evidence(cls, fv: TelemetryFeatureVector_v2, fusion: FusionResult) -> Tuple[List[str], str, Dict[str, Any]]:
        evidence = []
        snapshot = {}
        category = fusion.threat_label

        if category == "DDOS":
            if fv.syn_ratio > 0.5:
                evidence.append(f"SYN packet ratio: {fv.syn_ratio * 100:.1f}% of total flow packets")
                snapshot["syn_ratio"] = fv.syn_ratio
            if fv.packet_rate > 10.0:
                evidence.append(f"High packet transmission rate: {fv.packet_rate:.1f} packets/sec")
                snapshot["packet_rate"] = fv.packet_rate
            if fv.src_ip_entropy > 1.5:
                evidence.append(f"Source IP entropy: {fv.src_ip_entropy:.2f} bits (distributed/spoofed sources)")
                snapshot["src_ip_entropy"] = fv.src_ip_entropy
            if fv.unique_src_count > 5.0 or fv.dst_in_degree > 5.0:
                evidence.append(f"Target destination in-degree: {int(fv.dst_in_degree)} unique contacting source IPs")
                snapshot["dst_in_degree"] = fv.dst_in_degree
            if fv.udp_rate > 10.0:
                evidence.append(f"UDP packet rate: {fv.udp_rate:.1f} packets/sec (amplification indicator: {fv.byte_amplification_ratio:.1f}x)")
                snapshot["udp_rate"] = fv.udp_rate
            primary_reason = f"Volumetric / Distributed Denial of Service attack targeting host (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "PORT_SCAN":
            if fv.unique_dst_ports > 1.0:
                evidence.append(f"Targeted unique destination ports: {int(fv.unique_dst_ports)} distinct ports")
                snapshot["unique_dst_ports"] = fv.unique_dst_ports
            if fv.dst_port_fanout > 0.5:
                evidence.append(f"Destination port fan-out rate: {fv.dst_port_fanout:.2f} ports/sec")
                snapshot["dst_port_fanout"] = fv.dst_port_fanout
            if fv.unique_dst_hosts > 1.0:
                evidence.append(f"Horizontal sweep hosts: {int(fv.unique_dst_hosts)} target hosts (out-degree: {int(fv.src_out_degree)})")
                snapshot["unique_dst_hosts"] = fv.unique_dst_hosts
            if fv.conn_attempts > 1.0:
                evidence.append(f"Connection attempts: {int(fv.conn_attempts)} attempts (failed/rejected ratio: {fv.failed_conn_ratio * 100:.1f}%)")
                snapshot["conn_attempts"] = fv.conn_attempts
                snapshot["failed_conn_ratio"] = fv.failed_conn_ratio
            primary_reason = f"Port scanning and host reconnaissance activity from source (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "DGA_DNS_TUNNELLING":
            if fv.shannon_entropy_mean > 2.5:
                evidence.append(f"DNS query character entropy: {fv.shannon_entropy_mean:.2f} bits (randomness threshold: >3.40 bits)")
                snapshot["shannon_entropy_mean"] = fv.shannon_entropy_mean
            if fv.query_len_mean > 15.0:
                evidence.append(f"Average DNS query length: {fv.query_len_mean:.1f} characters")
                snapshot["query_len_mean"] = fv.query_len_mean
            if fv.txt_record_ratio > 0.2:
                evidence.append(f"Suspicious TXT record query ratio: {fv.txt_record_ratio * 100:.1f}%")
                snapshot["txt_record_ratio"] = fv.txt_record_ratio
            if fv.ngram_log_likelihood < -3.0:
                evidence.append(f"English bigram log-likelihood score: {fv.ngram_log_likelihood:.2f} (unpronounceable algorithmic domain)")
                snapshot["ngram_log_likelihood"] = fv.ngram_log_likelihood
            if fv.query_frequency > 1.0:
                evidence.append(f"DNS query frequency: {fv.query_frequency:.1f} queries/sec")
                snapshot["query_frequency"] = fv.query_frequency
            primary_reason = f"Algorithmic domain generation (DGA) or DNS covert data tunnelling (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "C2_BEACONING":
            if fv.iat_mean > 0.0:
                evidence.append(f"Mean connection inter-arrival time (IAT): {fv.iat_mean:.3f} seconds")
                snapshot["iat_mean"] = fv.iat_mean
            if fv.iat_cv < 0.30:
                evidence.append(f"Low timing jitter (Coefficient of Variation): {fv.iat_cv:.4f} (automated heartbeat threshold: <0.15)")
                snapshot["iat_cv"] = fv.iat_cv
            if fv.periodicity_score > 0.05:
                evidence.append(f"Dominant FFT periodicity spectral power: {fv.periodicity_score:.3f}")
                snapshot["periodicity_score"] = fv.periodicity_score
            if fv.repeated_conn_count > 1.0:
                evidence.append(f"Persistent connection count to destination: {int(fv.repeated_conn_count)} sessions ({fv.repeated_dst_freq:.1f} conns/min)")
                snapshot["repeated_conn_count"] = fv.repeated_conn_count
            primary_reason = f"Automated periodic Command & Control (C2) beaconing heartbeat (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "DATA_EXFILTRATION":
            evidence.append(f"Total outbound bytes: {int(fv.outbound_bytes)} bytes vs inbound: {int(fv.inbound_bytes)} bytes")
            evidence.append(f"Outbound/Inbound volume ratio: {fv.out_in_byte_ratio:.1f}x (asymmetry index: {fv.asymmetric_traffic_score:+.2f})")
            if fv.outbound_rate > 1000.0:
                evidence.append(f"Outbound transfer rate: {fv.outbound_rate:.0f} bytes/sec")
            snapshot["outbound_bytes"] = fv.outbound_bytes
            snapshot["out_in_byte_ratio"] = fv.out_in_byte_ratio
            snapshot["asymmetric_traffic_score"] = fv.asymmetric_traffic_score
            primary_reason = f"Unauthorized high-volume outbound data transfer and exfiltration (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "ENCRYPTED_MALWARE":
            if fv.tls_version_num > 0.0:
                evidence.append(f"TLS Protocol Version: v{fv.tls_version_num:.1f}")
                snapshot["tls_version_num"] = fv.tls_version_num
            if fv.has_tls_sni == 0.0:
                evidence.append("Direct IP TLS connection: handshake initiated without cleartext Server Name Indication (SNI)")
                snapshot["has_tls_sni"] = 0.0
            if fv.pkt_size_entropy > 0.0:
                evidence.append(f"Packet size distribution entropy: {fv.pkt_size_entropy:.2f} bits (mean size: {fv.pkt_size_mean:.1f} bytes)")
                snapshot["pkt_size_entropy"] = fv.pkt_size_entropy
            primary_reason = f"Suspicious encrypted communication pipeline without SNI metadata (confidence: {fusion.confidence * 100:.1f}%)"

        elif category == "UNKNOWN_ANOMALY":
            evidence.append(f"Isolation Forest raw anomaly score: {fusion.if_anomaly_score:.6f} (threshold: {fusion.if_threshold:.6f})")
            if fv.packet_rate > 10.0:
                evidence.append(f"Observed packet rate: {fv.packet_rate:.1f} pkts/s")
            snapshot["if_anomaly_score"] = fusion.if_anomaly_score
            primary_reason = f"Unsupervised network anomaly detected without matching known signature (confidence: {fusion.confidence * 100:.1f}%)"

        else:
            evidence.append("Normal network behavior with balanced bidirectional parameters.")
            primary_reason = "Normal benign communication session."

        # Include behavioral detector evidence strings if present
        for det in fusion.behavioral_results:
            if det.triggered and det.human_readable_reason not in evidence:
                evidence.append(f"[{det.category}] {det.human_readable_reason}")

        return evidence, primary_reason, snapshot

class AlertEngine:
    """
    Central Alert Engine managing severity assignment, sliding-window deduplication,
    and alert store persistence.
    """
    def __init__(self, dedup_window_sec: float = 30.0, max_alert_history: int = 10_000):
        self.dedup_window_sec = dedup_window_sec
        self.max_alert_history = max_alert_history
        self._lock = threading.Lock()
        
        # Alert Store: list of SecurityAlert_v2
        self._alerts: List[SecurityAlert_v2] = []
        self._alert_lookup: Dict[str, SecurityAlert_v2] = {}
        
        # Deduplication Tracker: correlation_key -> (alert_id, last_seen)
        self._active_correlations: Dict[str, str] = {}
        self._total_events_processed: int = 0

    @classmethod
    def resolve_severity(cls, threat_class: str, confidence: float, fv: TelemetryFeatureVector_v2) -> AlertSeverity:
        """
        Deterministic Risk Severity Resolution:
        - CRITICAL: Volumetric DDoS, massive data exfiltration (>10MB), high-confidence C2 (>0.85).
        - HIGH: Port scans touching >20 ports, DGA/DNS tunnels, Encrypted malware C2.
        - MEDIUM: Unknown anomalies, moderate port scans, moderate beaconing.
        - LOW: Single-event anomalies with low volume.
        - INFO: Verified benign sessions.
        """
        if threat_class == "BENIGN":
            return AlertSeverity.INFO

        if threat_class == "DDOS":
            if fv.packet_rate >= 500.0 or fv.dst_in_degree >= 20.0 or confidence >= 0.90:
                return AlertSeverity.CRITICAL
            return AlertSeverity.HIGH

        if threat_class == "DATA_EXFILTRATION":
            if fv.outbound_bytes >= 10_000_000.0 or fv.outbound_rate >= 100_000.0:
                return AlertSeverity.CRITICAL
            return AlertSeverity.HIGH

        if threat_class == "C2_BEACONING":
            if confidence >= 0.85 or fv.periodicity_score >= 0.20:
                return AlertSeverity.CRITICAL
            return AlertSeverity.HIGH

        if threat_class == "PORT_SCAN":
            if fv.unique_dst_ports >= 25.0 or fv.dst_port_fanout >= 10.0:
                return AlertSeverity.HIGH
            return AlertSeverity.MEDIUM

        if threat_class in ("DGA_DNS_TUNNELLING", "ENCRYPTED_MALWARE"):
            return AlertSeverity.HIGH if confidence >= 0.80 else AlertSeverity.MEDIUM

        if threat_class == "UNKNOWN_ANOMALY":
            return AlertSeverity.MEDIUM if confidence >= 0.70 else AlertSeverity.LOW

        return AlertSeverity.LOW

    def process_detection(self, fv: TelemetryFeatureVector_v2, fusion: FusionResult) -> Tuple[SecurityAlert_v2, bool]:
        """
        Processes a detection event, checks deduplication window, and returns (alert, is_new).
        If event is within deduplication window for same (src_ip, dst_ip, threat_class),
        the existing alert is updated and correlated without generating duplicate noise.
        """
        with self._lock:
            self._total_events_processed += 1
            now = fv.timestamp if fv.timestamp > 0 else time.time()
            now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

            # Correlation Key: (src_ip, dst_ip, threat_class)
            parts = fv.flow_id.split(" -> ")
            src_ip = parts[0].split(":")[0] if len(parts) > 0 else "0.0.0.0"
            dst_ip = parts[1].split(":")[0] if len(parts) > 1 else "0.0.0.0"
            correlation_key = f"{src_ip}|{dst_ip}|{fusion.threat_label}"

            # Check if active correlation exists
            if correlation_key in self._active_correlations:
                existing_id = self._active_correlations[correlation_key]
                existing_alert = self._alert_lookup.get(existing_id)
                if existing_alert and (now - existing_alert.last_seen) <= self.dedup_window_sec:
                    # Correlate into existing alert
                    existing_alert.occurrence_count += 1
                    existing_alert.last_seen = now
                    # Update confidence if higher
                    if fusion.confidence > existing_alert.confidence_score:
                        existing_alert.confidence_score = fusion.confidence
                    return existing_alert, False

            # Create new SecurityAlert_v2
            evidence, primary_reason, snapshot = EvidenceGenerator.generate_evidence(fv, fusion)
            severity = self.resolve_severity(fusion.threat_label, fusion.confidence, fv)
            alert_id = f"ALT-{datetime.fromtimestamp(now, tz=timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

            triggered_det_names = [d.detector_name for d in fusion.behavioral_results if d.triggered]

            new_alert = SecurityAlert_v2(
                alert_id=alert_id,
                schema_version="v2.0",
                timestamp=now,
                timestamp_iso=now_iso,
                flow_id=fv.flow_id,
                threat_class=fusion.threat_label,
                confidence_score=fusion.confidence,
                severity=severity,
                supporting_evidence=evidence,
                primary_reason=primary_reason,
                classifier_probability=fusion.rf_confidence if fusion.rf_prediction == fusion.threat_label else None,
                rf_class_probabilities=fusion.rf_class_probabilities,
                anomaly_score=fusion.if_anomaly_score,
                if_is_anomalous=fusion.if_is_anomalous,
                triggered_detectors=triggered_det_names,
                feature_snapshot=snapshot,
                occurrence_count=1,
                first_seen=now,
                last_seen=now,
                model_version="v2.0",
                feature_schema_version="2.0.0",
                detection_method=fusion.detection_method
            )

            # Store alert
            self._alerts.append(new_alert)
            self._alert_lookup[alert_id] = new_alert
            self._active_correlations[correlation_key] = alert_id

            if len(self._alerts) > self.max_alert_history:
                evicted = self._alerts.pop(0)
                self._alert_lookup.pop(evicted.alert_id, None)

            return new_alert, True

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        threat_class: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        exclude_benign: bool = False
    ) -> List[SecurityAlert_v2]:
        with self._lock:
            filtered = list(self._alerts)
            if exclude_benign:
                filtered = [a for a in filtered if a.threat_class != "BENIGN"]
            if threat_class:
                filtered = [a for a in filtered if a.threat_class.upper() == threat_class.upper()]
            if severity:
                filtered = [a for a in filtered if a.severity == severity]
            
            # Reverse order (latest first)
            filtered.reverse()
            return filtered[offset : offset + limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[SecurityAlert_v2]:
        with self._lock:
            return self._alert_lookup.get(alert_id)

    def get_statistics(self) -> AlertStatistics:
        with self._lock:
            total_alerts = len(self._alerts)
            events = max(1, self._total_events_processed)
            savings = round(max(0.0, 1.0 - (total_alerts / events)), 4)

            sev_counts = Counter(a.severity.value for a in self._alerts)
            class_counts = Counter(a.threat_class for a in self._alerts)
            method_counts = Counter(a.detection_method for a in self._alerts)
            
            active_threats = sum(1 for a in self._alerts if a.threat_class != "BENIGN")
            now_iso = datetime.now(timezone.utc).isoformat()

            return AlertStatistics(
                total_alerts=total_alerts,
                total_events_processed=self._total_events_processed,
                deduplication_savings_ratio=savings,
                severity_breakdown=dict(sev_counts),
                threat_class_breakdown=dict(class_counts),
                detection_method_breakdown=dict(method_counts),
                active_threats_count=active_threats,
                last_updated_iso=now_iso
            )
