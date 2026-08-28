"""
Deterministic Behavioral Detection Engine.

Provides modular, explainable detectors across 6 threat categories:
1. DDoS Detector
2. Port Scan Detector
3. DNS / DGA Detector
4. C2 Beaconing Detector
5. Data Exfiltration Detector
6. Encrypted Malware Traffic Detector
"""
import logging
from typing import List, Dict, Any, Optional
from app.detectors.models import BehavioralDetectionResult, BehavioralDetectorsConfig
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

logger = logging.getLogger(__name__)

class BehavioralDetectionEngine:
    """
    Evaluates telemetry feature vectors against deterministic behavioral rules.
    """
    def __init__(self, config: Optional[BehavioralDetectorsConfig] = None):
        self.config = config or BehavioralDetectorsConfig()

    def evaluate_ddos(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Indicator 1: Distributed SYN Flood
        is_syn_flood = (
            fv.syn_ratio >= cfg.ddos_syn_ratio_thresh and
            (fv.src_ip_entropy >= cfg.ddos_src_entropy_thresh or fv.dst_in_degree >= 5.0)
        )
        if is_syn_flood:
            score = max(score, 0.95)
            reasons.append(
                f"Distributed SYN flood pattern: SYN ratio {fv.syn_ratio:.2f} >= {cfg.ddos_syn_ratio_thresh:.2f} "
                f"with source IP entropy {fv.src_ip_entropy:.2f} bits "
                f"({int(fv.unique_src_count)} distinct sources, in-degree {int(fv.dst_in_degree)})."
            )
            ev["syn_ratio"] = fv.syn_ratio
            ev["src_ip_entropy"] = fv.src_ip_entropy
            ev["unique_src_count"] = fv.unique_src_count
            ev["dst_in_degree"] = fv.dst_in_degree

        # Indicator 2: High Packet Rate Flood
        if fv.packet_rate >= cfg.ddos_packet_rate_thresh:
            score = max(score, 0.85)
            reasons.append(f"High volumetric packet rate: {fv.packet_rate:.1f} pkts/s >= {cfg.ddos_packet_rate_thresh:.1f} pkts/s.")
            ev["packet_rate"] = fv.packet_rate

        # Indicator 3: UDP Reflection / Amplification (Surge rate + high response amplification)
        if fv.udp_rate >= cfg.ddos_udp_rate_thresh and fv.byte_amplification_ratio > 3.0:
            score = max(score, 0.90)
            reasons.append(
                f"UDP flood/amplification: rate {fv.udp_rate:.1f} pkts/s >= {cfg.ddos_udp_rate_thresh:.1f} pkts/s "
                f"with amplification ratio {fv.byte_amplification_ratio:.1f}x."
            )
            ev["udp_rate"] = fv.udp_rate
            ev["byte_amplification_ratio"] = fv.byte_amplification_ratio

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Normal packet volume and balanced flag distribution."
        
        return BehavioralDetectionResult(
            detector_name="ddos_behavioral_detector",
            category="DDoS",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_port_scan(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Indicator 1: Vertical Port Scan (many ports on one target, >= 10 ports + high fanout)
        is_vertical_scan = (fv.unique_dst_ports >= cfg.scan_unique_ports_thresh and fv.dst_port_fanout >= cfg.scan_port_fanout_thresh)
        if is_vertical_scan:
            score = max(score, 0.92)
            reasons.append(
                f"Vertical port scan: {int(fv.unique_dst_ports)} unique destination ports targeted "
                f"(fan-out: {fv.dst_port_fanout:.2f} ports/s >= {cfg.scan_port_fanout_thresh:.2f}, "
                f"failed connection ratio: {fv.failed_conn_ratio:.2f})."
            )
            ev["unique_dst_ports"] = fv.unique_dst_ports
            ev["dst_port_fanout"] = fv.dst_port_fanout
            ev["failed_conn_ratio"] = fv.failed_conn_ratio

        # Indicator 2: Horizontal Host Sweep / Subnet Recon (many hosts, >= 8 hosts + high fanout)
        is_horizontal_sweep = (fv.unique_dst_hosts >= cfg.scan_unique_hosts_thresh and fv.dst_host_fanout >= cfg.scan_host_fanout_thresh)
        if is_horizontal_sweep:
            score = max(score, 0.88)
            reasons.append(
                f"Horizontal subnet sweep: {int(fv.unique_dst_hosts)} unique hosts targeted "
                f"(fan-out: {fv.dst_host_fanout:.2f} hosts/s >= {cfg.scan_host_fanout_thresh:.2f}, "
                f"out-degree {int(fv.src_out_degree)})."
            )
            ev["unique_dst_hosts"] = fv.unique_dst_hosts
            ev["dst_host_fanout"] = fv.dst_host_fanout
            ev["src_out_degree"] = fv.src_out_degree

        # Indicator 3: High Attempt Rate with High Failure
        if fv.conn_attempts >= 15.0 and fv.failed_conn_ratio >= cfg.scan_failed_conn_ratio_thresh:
            score = max(score, 0.85)
            reasons.append(
                f"High failed probing rate: {int(fv.conn_attempts)} attempts with {fv.failed_conn_ratio * 100:.1f}% unestablished."
            )
            ev["conn_attempts"] = fv.conn_attempts
            ev["failed_conn_ratio"] = fv.failed_conn_ratio

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Low destination port/host fan-out with normal connection establishment."

        return BehavioralDetectionResult(
            detector_name="port_scan_behavioral_detector",
            category="Port Scanning",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_dns_dga(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Indicator 1: Algorithmically Generated Domain (High Entropy + Low English N-gram Likelihood)
        is_dga_entropy = (fv.shannon_entropy_mean >= cfg.dns_entropy_thresh and fv.query_len_mean >= 15.0)
        is_dga_ngram = (fv.ngram_log_likelihood <= cfg.dns_ngram_ll_thresh and fv.query_len_mean >= 15.0)
        
        if is_dga_entropy or is_dga_ngram:
            score = max(score, 0.90)
            reasons.append(
                f"Algorithmic domain name (DGA): Shannon entropy {fv.shannon_entropy_mean:.2f} bits >= {cfg.dns_entropy_thresh:.2f} "
                f"with English bigram log-likelihood {fv.ngram_log_likelihood:.2f} <= {cfg.dns_ngram_ll_thresh:.2f} "
                f"(query len: {fv.query_len_mean:.1f} chars, unique char ratio: {fv.unique_char_ratio:.2f})."
            )
            ev["shannon_entropy_mean"] = fv.shannon_entropy_mean
            ev["ngram_log_likelihood"] = fv.ngram_log_likelihood
            ev["query_len_mean"] = fv.query_len_mean
            ev["unique_char_ratio"] = fv.unique_char_ratio

        # Indicator 2: DNS Tunnelling (High TXT/NULL Query Ratio or Deep Subdomains)
        if fv.txt_record_ratio >= cfg.dns_txt_ratio_thresh:
            score = max(score, 0.93)
            reasons.append(
                f"Suspicious DNS record abuse: TXT record ratio {fv.txt_record_ratio * 100:.1f}% >= {cfg.dns_txt_ratio_thresh * 100:.1f}% "
                f"(subdomain depth: {fv.subdomain_depth_mean:.1f} labels)."
            )
            ev["txt_record_ratio"] = fv.txt_record_ratio
            ev["subdomain_depth_mean"] = fv.subdomain_depth_mean

        if fv.query_frequency >= cfg.dns_query_freq_thresh and fv.query_len_mean >= 15.0 and fv.shannon_entropy_mean >= 3.0:
            score = max(score, 0.80)
            reasons.append(f"High DNS query burst rate with anomalous entropy: {fv.query_frequency:.1f} queries/s >= {cfg.dns_query_freq_thresh:.1f}.")
            ev["query_frequency"] = fv.query_frequency

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Standard dictionary domain queries with normal DNS record types."

        return BehavioralDetectionResult(
            detector_name="dns_dga_behavioral_detector",
            category="DNS / DGA",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_c2_beaconing(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Indicator 1: Rigid Temporal Heartbeat (Requires >= 5 connections, ultra-low jitter CV OR periodicity peak, interval >= 0.5s)
        has_min_history = (fv.repeated_conn_count >= cfg.c2_min_conn_count)
        is_rigid_heartbeat = (
            (fv.iat_cv <= cfg.c2_iat_cv_thresh or fv.periodicity_score >= cfg.c2_periodicity_thresh) and
            fv.iat_mean >= 0.50 and
            fv.repeated_conn_count >= 5.0
        )

        if has_min_history and is_rigid_heartbeat:
            score = max(score, 0.88)
            reasons.append(
                f"Automated C2 beaconing signal: timing jitter CV {fv.iat_cv:.4f} <= {cfg.c2_iat_cv_thresh:.2f} "
                f"(mean interval: {fv.iat_mean:.3f}s across {int(fv.repeated_conn_count)} connections)."
            )
            ev["iat_mean"] = fv.iat_mean
            ev["iat_cv"] = fv.iat_cv
            ev["periodicity_score"] = fv.periodicity_score
            ev["repeated_conn_count"] = fv.repeated_conn_count

        # Indicator 2: High Repeated Endpoint Check-in Frequency with Low Timing Jitter
        is_frequent_beacon = (
            fv.repeated_dst_freq >= cfg.c2_repeated_dst_freq_thresh and
            fv.repeated_conn_count >= 5.0 and
            fv.iat_cv <= 0.30 and
            fv.periodicity_score >= cfg.c2_periodicity_thresh and
            fv.iat_mean >= 0.50
        )
        if is_frequent_beacon:
            score = max(score, 0.75)
            reasons.append(
                f"Persistent recurring endpoint connections: {fv.repeated_dst_freq:.1f} check-ins/min "
                f"with periodic timing ({int(fv.repeated_conn_count)} total flows)."
            )
            ev["repeated_dst_freq"] = fv.repeated_dst_freq

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Natural human timing variance with non-periodic connection intervals."

        return BehavioralDetectionResult(
            detector_name="c2_beaconing_behavioral_detector",
            category="C2 Beaconing",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_data_exfiltration(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Guard: Inbound server response downlink (e.g. web server sending web pages on port 80/443)
        # Exfiltration is defined as a client endpoint uploading abnormal volumes outward.
        src_port = 0
        if ":" in fv.flow_id:
            try:
                src_port = int(fv.flow_id.split(":")[1].split(" ")[0].split("->")[0].strip())
            except Exception:
                src_port = 0
        is_server_downlink = (src_port in (80, 443, 8080, 53) and fv.outbound_bytes < 100_000)

        # Indicator 1: Strong Outbound Asymmetry & High Out/In Ratio
        is_asymmetric = (
            not is_server_downlink and
            fv.out_in_byte_ratio >= cfg.exfil_out_in_ratio_thresh and
            fv.asymmetric_traffic_score >= cfg.exfil_asym_score_thresh and
            fv.outbound_bytes >= cfg.exfil_min_outbound_bytes
        )

        if is_asymmetric:
            score = max(score, 0.90)
            reasons.append(
                f"Heavy data exfiltration pattern: outbound/inbound byte ratio {fv.out_in_byte_ratio:.1f}x >= {cfg.exfil_out_in_ratio_thresh:.1f}x "
                f"with asymmetry index {fv.asymmetric_traffic_score:+.2f} "
                f"({int(fv.outbound_bytes)} outbound bytes vs {int(fv.inbound_bytes)} inbound bytes)."
            )
            ev["outbound_bytes"] = fv.outbound_bytes
            ev["inbound_bytes"] = fv.inbound_bytes
            ev["out_in_byte_ratio"] = fv.out_in_byte_ratio
            ev["asymmetric_traffic_score"] = fv.asymmetric_traffic_score

        # Indicator 2: High Outbound Upload Throughput (requires minimum 25KB total transfer)
        if not is_server_downlink and fv.outbound_rate >= cfg.exfil_outbound_rate_thresh and fv.outbound_bytes >= cfg.exfil_min_outbound_bytes:
            score = max(score, 0.85)
            reasons.append(f"High outbound transfer velocity: {fv.outbound_rate:.0f} B/s >= {cfg.exfil_outbound_rate_thresh:.0f} B/s.")
            ev["outbound_rate"] = fv.outbound_rate

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Standard download/inbound-dominant traffic volume ratio."

        return BehavioralDetectionResult(
            detector_name="data_exfiltration_behavioral_detector",
            category="Data Exfiltration",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_encrypted_traffic(self, fv: TelemetryFeatureVector_v2) -> BehavioralDetectionResult:
        cfg = self.config
        ev = {}
        reasons = []
        score = 0.0

        # Indicator 1: Direct IP HTTPS connection without SNI header (client connecting to server on 443/8443)
        dst_port = 0
        if "->" in fv.flow_id and ":" in fv.flow_id:
            try:
                dst_port = int(fv.flow_id.split("->")[1].split("[")[0].split(":")[1].strip())
            except Exception:
                dst_port = 0

        if dst_port in (443, 8443) and fv.tls_version_num > 0.0 and fv.has_tls_sni == 0.0:
            score = max(score, 0.75)
            reasons.append(
                f"Direct IP TLS connection: TLS v{fv.tls_version_num:.1f} handshake established without Server Name Indication (SNI)."
            )
            ev["tls_version_num"] = fv.tls_version_num
            ev["has_tls_sni"] = fv.has_tls_sni

        # Indicator 2: Unidirectional Low-Entropy Packet Footprint (Covert Encrypted Tunnel / C2 without SNI)
        if fv.tls_version_num > 0.0 and fv.has_tls_sni == 0.0 and fv.directionality_ratio >= cfg.enc_directionality_thresh and fv.pkt_size_entropy <= cfg.enc_pkt_size_entropy_thresh:
            score = max(score, 0.80)
            reasons.append(
                f"Unidirectional covert encrypted pipeline: {fv.directionality_ratio * 100:.1f}% outbound packets "
                f"without SNI and low packet size entropy {fv.pkt_size_entropy:.2f} bits <= {cfg.enc_pkt_size_entropy_thresh:.2f}."
            )
            ev["directionality_ratio"] = fv.directionality_ratio
            ev["pkt_size_entropy"] = fv.pkt_size_entropy

        triggered = len(reasons) > 0
        reason_str = " | ".join(reasons) if triggered else "Standard TLS handshake with valid SNI and balanced packet sizes."

        return BehavioralDetectionResult(
            detector_name="encrypted_malware_behavioral_detector",
            category="Encrypted Malware",
            triggered=triggered,
            score=round(score, 3),
            supporting_evidence=ev,
            human_readable_reason=reason_str
        )

    def evaluate_all(self, fv: TelemetryFeatureVector_v2) -> List[BehavioralDetectionResult]:
        """Runs all 6 behavioral detectors and returns list of detection results."""
        return [
            self.evaluate_ddos(fv),
            self.evaluate_port_scan(fv),
            self.evaluate_dns_dga(fv),
            self.evaluate_c2_beaconing(fv),
            self.evaluate_data_exfiltration(fv),
            self.evaluate_encrypted_traffic(fv)
        ]
