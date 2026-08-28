"""
Versioned Feature Schema (v1) for SIH 2026 Cyber Threat Detection Engine.
Defines typed schemas, numerical vector conversion, and documentation metadata.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import numpy as np

class FeatureMetadata(BaseModel):
    name: str
    dtype: str
    category: str
    meaning: str
    calculation: str
    threat_relevance: str

FEATURE_CATALOG: List[FeatureMetadata] = [
    # 1. Volumetric / DDoS Features
    FeatureMetadata(
        name="packet_rate",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Packets transmitted per second within active window",
        calculation="total_packets / window_duration_sec",
        threat_relevance="High spikes indicate volumetric flooding attacks (e.g. UDP/SYN flood)"
    ),
    FeatureMetadata(
        name="byte_rate",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Bytes transmitted per second within active window",
        calculation="total_bytes / window_duration_sec",
        threat_relevance="Indicates bandwidth exhaustion attacks or high-volume data exfiltration"
    ),
    FeatureMetadata(
        name="syn_ratio",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Ratio of TCP SYN packets to total flow packets",
        calculation="syn_packets / max(1, total_tcp_packets)",
        threat_relevance="Approaches 1.0 during unidirectional SYN flood attacks"
    ),
    FeatureMetadata(
        name="ack_ratio",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Ratio of TCP ACK packets to total flow packets",
        calculation="ack_packets / max(1, total_tcp_packets)",
        threat_relevance="Assesses handshake completion and ACK-flood anomalies"
    ),
    FeatureMetadata(
        name="rst_ratio",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Ratio of TCP RST packets to total flow packets",
        calculation="rst_packets / max(1, total_tcp_packets)",
        threat_relevance="Elevated in scanner teardowns and connection termination storms"
    ),
    FeatureMetadata(
        name="fin_ratio",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Ratio of TCP FIN packets to total flow packets",
        calculation="fin_packets / max(1, total_tcp_packets)",
        threat_relevance="Used to detect FIN-scan and teardown floods"
    ),
    FeatureMetadata(
        name="syn_ack_ratio",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Ratio of SYN+ACK packets to total flow packets",
        calculation="syn_ack_packets / max(1, total_tcp_packets)",
        threat_relevance="Monitors server response reflection floods"
    ),
    FeatureMetadata(
        name="src_ip_entropy",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Shannon entropy of source IP addresses targeting this destination",
        calculation="-sum(p_i * log2(p_i)) over source IP distribution",
        threat_relevance="High entropy indicates distributed spoofed-source DDoS"
    ),
    FeatureMetadata(
        name="unique_src_ips",
        dtype="float64",
        category="Volumetric / DDoS",
        meaning="Count of distinct source IPs contacting destination within window",
        calculation="len(set(src_ips))",
        threat_relevance="Distinguishes single-host floods from distributed DDoS"
    ),

    # 2. Port Scanning / Reconnaissance Features
    FeatureMetadata(
        name="unique_dst_ports",
        dtype="float64",
        category="Reconnaissance / Scan",
        meaning="Count of unique destination ports targeted by source IP",
        calculation="len(set(dst_ports))",
        threat_relevance="Direct indicator of vertical port scanning"
    ),
    FeatureMetadata(
        name="unique_dst_hosts",
        dtype="float64",
        category="Reconnaissance / Scan",
        meaning="Count of unique destination hosts targeted by source IP",
        calculation="len(set(dst_hosts))",
        threat_relevance="Direct indicator of horizontal network sweep / reconnaissance"
    ),
    FeatureMetadata(
        name="dst_port_fanout",
        dtype="float64",
        category="Reconnaissance / Scan",
        meaning="Rate of unique destination ports contacted per second",
        calculation="unique_dst_ports / window_duration_sec",
        threat_relevance="High fanout velocity signifies fast automated scanning tools (Nmap/Masscan)"
    ),
    FeatureMetadata(
        name="dst_host_fanout",
        dtype="float64",
        category="Reconnaissance / Scan",
        meaning="Rate of unique destination hosts contacted per second",
        calculation="unique_dst_hosts / window_duration_sec",
        threat_relevance="Identifies active worm propagation and subnet sweeping"
    ),
    FeatureMetadata(
        name="connection_attempt_rate",
        dtype="float64",
        category="Reconnaissance / Scan",
        meaning="Initial connection attempts (SYN packets) per second from source IP",
        calculation="syn_count / window_duration_sec",
        threat_relevance="Measures brute-force probing and aggressive scanner velocity"
    ),

    # 3. C2 Beaconing Features
    FeatureMetadata(
        name="iat_mean",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Mean packet inter-arrival time in seconds",
        calculation="mean(diff(timestamps))",
        threat_relevance="Establishes base communication heartbeat frequency"
    ),
    FeatureMetadata(
        name="iat_std",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Standard deviation of packet inter-arrival times",
        calculation="std(diff(timestamps))",
        threat_relevance="Low standard deviation indicates rigid, non-human periodic polling"
    ),
    FeatureMetadata(
        name="iat_cv",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Coefficient of Variation of inter-arrival times (Jitter Metric)",
        calculation="iat_std / max(1e-5, iat_mean)",
        threat_relevance="Values < 0.15 strongly signify automated C2 beacon heartbeats"
    ),
    FeatureMetadata(
        name="iat_skewness",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Skewness of the inter-arrival time distribution",
        calculation="E[((X - mu) / sigma)^3]",
        threat_relevance="Detects asymmetry in beacon sleep-wake cycles"
    ),
    FeatureMetadata(
        name="fft_peak_magnitude",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Dominant normalized frequency power peak from FFT spectral analysis",
        calculation="max(abs(fft(iat_series))[1:]) / sum(abs(fft))",
        threat_relevance="Strong spectral peaks reveal hidden periodic beacons even with jitter"
    ),
    FeatureMetadata(
        name="autocorr_max_peak",
        dtype="float64",
        category="Botnet C2 Beaconing",
        meaning="Maximum secondary autocorrelation peak across time lags",
        calculation="max(autocorr(iat_series)[lag > 0])",
        threat_relevance="Confirms repeating temporal patterns characteristic of C2 frameworks"
    ),

    # 4. DNS / DGA / Tunnelling Features
    FeatureMetadata(
        name="dns_query_len_mean",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Average length of queried domain names in flow",
        calculation="mean(len(query_domain))",
        threat_relevance="Elevated domain lengths occur in DNS exfiltration tunnels"
    ),
    FeatureMetadata(
        name="dns_entropy_mean",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Average Shannon character entropy of requested domain names",
        calculation="-sum(p_i * log2(p_i)) over domain characters",
        threat_relevance="Values > 3.8 reveal pseudo-random DGA algorithmic domains"
    ),
    FeatureMetadata(
        name="dns_txt_record_ratio",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Proportion of DNS queries requesting TXT or NULL records",
        calculation="txt_queries / max(1, total_dns_queries)",
        threat_relevance="High TXT ratio signifies DNS tunnelling payloads (e.g. dnscat2/iodine)"
    ),
    FeatureMetadata(
        name="dns_consonant_ratio",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Proportion of consonants in query domain names",
        calculation="consonant_count / max(1, total_letters)",
        threat_relevance="Abnormal consonant/vowel balance distinguishes DGAs from natural words"
    ),
    FeatureMetadata(
        name="dns_digit_ratio",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Proportion of numerical digits in domain names",
        calculation="digit_count / max(1, len(domain))",
        threat_relevance="Hex/Base32 encoded subdomains exhibit high digit densities"
    ),
    FeatureMetadata(
        name="dns_ngram_score",
        dtype="float64",
        category="DNS / DGA / Tunnelling",
        meaning="Bi-gram log-likelihood score against baseline English language corpus",
        calculation="mean(log P(c_i, c_i+1))",
        threat_relevance="Low log-likelihood signifies unpronounceable algorithmic domains"
    ),

    # 5. Encrypted Traffic Features (TLS/QUIC - Zero Decryption)
    FeatureMetadata(
        name="pkt_size_mean",
        dtype="float64",
        category="Encrypted Traffic",
        meaning="Mean packet wire size in bytes",
        calculation="mean(wire_lengths)",
        threat_relevance="Characterizes payload footprint across protocols"
    ),
    FeatureMetadata(
        name="pkt_size_std",
        dtype="float64",
        category="Encrypted Traffic",
        meaning="Standard deviation of packet wire sizes",
        calculation="std(wire_lengths)",
        threat_relevance="Distinguishes fixed-size keepalive beacons from interactive browsing"
    ),
    FeatureMetadata(
        name="pkt_size_entropy",
        dtype="float64",
        category="Encrypted Traffic",
        meaning="Shannon entropy of packet size distribution (SPLT)",
        calculation="-sum(p(size) * log2(p(size)))",
        threat_relevance="Reveals structural variance in encrypted protocol exchanges"
    ),
    FeatureMetadata(
        name="has_tls_sni",
        dtype="float64",
        category="Encrypted Traffic",
        meaning="Binary flag indicating presence of cleartext TLS SNI in ClientHello",
        calculation="1.0 if sni is present else 0.0",
        threat_relevance="Missing SNI in port 443 traffic often indicates raw malware C2 channels"
    ),

    # 6. Exfiltration & Flow Asymmetry Features
    FeatureMetadata(
        name="outbound_bytes_total",
        dtype="float64",
        category="Data Exfiltration",
        meaning="Cumulative volume of bytes transmitted outbound in flow",
        calculation="sum(outbound_wire_lengths)",
        threat_relevance="Detects abnormal large-volume data theft"
    ),
    FeatureMetadata(
        name="byte_velocity",
        dtype="float64",
        category="Data Exfiltration",
        meaning="Acceleration/rate of outbound byte transfer over short sub-windows",
        calculation="delta(bytes) / delta(time)",
        threat_relevance="Captures sudden bursty exfiltration transfers"
    ),
    FeatureMetadata(
        name="flow_duration_sec",
        dtype="float64",
        category="Flow Overview",
        meaning="Total active duration of the flow in seconds",
        calculation="last_seen_ts - first_seen_ts",
        threat_relevance="Contextual feature for long-lived C2 vs transient scan flows"
    )
]

ORDERED_FEATURE_NAMES: List[str] = [f.name for f in FEATURE_CATALOG]

class FeatureVector_v1(BaseModel):
    """
    Version 1 Feature Vector Schema.
    Immutable, typed representation of all extracted features for a flow/window.
    """
    flow_id: str
    timestamp: float
    window_duration_sec: float = 1.0

    # 1. Volumetric / DDoS
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    syn_ratio: float = 0.0
    ack_ratio: float = 0.0
    rst_ratio: float = 0.0
    fin_ratio: float = 0.0
    syn_ack_ratio: float = 0.0
    src_ip_entropy: float = 0.0
    unique_src_ips: float = 0.0

    # 2. Port Scanning / Reconnaissance
    unique_dst_ports: float = 0.0
    unique_dst_hosts: float = 0.0
    dst_port_fanout: float = 0.0
    dst_host_fanout: float = 0.0
    connection_attempt_rate: float = 0.0

    # 3. C2 Beaconing
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_cv: float = 0.0
    iat_skewness: float = 0.0
    fft_peak_magnitude: float = 0.0
    autocorr_max_peak: float = 0.0

    # 4. DNS / DGA / Tunnelling
    dns_query_len_mean: float = 0.0
    dns_entropy_mean: float = 0.0
    dns_txt_record_ratio: float = 0.0
    dns_consonant_ratio: float = 0.0
    dns_digit_ratio: float = 0.0
    dns_ngram_score: float = 0.0

    # 5. Encrypted Traffic
    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0
    pkt_size_entropy: float = 0.0
    has_tls_sni: float = 0.0

    # 6. Exfiltration & Overview
    outbound_bytes_total: float = 0.0
    byte_velocity: float = 0.0
    flow_duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        """Convert features to a dictionary of {feature_name: value}."""
        return {name: getattr(self, name) for name in ORDERED_FEATURE_NAMES}

    def to_numpy(self) -> np.ndarray:
        """Convert features to a 1D NumPy array for vectorized ML inference."""
        return np.array([getattr(self, name) for name in ORDERED_FEATURE_NAMES], dtype=np.float64)

    @classmethod
    def feature_names(cls) -> List[str]:
        return list(ORDERED_FEATURE_NAMES)
