"""
Production Telemetry Feature Schema (v2) for SIH 2026 Threat Detection.

Defines the 42-feature numerical schema generated from Zeek & Suricata telemetry,
supporting both structured explainability dictionaries and dense NumPy vectors.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import numpy as np

class FeatureFieldDef(BaseModel):
    name: str
    datatype: str
    category: str
    meaning: str
    calculation: str
    window: str
    threat_relevance: str

TELEMETRY_FEATURE_DEFS: List[FeatureFieldDef] = [
    # ── 1. DDoS Features ──────────────────────────────────────────────────────
    FeatureFieldDef(
        name="packet_rate",
        datatype="float64",
        category="DDoS",
        meaning="Packets transmitted per second in active flow window",
        calculation="(orig_pkts + resp_pkts) / max(1e-3, duration)",
        window="flow_window (1.0s - 30.0s)",
        threat_relevance="Massive packet spikes signify volumetric DDoS floods."
    ),
    FeatureFieldDef(
        name="byte_rate",
        datatype="float64",
        category="DDoS",
        meaning="Bytes transmitted per second in active flow window",
        calculation="(orig_bytes + resp_bytes) / max(1e-3, duration)",
        window="flow_window (1.0s - 30.0s)",
        threat_relevance="High bandwidth consumption indicates pipe-saturating flood attacks."
    ),
    FeatureFieldDef(
        name="syn_rate",
        datatype="float64",
        category="DDoS",
        meaning="Initial SYN attempt rate per second",
        calculation="syn_count / max(1e-3, duration)",
        window="flow_window",
        threat_relevance="High SYN rates mark aggressive SYN flood attacks."
    ),
    FeatureFieldDef(
        name="syn_ratio",
        datatype="float64",
        category="DDoS",
        meaning="Ratio of SYN packets to total flow packets",
        calculation="syn_packets / max(1, total_packets)",
        window="flow_window",
        threat_relevance="Approaches 1.0 during unidirectional SYN flood attacks."
    ),
    FeatureFieldDef(
        name="ack_ratio",
        datatype="float64",
        category="DDoS",
        meaning="Ratio of ACK packets to total flow packets",
        calculation="ack_packets / max(1, total_packets)",
        window="flow_window",
        threat_relevance="Low in SYN floods; elevated in ACK reflection attacks."
    ),
    FeatureFieldDef(
        name="rst_ratio",
        datatype="float64",
        category="DDoS",
        meaning="Ratio of RST packets to total flow packets",
        calculation="rst_packets / max(1, total_packets)",
        window="flow_window",
        threat_relevance="Elevated in scanner teardowns and connection termination storms."
    ),
    FeatureFieldDef(
        name="udp_rate",
        datatype="float64",
        category="DDoS",
        meaning="UDP packet transmission rate per second",
        calculation="udp_pkts / max(1e-3, duration) if protocol == 'UDP' else 0.0",
        window="flow_window",
        threat_relevance="Surges indicate UDP reflection/amplification floods (NTP, DNS, CLDAP)."
    ),
    FeatureFieldDef(
        name="unique_src_count",
        datatype="float64",
        category="DDoS",
        meaning="Unique source IPs contacting target destination in window",
        calculation="count(distinct(src_ips)) targeting dst_ip in window",
        window="sliding_host_window (30.0s)",
        threat_relevance="Distinguishes single-source floods from distributed botnet attacks."
    ),
    FeatureFieldDef(
        name="src_ip_entropy",
        datatype="float64",
        category="DDoS",
        meaning="Shannon entropy of source IPs targeting destination",
        calculation="-sum(p_i * log2(p_i)) over src_ip distribution",
        window="sliding_host_window (30.0s)",
        threat_relevance="High entropy signifies heavily distributed spoofed-source DDoS."
    ),
    FeatureFieldDef(
        name="dest_concentration",
        datatype="float64",
        category="DDoS",
        meaning="Fraction of all network packets directed at this single destination",
        calculation="dst_packets / max(1, total_network_packets)",
        window="sliding_global_window (30.0s)",
        threat_relevance="High concentration reveals targeted victim host under heavy flood."
    ),
    FeatureFieldDef(
        name="byte_amplification_ratio",
        datatype="float64",
        category="DDoS",
        meaning="Ratio of response bytes to origin request bytes",
        calculation="resp_bytes / max(1.0, orig_bytes)",
        window="flow_window",
        threat_relevance="Values >> 10 signify active UDP reflection/amplification."
    ),

    # ── 2. C2 Beaconing Features ──────────────────────────────────────────────
    FeatureFieldDef(
        name="iat_min",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Minimum inter-arrival time between consecutive connections",
        calculation="min(diff(timestamps))",
        window="flow_history (up to 1000 events)",
        threat_relevance="Identifies rigid timing floors in botnet polling intervals."
    ),
    FeatureFieldDef(
        name="iat_max",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Maximum inter-arrival time between consecutive connections",
        calculation="max(diff(timestamps))",
        window="flow_history",
        threat_relevance="Assesses upper bound of sleep/wake cycles."
    ),
    FeatureFieldDef(
        name="iat_mean",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Mean packet/connection inter-arrival time in seconds",
        calculation="mean(diff(timestamps))",
        window="flow_history",
        threat_relevance="Establishes base heartbeat interval of malware beaconing."
    ),
    FeatureFieldDef(
        name="iat_std",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Standard deviation of inter-arrival times",
        calculation="std(diff(timestamps))",
        window="flow_history",
        threat_relevance="Ultra-low variance indicates non-human automated heartbeat."
    ),
    FeatureFieldDef(
        name="iat_cv",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Coefficient of Variation of IAT (Jitter Metric)",
        calculation="iat_std / max(1e-5, iat_mean)",
        window="flow_history",
        threat_relevance="Values < 0.15 strongly signify rigid C2 framework beaconing."
    ),
    FeatureFieldDef(
        name="periodicity_score",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Dominant FFT spectral power peak fraction",
        calculation="max(abs(fft(centered_iats))) / sum(abs(fft))",
        window="flow_history",
        threat_relevance="Detects periodic beaconing even when jitter is added."
    ),
    FeatureFieldDef(
        name="repeated_dst_freq",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Connection frequency to this specific external endpoint per minute",
        calculation="flow_count_to_dst / (window_duration / 60.0)",
        window="sliding_host_window (300.0s)",
        threat_relevance="Repeated persistent check-ins to identical C2 servers."
    ),
    FeatureFieldDef(
        name="flow_duration",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Total active duration of the connection in seconds",
        calculation="last_seen_ts - first_seen_ts",
        window="flow_window",
        threat_relevance="Short, recurring bursts characterize classic HTTP/TLS beacons."
    ),
    FeatureFieldDef(
        name="repeated_conn_count",
        datatype="float64",
        category="C2 Beaconing",
        meaning="Total number of discrete connection sessions established to same endpoint",
        calculation="count(flows_between_pair)",
        window="sliding_host_window (300.0s)",
        threat_relevance="High session repetition without user interaction indicates malware."
    ),

    # ── 3. DGA / DNS Tunnelling Features ──────────────────────────────────────
    FeatureFieldDef(
        name="query_len_mean",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Average character length of requested DNS domain names",
        calculation="mean(len(query_domain))",
        window="dns_buffer (last 100 queries)",
        threat_relevance="Significantly elevated in DNS data exfiltration tunnels."
    ),
    FeatureFieldDef(
        name="shannon_entropy_mean",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Average Shannon character entropy of requested domain names",
        calculation="-sum(p_c * log2(p_c)) over domain characters",
        window="dns_buffer",
        threat_relevance="Values > 3.8 reveal pseudo-random algorithmic DGAs."
    ),
    FeatureFieldDef(
        name="vowel_ratio",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Proportion of vowel characters (a,e,i,o,u) in domain name",
        calculation="vowel_count / max(1, letter_count)",
        window="dns_buffer",
        threat_relevance="Abnormal vowel density flags non-natural algorithmic domain names."
    ),
    FeatureFieldDef(
        name="consonant_ratio",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Proportion of consonant characters in domain name",
        calculation="consonant_count / max(1, letter_count)",
        window="dns_buffer",
        threat_relevance="Heavy consonant clustering is a classic signature of DGAs."
    ),
    FeatureFieldDef(
        name="digit_ratio",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Proportion of numerical digits in domain name",
        calculation="digit_count / max(1, len(domain))",
        window="dns_buffer",
        threat_relevance="Hex/Base32 encoded subdomains exhibit heavy digit counts."
    ),
    FeatureFieldDef(
        name="unique_char_ratio",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Ratio of unique characters to total domain length",
        calculation="len(set(domain)) / max(1, len(domain))",
        window="dns_buffer",
        threat_relevance="High uniqueness indicates random high-entropy strings."
    ),
    FeatureFieldDef(
        name="subdomain_depth_mean",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Average number of subdomain labels in DNS query",
        calculation="mean(count('.') in domain)",
        window="dns_buffer",
        threat_relevance="DNS tunnelling uses deep nested subdomains for data chunks."
    ),
    FeatureFieldDef(
        name="query_frequency",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="DNS queries per second from source host",
        calculation="dns_queries / max(1e-3, window_duration)",
        window="sliding_host_window (30.0s)",
        threat_relevance="Rapid query bursts indicate automated DGA resolution sweeps."
    ),
    FeatureFieldDef(
        name="txt_record_ratio",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Proportion of DNS queries requesting TXT or NULL records",
        calculation="txt_queries / max(1, total_dns_queries)",
        window="dns_buffer",
        threat_relevance="Heavy TXT querying signifies DNS tunnel command & exfil channels."
    ),
    FeatureFieldDef(
        name="ngram_log_likelihood",
        datatype="float64",
        category="DGA / DNS Tunnelling",
        meaning="Bi-gram log-likelihood score against baseline English language corpus",
        calculation="mean(log P(c_i, c_i+1))",
        window="dns_buffer",
        threat_relevance="Low scores identify unpronounceable algorithmic domains."
    ),

    # ── 4. Encrypted Malware Traffic Features (Zero Decryption) ───────────────
    FeatureFieldDef(
        name="tls_version_num",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Numeric encoding of negotiated TLS version (e.g. 1.2, 1.3, 0.0 if missing)",
        calculation="1.3 if TLSv1.3 else (1.2 if TLSv1.2 else 0.0)",
        window="flow_window",
        threat_relevance="Identifies legacy or anomalous TLS versions."
    ),
    FeatureFieldDef(
        name="has_tls_sni",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Binary indicator for presence of Server Name Indication in ClientHello",
        calculation="1.0 if sni is present else 0.0",
        window="flow_window",
        threat_relevance="Direct IP connection without SNI on 443 often marks raw malware C2."
    ),
    FeatureFieldDef(
        name="ja3_present",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Binary indicator of whether client JA3 fingerprint is available",
        calculation="1.0 if ja3 is not None else 0.0",
        window="flow_window",
        threat_relevance="Presence enables client TLS stack behavioral identification."
    ),
    FeatureFieldDef(
        name="pkt_size_mean",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Mean packet wire size in bytes across flow",
        calculation="(orig_bytes + resp_bytes) / max(1, orig_pkts + resp_pkts)",
        window="flow_window",
        threat_relevance="Characterizes payload footprint across protocols."
    ),
    FeatureFieldDef(
        name="pkt_size_std",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Standard deviation of packet sizes",
        calculation="std(packet_sizes)",
        window="flow_window",
        threat_relevance="Distinguishes uniform keepalive beacons from rich interactive sessions."
    ),
    FeatureFieldDef(
        name="pkt_size_entropy",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Shannon entropy of packet size distribution (SPLT)",
        calculation="-sum(p(size) * log2(p(size)))",
        window="flow_window",
        threat_relevance="Captures structural behavioral variance in encrypted sessions."
    ),
    FeatureFieldDef(
        name="directionality_ratio",
        datatype="float64",
        category="Encrypted Malware",
        meaning="Ratio of origin (outbound) packets to total session packets",
        calculation="orig_pkts / max(1, orig_pkts + resp_pkts)",
        window="flow_window",
        threat_relevance="Reveals unidirectional command pipelines vs interactive sessions."
    ),

    # ── 5. Port Scanning & Reconnaissance Features ───────────────────────────
    FeatureFieldDef(
        name="unique_dst_ports",
        datatype="float64",
        category="Port Scanning",
        meaning="Count of distinct destination ports targeted by source IP",
        calculation="len(set(dst_ports))",
        window="sliding_host_window (30.0s)",
        threat_relevance="Direct indicator of vertical port scanning."
    ),
    FeatureFieldDef(
        name="unique_dst_hosts",
        datatype="float64",
        category="Port Scanning",
        meaning="Count of distinct destination IP hosts targeted by source IP",
        calculation="len(set(dst_hosts))",
        window="sliding_host_window (30.0s)",
        threat_relevance="Direct indicator of horizontal subnet sweep / reconnaissance."
    ),
    FeatureFieldDef(
        name="dst_port_fanout",
        datatype="float64",
        category="Port Scanning",
        meaning="Rate of unique destination ports contacted per second",
        calculation="unique_dst_ports / max(1e-3, window_duration)",
        window="sliding_host_window (30.0s)",
        threat_relevance="Identifies high-speed automated scanning tools (Nmap/Masscan)."
    ),
    FeatureFieldDef(
        name="dst_host_fanout",
        datatype="float64",
        category="Port Scanning",
        meaning="Rate of unique destination hosts contacted per second",
        calculation="unique_dst_hosts / max(1e-3, window_duration)",
        window="sliding_host_window (30.0s)",
        threat_relevance="Measures horizontal worm spreading or reconnaissance velocity."
    ),
    FeatureFieldDef(
        name="conn_attempts",
        datatype="float64",
        category="Port Scanning",
        meaning="Total connection attempts initiated by source host in window",
        calculation="count(connection_events)",
        window="sliding_host_window (30.0s)",
        threat_relevance="High volumes indicate aggressive brute-force probing."
    ),
    FeatureFieldDef(
        name="conn_attempt_rate",
        datatype="float64",
        category="Port Scanning",
        meaning="Connection attempts initiated per second by source host",
        calculation="conn_attempts / max(1e-3, window_duration)",
        window="sliding_host_window (30.0s)",
        threat_relevance="Quantifies scanner aggression and throughput."
    ),
    FeatureFieldDef(
        name="failed_conn_ratio",
        datatype="float64",
        category="Port Scanning",
        meaning="Proportion of connections with unestablished states (S0, REJ, RSTO)",
        calculation="failed_connections / max(1, total_connections)",
        window="sliding_host_window (30.0s)",
        threat_relevance="Port scans yield high failure rates on closed/filtered ports."
    ),

    # ── 6. Data Exfiltration Features ─────────────────────────────────────────
    FeatureFieldDef(
        name="inbound_bytes",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Total inbound (server-to-client) bytes received in flow",
        calculation="resp_bytes",
        window="flow_window",
        threat_relevance="Baseline for bidirectional volume ratio calculation."
    ),
    FeatureFieldDef(
        name="outbound_bytes",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Total outbound (client-to-server) bytes transmitted in flow",
        calculation="orig_bytes",
        window="flow_window",
        threat_relevance="Surges flag massive unauthorized data transfer."
    ),
    FeatureFieldDef(
        name="out_in_byte_ratio",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Ratio of outbound bytes to inbound bytes",
        calculation="orig_bytes / max(1.0, resp_bytes)",
        window="flow_window",
        threat_relevance="Values >> 1.0 reveal asymmetric upload/exfiltration behavior."
    ),
    FeatureFieldDef(
        name="bytes_per_flow",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Average total bytes per connection session between endpoints",
        calculation="(orig_bytes + resp_bytes)",
        window="flow_window",
        threat_relevance="Distinguishes tiny heartbeat sessions from bulky file transfers."
    ),
    FeatureFieldDef(
        name="outbound_rate",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Outbound byte transfer rate in bytes per second",
        calculation="orig_bytes / max(1e-3, duration)",
        window="flow_window",
        threat_relevance="High upload throughput signifies active file exfiltration."
    ),
    FeatureFieldDef(
        name="asymmetric_traffic_score",
        datatype="float64",
        category="Data Exfiltration",
        meaning="Normalized flow volume asymmetry index between -1.0 and +1.0",
        calculation="(orig_bytes - resp_bytes) / max(1.0, orig_bytes + resp_bytes)",
        window="flow_window",
        threat_relevance="+1.0 indicates pure outbound exfiltration; -1.0 indicates pure download."
    ),

    # ── 7. Behavioral Graph Features ─────────────────────────────────────────
    FeatureFieldDef(
        name="src_out_degree",
        datatype="float64",
        category="Behavioral Graph",
        meaning="Graph out-degree: number of unique target IPs contacted by source",
        calculation="graph.out_degree(src_ip)",
        window="sliding_graph_window (60.0s)",
        threat_relevance="High out-degree flags scanners, worms, and lateral movement."
    ),
    FeatureFieldDef(
        name="dst_in_degree",
        datatype="float64",
        category="Behavioral Graph",
        meaning="Graph in-degree: number of unique source IPs contacting destination",
        calculation="graph.in_degree(dst_ip)",
        window="sliding_graph_window (60.0s)",
        threat_relevance="Surges mark DDoS attack targets or central enterprise servers."
    ),
    FeatureFieldDef(
        name="comm_partner_count",
        datatype="float64",
        category="Behavioral Graph",
        meaning="Total unique bipartite communication partners for this endpoint",
        calculation="len(neighbors(endpoint))",
        window="sliding_graph_window (60.0s)",
        threat_relevance="Broad partner fan-out signifies automated discovery activity."
    ),
    FeatureFieldDef(
        name="graph_fanout_ratio",
        datatype="float64",
        category="Behavioral Graph",
        meaning="Ratio of distinct targets to total connection edges",
        calculation="src_out_degree / max(1, total_outbound_edges)",
        window="sliding_graph_window (60.0s)",
        threat_relevance="Approaches 1.0 during rapid 1-packet-per-host reconnaissance."
    )
]

ORDERED_TELEMETRY_FEATURE_NAMES: List[str] = [f.name for f in TELEMETRY_FEATURE_DEFS]

class TelemetryFeatureVector_v2(BaseModel):
    """
    Version 2 Telemetry Feature Vector.
    Strictly standardized 42-feature numerical schema for ML inference and explainability.
    """
    flow_id: str
    timestamp: float
    window_duration_sec: float = 1.0

    # 1. DDoS
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    syn_rate: float = 0.0
    syn_ratio: float = 0.0
    ack_ratio: float = 0.0
    rst_ratio: float = 0.0
    udp_rate: float = 0.0
    unique_src_count: float = 0.0
    src_ip_entropy: float = 0.0
    dest_concentration: float = 0.0
    byte_amplification_ratio: float = 0.0

    # 2. C2 Beaconing
    iat_min: float = 0.0
    iat_max: float = 0.0
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_cv: float = 0.0
    periodicity_score: float = 0.0
    repeated_dst_freq: float = 0.0
    flow_duration: float = 0.0
    repeated_conn_count: float = 0.0

    # 3. DGA / DNS Tunnelling
    query_len_mean: float = 0.0
    shannon_entropy_mean: float = 0.0
    vowel_ratio: float = 0.0
    consonant_ratio: float = 0.0
    digit_ratio: float = 0.0
    unique_char_ratio: float = 0.0
    subdomain_depth_mean: float = 0.0
    query_frequency: float = 0.0
    txt_record_ratio: float = 0.0
    ngram_log_likelihood: float = 0.0

    # 4. Encrypted Malware
    tls_version_num: float = 0.0
    has_tls_sni: float = 0.0
    ja3_present: float = 0.0
    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0
    pkt_size_entropy: float = 0.0
    directionality_ratio: float = 0.0

    # 5. Port Scanning
    unique_dst_ports: float = 0.0
    unique_dst_hosts: float = 0.0
    dst_port_fanout: float = 0.0
    dst_host_fanout: float = 0.0
    conn_attempts: float = 0.0
    conn_attempt_rate: float = 0.0
    failed_conn_ratio: float = 0.0

    # 6. Data Exfiltration
    inbound_bytes: float = 0.0
    outbound_bytes: float = 0.0
    out_in_byte_ratio: float = 0.0
    bytes_per_flow: float = 0.0
    outbound_rate: float = 0.0
    asymmetric_traffic_score: float = 0.0

    # 7. Behavioral Graph
    src_out_degree: float = 0.0
    dst_in_degree: float = 0.0
    comm_partner_count: float = 0.0
    graph_fanout_ratio: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        """Export as key-value dictionary for explainability and alert engines."""
        return {name: float(getattr(self, name, 0.0)) for name in ORDERED_TELEMETRY_FEATURE_NAMES}

    def to_numpy(self) -> np.ndarray:
        """Export as dense 1D NumPy array for vectorized ML inference."""
        return np.array([getattr(self, name, 0.0) for name in ORDERED_TELEMETRY_FEATURE_NAMES], dtype=np.float64)

    @classmethod
    def feature_names(cls) -> List[str]:
        return list(ORDERED_TELEMETRY_FEATURE_NAMES)
