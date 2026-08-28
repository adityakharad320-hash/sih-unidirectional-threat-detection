"""
Data Models and Configuration for Deterministic Behavioral Detectors.
"""
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class BehavioralDetectionResult(BaseModel):
    """Structured output from an individual behavioral detector."""
    detector_name: str
    category: str              # "DDoS", "Port Scanning", "DNS / DGA", "C2 Beaconing", "Data Exfiltration", "Encrypted Malware"
    triggered: bool
    score: float = 0.0         # Confidence or severity score [0.0 - 1.0]
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    human_readable_reason: str = "No anomalous behavioral pattern detected."

class BehavioralDetectorsConfig(BaseModel):
    """
    Configurable Thresholds for Deterministic Behavioral Detectors.
    All thresholds are documented with explicit cybersecurity rationales.
    """
    # ── 1. DDoS Thresholds ───────────────────────────────────────────────────
    # Rationale: Floods generate extreme packet volume or high SYN density with distributed source IPs.
    ddos_packet_rate_thresh: float = Field(default=50.0, description="Minimum packet rate (pkts/s) for volumetric flood indicator")
    ddos_syn_ratio_thresh: float = Field(default=0.80, description="Minimum SYN packet ratio indicating unidirectional SYN flood")
    ddos_src_entropy_thresh: float = Field(default=2.50, description="Minimum Shannon source IP entropy (bits) indicating distributed spoofing")
    ddos_unique_src_thresh: float = Field(default=15.0, description="Minimum distinct source IPs targeting single destination")
    ddos_udp_rate_thresh: float = Field(default=50.0, description="Minimum UDP packet rate (pkts/s) for reflection/amplification flood")

    # ── 2. Port Scanning Thresholds ──────────────────────────────────────────
    # Rationale: Standard hosts touch 1-3 ports; scanners probe wide ranges with high failure/rejection rates.
    scan_unique_ports_thresh: float = Field(default=10.0, description="Minimum distinct destination ports contacted by source IP")
    scan_port_fanout_thresh: float = Field(default=2.0, description="Rate of unique destination ports contacted per second")
    scan_unique_hosts_thresh: float = Field(default=8.0, description="Minimum distinct destination hosts contacted (horizontal sweep)")
    scan_host_fanout_thresh: float = Field(default=2.0, description="Rate of unique destination hosts contacted per second")
    scan_failed_conn_ratio_thresh: float = Field(default=0.60, description="Minimum ratio of unestablished connections (S0, REJ, RSTO)")

    # ── 3. DNS Tunnelling / DGA Thresholds ───────────────────────────────────
    # Rationale: English domains have entropy < 3.2, len < 20. Tunnels and DGAs use long, random, or TXT queries.
    dns_entropy_thresh: float = Field(default=3.40, description="Minimum domain Shannon character entropy indicating DGA randomness")
    dns_query_len_thresh: float = Field(default=22.0, description="Minimum average DNS query string character length")
    dns_txt_ratio_thresh: float = Field(default=0.50, description="Minimum proportion of TXT/NULL record requests")
    dns_ngram_ll_thresh: float = Field(default=-4.50, description="Maximum English bigram log-likelihood score (lower = less English-like)")
    dns_query_freq_thresh: float = Field(default=5.0, description="Minimum DNS queries per second indicating automated sweeps")

    # ── 4. C2 Beaconing Thresholds ───────────────────────────────────────────
    # Rationale: Automated malware beacons exhibit ultra-low jitter (CV < 0.15) and distinct FFT periodicity peaks.
    c2_iat_cv_thresh: float = Field(default=0.15, description="Maximum coefficient of variation of IAT (timing jitter)")
    c2_periodicity_thresh: float = Field(default=0.08, description="Minimum dominant FFT spectral power fraction")
    c2_min_conn_count: float = Field(default=4.0, description="Minimum repeated connections required to evaluate periodicity")
    c2_repeated_dst_freq_thresh: float = Field(default=2.0, description="Minimum connection frequency per minute to same destination")

    # ── 5. Data Exfiltration Thresholds ──────────────────────────────────────
    # Rationale: Typical user flows are inbound-heavy; exfiltration produces massive outbound ratios and positive asymmetry.
    exfil_out_in_ratio_thresh: float = Field(default=8.0, description="Minimum outbound-to-inbound byte ratio")
    exfil_outbound_rate_thresh: float = Field(default=10_000.0, description="Minimum outbound byte rate (bytes/s)")
    exfil_asym_score_thresh: float = Field(default=0.75, description="Minimum traffic asymmetry index [(out-in)/(out+in)]")
    exfil_min_outbound_bytes: float = Field(default=25000.0, description="Minimum total outbound volume (bytes) for exfiltration alert")

    # ── 6. Encrypted Malware Traffic Thresholds ──────────────────────────────
    # Rationale: Malware C2 on TLS 443 often lacks SNI or exhibits rigid unvaried packet sizes (entropy < 1.0).
    enc_min_pkt_size_thresh: float = Field(default=50.0, description="Minimum mean packet size (bytes)")
    enc_pkt_size_entropy_thresh: float = Field(default=1.0, description="Maximum packet size entropy (bits) indicating uniform payload footprint")
    enc_directionality_thresh: float = Field(default=0.90, description="Minimum outbound packet ratio for unidirectional TLS channel")
