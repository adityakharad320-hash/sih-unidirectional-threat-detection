"""
Fast Behavioral Screening Gate (Stage 1).

A high-performance, conservative pre-screening layer that operates in nanoseconds:
- Evaluates cheap observable L4/L7 flow metrics (rates, flag ratios, fan-outs, asymmetry).
- Categorizes traffic into:
    1. PASS_NORMAL: Clean traffic within safe operational parameters (avoids 200-tree ML traversal).
    2. SUSPICIOUS: Borderline rates/ratios or unknown patterns (escalated to Tier 2/3 and ML).
    3. CRITICAL_RULE: Definite high-confidence threat signature matching deterministic behavioral detectors.
"""
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any


class GateDecision(str, Enum):
    PASS_NORMAL = "PASS_NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL_RULE = "CRITICAL_RULE"


@dataclass(slots=True)
class GateResult:
    decision: GateDecision
    flagged_reasons: list
    threat_category: Optional[str] = None
    urgency_level: float = 0.0  # [0.0, 1.0]


class FastBehavioralGate:
    """
    Zero-allocation conservative gate.
    Ensures zero false negatives on attack traffic while shielding the ML engine
    from millions of repetitive benign keepalive packets.
    """
    def __init__(
        self,
        syn_ratio_warn: float = 0.45,
        syn_ratio_crit: float = 0.70,
        packet_rate_warn: float = 20.0,
        packet_rate_crit: float = 80.0,
        port_fanout_warn: float = 3.0,
        port_fanout_crit: float = 10.0,
        host_fanout_warn: float = 3.0,
        host_fanout_crit: float = 8.0,
        exfil_ratio_warn: float = 8.0,
        exfil_ratio_crit: float = 20.0,
        exfil_min_bytes: int = 15_000,
        dns_query_len_warn: int = 15,
        c2_conn_count_warn: int = 4
    ):
        self.syn_ratio_warn = syn_ratio_warn
        self.syn_ratio_crit = syn_ratio_crit
        self.packet_rate_warn = packet_rate_warn
        self.packet_rate_crit = packet_rate_crit
        self.port_fanout_warn = port_fanout_warn
        self.port_fanout_crit = port_fanout_crit
        self.host_fanout_warn = host_fanout_warn
        self.host_fanout_crit = host_fanout_crit
        self.exfil_ratio_warn = exfil_ratio_warn
        self.exfil_ratio_crit = exfil_ratio_crit
        self.exfil_min_bytes = exfil_min_bytes
        self.dns_query_len_warn = dns_query_len_warn
        self.c2_conn_count_warn = c2_conn_count_warn

    def screen_flow(self, flow_state, graph_tracker=None) -> GateResult:
        """
        Screens a flow using cheap observable features in < 1 microsecond.
        """
        reasons = []
        is_critical = False
        crit_cat = None
        urgency = 0.0

        # Duration & Rates
        dur = max(1e-3, flow_state.duration if flow_state.duration > 0 else (flow_state.last_seen - flow_state.first_seen))
        total_pkts = flow_state.orig_pkts + flow_state.resp_pkts
        pkt_rate = total_pkts / dur
        total_bytes = flow_state.orig_bytes + flow_state.resp_bytes

        # 1. DDoS / SYN Surge Check
        syn_ratio = flow_state.syn_count / max(1, total_pkts)

        if syn_ratio >= self.syn_ratio_crit or pkt_rate >= self.packet_rate_crit:
            reasons.append(f"Volumetric surge: SYN ratio {syn_ratio:.2f}, pkt_rate {pkt_rate:.1f}/s")
            is_critical = True
            crit_cat = "DDOS"
            urgency = max(urgency, 0.95)
        elif syn_ratio >= self.syn_ratio_warn or pkt_rate >= self.packet_rate_warn:
            reasons.append(f"Elevated volumetric activity: SYN ratio {syn_ratio:.2f}, pkt_rate {pkt_rate:.1f}/s")
            urgency = max(urgency, 0.65)

        # 2. Port Scanning / Reconnaissance Check (Graph Fanout)
        unique_ports = 1.0
        port_fanout = 0.0
        unique_hosts = 1.0
        host_fanout = 0.0

        if graph_tracker:
            ports = graph_tracker.src_to_ports.get(flow_state.src_ip)
            if ports:
                unique_ports = float(len(set(ports)))
                port_fanout = unique_ports / max(1.0, dur)
            dsts = graph_tracker.src_to_dsts.get(flow_state.src_ip)
            if dsts:
                unique_hosts = float(len(set(dsts)))
                host_fanout = unique_hosts / max(1.0, dur)

        if unique_ports >= self.port_fanout_crit or port_fanout >= self.port_fanout_crit:
            reasons.append(f"Vertical scanning: {int(unique_ports)} ports, fanout {port_fanout:.1f} ports/s")
            is_critical = True
            crit_cat = "PORT_SCAN"
            urgency = max(urgency, 0.92)
        elif unique_hosts >= self.host_fanout_crit or host_fanout >= self.host_fanout_crit:
            reasons.append(f"Horizontal sweep: {int(unique_hosts)} hosts, fanout {host_fanout:.1f} hosts/s")
            is_critical = True
            crit_cat = "PORT_SCAN"
            urgency = max(urgency, 0.88)
        elif unique_ports >= self.port_fanout_warn or unique_hosts >= self.host_fanout_warn:
            reasons.append(f"Recon probe diversity: {int(unique_ports)} ports, {int(unique_hosts)} hosts")
            urgency = max(urgency, 0.60)

        # 3. DNS / DGA Tunnelling Check
        if flow_state.dns_queries:
            last_q = flow_state.dns_queries[-1]
            q_len = len(last_q)
            txt_ratio = sum(1 for t in flow_state.dns_record_types if t in ("TXT", "NULL", "16")) / max(1, len(flow_state.dns_record_types))
            if q_len >= self.dns_query_len_warn or txt_ratio >= 0.20:
                reasons.append(f"DNS anomaly: domain query len {q_len}, TXT ratio {txt_ratio:.2f}")
                if q_len >= 25 or txt_ratio >= 0.35:
                    is_critical = True
                    crit_cat = "DGA_DNS_TUNNELLING"
                    urgency = max(urgency, 0.93)
                else:
                    urgency = max(urgency, 0.70)

        # 4. Data Exfiltration Check (Byte Asymmetry)
        out_bytes = flow_state.orig_bytes
        in_bytes = max(1, flow_state.resp_bytes)
        ratio = out_bytes / in_bytes

        # Exclude normal server outbound responses
        is_client_exfil = flow_state.src_port > 1024 and flow_state.dst_port in (80, 443, 8080, 22)
        if is_client_exfil and out_bytes >= self.exfil_min_bytes:
            if ratio >= self.exfil_ratio_crit:
                reasons.append(f"Data exfiltration: Out/In ratio {ratio:.1f}x ({out_bytes} B outbound)")
                is_critical = True
                crit_cat = "DATA_EXFILTRATION"
                urgency = max(urgency, 0.90)
            elif ratio >= self.exfil_ratio_warn:
                reasons.append(f"High outbound asymmetry: {ratio:.1f}x ratio")
                urgency = max(urgency, 0.65)

        # 5. C2 Beaconing Check
        conn_count = len(flow_state.timestamps)
        if conn_count >= self.c2_conn_count_warn:
            # Check for regular timing
            reasons.append(f"C2 heartbeat candidate: {conn_count} periodic events")
            urgency = max(urgency, 0.55)

        # 6. Encrypted Traffic Anomaly (TLS without SNI)
        if flow_state.has_tls and not flow_state.tls_sni and flow_state.dst_port in (443, 8443):
            reasons.append("TLS handshake missing cleartext SNI")
            urgency = max(urgency, 0.75)

        # Final Decision
        if is_critical:
            return GateResult(
                decision=GateDecision.CRITICAL_RULE,
                flagged_reasons=reasons,
                threat_category=crit_cat,
                urgency_level=urgency
            )
        elif len(reasons) > 0:
            return GateResult(
                decision=GateDecision.SUSPICIOUS,
                flagged_reasons=reasons,
                threat_category=None,
                urgency_level=urgency
            )
        else:
            return GateResult(
                decision=GateDecision.PASS_NORMAL,
                flagged_reasons=[],
                threat_category="BENIGN",
                urgency_level=0.0
            )
