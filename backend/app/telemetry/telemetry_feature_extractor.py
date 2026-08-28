"""
Production Telemetry Feature Extractor.

Converts TelemetryFlowState and HostGraphTracker snapshots into a strict,
versioned 42-feature numerical vector (TelemetryFeatureVector_v2).
"""
import math
import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import Counter
from app.telemetry.schema import NormalizedBaseEvent
from app.telemetry.telemetry_flow_tracker import TelemetryFlowState, StreamingTelemetryTracker
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

# Reference English letter bigrams for DGA scoring
ENGLISH_BIGRAM_BASELINE = {
    "th": 0.035, "he": 0.030, "in": 0.024, "er": 0.020, "an": 0.019,
    "re": 0.018, "on": 0.017, "at": 0.014, "en": 0.014, "nd": 0.013,
    "ti": 0.013, "es": 0.013, "or": 0.012, "te": 0.012, "of": 0.011,
    "ed": 0.011, "is": 0.011, "it": 0.011, "al": 0.010, "ar": 0.010,
    "st": 0.010, "to": 0.010, "nt": 0.010, "ng": 0.009, "se": 0.009,
    "ha": 0.009, "as": 0.008, "ou": 0.008, "io": 0.008, "le": 0.008
}

class TelemetryFeatureExtractor:
    """
    High-performance feature calculator mapping telemetry states to TelemetryFeatureVector_v2.
    """

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calculate Shannon character entropy in bits."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    @classmethod
    def calculate_dga_ngram_score(cls, domain: str) -> float:
        """Calculate mean log-probability of domain bi-grams against English corpus."""
        clean = domain.lower().split(".")[0]
        if len(clean) < 2:
            return 0.0
        score_sum = 0.0
        pairs = 0
        min_p = 1e-4
        for i in range(len(clean) - 1):
            pair = clean[i:i+2]
            prob = ENGLISH_BIGRAM_BASELINE.get(pair, min_p)
            score_sum += math.log(prob)
            pairs += 1
        return float(score_sum / max(1, pairs))

    @staticmethod
    def calculate_temporal_beaconing_features(timestamps: List[float]) -> Tuple[float, float, float, float, float, float]:
        """Compute IAT min, max, mean, std, CV (jitter), and FFT periodicity score."""
        if len(timestamps) < 3:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        ts_array = np.array(timestamps, dtype=np.float64)
        iats = np.diff(ts_array)
        iats = iats[iats > 0]
        if len(iats) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        iat_min = float(np.min(iats))
        iat_max = float(np.max(iats))
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_cv = float(iat_std / max(1e-5, iat_mean))

        periodicity = 0.0
        if len(iats) >= 6:
            centered = iats - iat_mean
            fft_vals = np.abs(np.fft.rfft(centered))
            if len(fft_vals) > 1:
                total_power = np.sum(fft_vals[1:])
                if total_power > 1e-6:
                    periodicity = float(np.max(fft_vals[1:]) / total_power)

        return iat_min, iat_max, iat_mean, iat_std, iat_cv, periodicity

    @classmethod
    def extract_features(
        cls,
        state: TelemetryFlowState,
        tracker: StreamingTelemetryTracker
    ) -> TelemetryFeatureVector_v2:
        """
        Extract complete 42-feature numerical vector for the given flow state.
        """
        now = state.last_seen
        first = state.first_seen
        raw_dur = state.duration if state.duration > 0 else (now - first)
        duration = max(1e-3, raw_dur)
        rate_duration = max(1.0, raw_dur)
        src_ip = state.src_ip
        dst_ip = state.dst_ip
        
        # ── 1. DDoS Features ──────────────────────────────────────────────────
        tot_pkts = max(state.orig_pkts + state.resp_pkts, state.event_count)
        tot_bytes = state.orig_bytes + state.resp_bytes
        packet_rate = float(tot_pkts / rate_duration)
        byte_rate = float(tot_bytes / rate_duration)
        
        # SYN & Flag analysis from conn_state and history
        is_syn = (state.history and "S" in state.history) or any(s in ("S0", "S1", "SF") for s in state.conn_states)
        syn_count = 1.0 if is_syn else 0.0
        syn_rate = float(syn_count / rate_duration)
        syn_ratio = 1.0 if any(s == "S0" for s in state.conn_states) else (0.5 if is_syn else 0.0)
        ack_ratio = 1.0 if (state.history and "A" in state.history) else (0.5 if any(s == "SF" for s in state.conn_states) else 0.0)
        rst_ratio = 1.0 if any(s in ("RSTO", "RSTR", "RSTOS0") for s in state.conn_states) else 0.0
        
        udp_rate = float(tot_pkts / duration) if state.protocol.upper() == "UDP" else 0.0
        
        # Source entropy targeting dst_ip
        recent_srcs = [s for ts, s in tracker.graph_tracker.dst_to_srcs[dst_ip] if (now - ts) <= 30.0]
        unique_src_count = float(len(set(recent_srcs)))
        src_ip_entropy = 0.0
        if recent_srcs:
            counts = Counter(recent_srcs)
            tot_s = len(recent_srcs)
            for c in counts.values():
                p = c / tot_s
                src_ip_entropy -= p * math.log2(p)
                
        dst_pkts = tracker.graph_tracker.dst_packet_counts[dst_ip]
        tot_net_pkts = max(1, tracker.graph_tracker.total_network_packets)
        dest_concentration = float(dst_pkts / tot_net_pkts)
        byte_amplification_ratio = float(state.resp_bytes / max(1.0, float(state.orig_bytes)))

        # ── 2. C2 Beaconing Features ──────────────────────────────────────────
        host_ts = list(tracker.host_conn_timestamps.get((src_ip, dst_ip), []))
        flow_ts = list(state.timestamps)
        ts_list = flow_ts if len(flow_ts) >= 3 else host_ts

        iat_min, iat_max, iat_mean, iat_std, iat_cv, periodicity_score = cls.calculate_temporal_beaconing_features(
            ts_list
        )
        
        # Frequency of connections to same destination
        repeated_conn_count = float(len(host_ts)) if host_ts else 1.0
        elapsed_sec = max(1.0, now - first) if len(flow_ts) >= 3 else max(1.0, (host_ts[-1] - host_ts[0]) if len(host_ts) >= 2 else 1.0)
        repeated_dst_freq = float(repeated_conn_count / (elapsed_sec / 60.0))

        # ── 3. DGA / DNS Tunnelling Features ──────────────────────────────────
        query_len_mean = 0.0
        shannon_entropy_mean = 0.0
        vowel_ratio = 0.0
        consonant_ratio = 0.0
        digit_ratio = 0.0
        unique_char_ratio = 0.0
        subdomain_depth_mean = 0.0
        query_frequency = 0.0
        txt_record_ratio = 0.0
        ngram_log_likelihood = 0.0

        if state.dns_queries:
            q_list = list(state.dns_queries)
            query_len_mean = float(np.mean([len(q) for q in q_list]))
            shannon_entropy_mean = float(np.mean([cls.shannon_entropy(q) for q in q_list]))
            subdomain_depth_mean = float(np.mean([q.count(".") for q in q_list]))
            query_frequency = float(len(q_list) / max(1e-3, duration))
            
            txt_count = sum(1 for r in state.dns_record_types if r in ("TXT", "NULL", "ANY"))
            txt_record_ratio = float(txt_count / max(1, len(state.dns_record_types)))
            
            all_chars = "".join(q_list).lower()
            if all_chars:
                vowels = set("aeiou")
                letters = [c for c in all_chars if c.isalpha()]
                consonants = [c for c in letters if c not in vowels]
                digits = [c for c in all_chars if c.isdigit()]
                
                vowel_ratio = float(len([c for c in letters if c in vowels]) / max(1, len(letters)))
                consonant_ratio = float(len(consonants) / max(1, len(letters)))
                digit_ratio = float(len(digits) / max(1, len(all_chars)))
                unique_char_ratio = float(len(set(all_chars)) / max(1, len(all_chars)))
                
            ngram_log_likelihood = float(np.mean([cls.calculate_dga_ngram_score(q) for q in q_list]))

        # ── 4. Encrypted Malware Traffic Features ─────────────────────────────
        tls_version_num = 0.0
        if state.tls_version:
            if "1.3" in state.tls_version:
                tls_version_num = 1.3
            elif "1.2" in state.tls_version:
                tls_version_num = 1.2
            else:
                tls_version_num = 1.0
                
        has_tls_sni = 1.0 if state.tls_sni else 0.0
        ja3_present = 1.0 if state.ja3 else 0.0
        
        sizes = list(state.packet_sizes)
        pkt_size_mean = float(np.mean(sizes)) if sizes else float(tot_bytes / max(1, tot_pkts))
        pkt_size_std = float(np.std(sizes)) if len(sizes) > 1 else 0.0
        
        pkt_size_entropy = 0.0
        if sizes:
            s_counts = Counter(sizes)
            tot_s = len(sizes)
            for c in s_counts.values():
                p = c / tot_s
                pkt_size_entropy -= p * math.log2(p)
                
        directionality_ratio = float(state.orig_pkts / max(1.0, float(state.orig_pkts + state.resp_pkts)))

        # ── 5. Port Scanning & Reconnaissance Features ────────────────────────
        recent_ports = [p for ts, p in tracker.graph_tracker.src_to_ports[src_ip] if (now - ts) <= 30.0]
        recent_hosts = [h for ts, h in tracker.graph_tracker.src_to_dsts[src_ip] if (now - ts) <= 30.0]
        unique_dst_ports = float(len(set(recent_ports)))
        unique_dst_hosts = float(len(set(recent_hosts)))
        dst_port_fanout = float(unique_dst_ports / max(1.0, duration))
        dst_host_fanout = float(unique_dst_hosts / max(1.0, duration))
        conn_attempts = float(len(recent_ports))
        conn_attempt_rate = float(conn_attempts / max(1.0, duration))
        
        # Failed connections: S0, REJ, RSTO
        failed_count = sum(1 for s in state.conn_states if s in ("S0", "REJ", "RSTO", "RSTOS0"))
        failed_conn_ratio = float(failed_count / max(1, len(state.conn_states)))

        # ── 6. Data Exfiltration Features ─────────────────────────────────────
        inbound_bytes = float(state.resp_bytes)
        outbound_bytes = float(state.orig_bytes)
        out_in_byte_ratio = float(outbound_bytes / max(1.0, inbound_bytes))
        bytes_per_flow = float(tot_bytes)
        outbound_rate = float(outbound_bytes / rate_duration)
        asymmetric_traffic_score = float((outbound_bytes - inbound_bytes) / max(1.0, outbound_bytes + inbound_bytes))

        # ── 7. Behavioral Graph Features ──────────────────────────────────────
        src_out_degree, dst_in_degree, comm_partner_count, graph_fanout_ratio = tracker.graph_tracker.get_graph_metrics(
            src_ip, dst_ip, now
        )

        return TelemetryFeatureVector_v2(
            flow_id=state.flow_id,
            timestamp=state.last_seen,
            window_duration_sec=duration,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            syn_rate=syn_rate,
            syn_ratio=syn_ratio,
            ack_ratio=ack_ratio,
            rst_ratio=rst_ratio,
            udp_rate=udp_rate,
            unique_src_count=unique_src_count,
            src_ip_entropy=float(src_ip_entropy),
            dest_concentration=dest_concentration,
            byte_amplification_ratio=byte_amplification_ratio,
            iat_min=iat_min,
            iat_max=iat_max,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_cv=iat_cv,
            periodicity_score=periodicity_score,
            repeated_dst_freq=repeated_dst_freq,
            flow_duration=duration,
            repeated_conn_count=repeated_conn_count,
            query_len_mean=query_len_mean,
            shannon_entropy_mean=shannon_entropy_mean,
            vowel_ratio=vowel_ratio,
            consonant_ratio=consonant_ratio,
            digit_ratio=digit_ratio,
            unique_char_ratio=unique_char_ratio,
            subdomain_depth_mean=subdomain_depth_mean,
            query_frequency=query_frequency,
            txt_record_ratio=txt_record_ratio,
            ngram_log_likelihood=ngram_log_likelihood,
            tls_version_num=tls_version_num,
            has_tls_sni=has_tls_sni,
            ja3_present=ja3_present,
            pkt_size_mean=pkt_size_mean,
            pkt_size_std=pkt_size_std,
            pkt_size_entropy=float(pkt_size_entropy),
            directionality_ratio=directionality_ratio,
            unique_dst_ports=unique_dst_ports,
            unique_dst_hosts=unique_dst_hosts,
            dst_port_fanout=dst_port_fanout,
            dst_host_fanout=dst_host_fanout,
            conn_attempts=conn_attempts,
            conn_attempt_rate=conn_attempt_rate,
            failed_conn_ratio=failed_conn_ratio,
            inbound_bytes=inbound_bytes,
            outbound_bytes=outbound_bytes,
            out_in_byte_ratio=out_in_byte_ratio,
            bytes_per_flow=bytes_per_flow,
            outbound_rate=outbound_rate,
            asymmetric_traffic_score=asymmetric_traffic_score,
            src_out_degree=src_out_degree,
            dst_in_degree=dst_in_degree,
            comm_partner_count=comm_partner_count,
            graph_fanout_ratio=graph_fanout_ratio
        )
