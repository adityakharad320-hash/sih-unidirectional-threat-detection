"""
Streaming Feature Extraction Engine.
Calculates statistical, behavioral, signal-processing, and protocol features across all 6 threat categories.
"""
import math
import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import Counter
from app.core.models import PacketMetadata
from app.core.flow_tracker import FlowState, StreamingFlowTracker
from app.core.feature_schema import FeatureVector_v1

# Reference English letter bigrams for DGA scoring
ENGLISH_BIGRAM_BASELINE = {
    "th": 0.035, "he": 0.030, "in": 0.024, "er": 0.020, "an": 0.019,
    "re": 0.018, "on": 0.017, "at": 0.014, "en": 0.014, "nd": 0.013,
    "ti": 0.013, "es": 0.013, "or": 0.012, "te": 0.012, "of": 0.011,
    "ed": 0.011, "is": 0.011, "it": 0.011, "al": 0.010, "ar": 0.010,
    "st": 0.010, "to": 0.010, "nt": 0.010, "ng": 0.009, "se": 0.009,
    "ha": 0.009, "as": 0.008, "ou": 0.008, "io": 0.008, "le": 0.008
}

class StreamingFeatureExtractor:
    """
    Stateless calculation engine that computes a FeatureVector_v1 snapshot for a flow.
    """

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy in bits per character."""
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
        """
        Calculate mean log-probability of domain bi-grams against English baseline.
        Lower scores = unpronounceable / random strings.
        """
        clean = domain.lower().split(".")[0]  # Focus on subdomain / main label
        if len(clean) < 2:
            return 0.0
        
        score_sum = 0.0
        pairs = 0
        min_p = 1e-4  # Smoothing floor for unseen n-grams
        
        for i in range(len(clean) - 1):
            pair = clean[i:i+2]
            prob = ENGLISH_BIGRAM_BASELINE.get(pair, min_p)
            score_sum += math.log(prob)
            pairs += 1
            
        return float(score_sum / max(1, pairs))

    @staticmethod
    def calculate_beaconing_signal_features(timestamps: List[float]) -> Tuple[float, float, float, float, float, float]:
        """
        Compute IAT mean, std, CV (jitter), skewness, FFT peak power, and autocorrelation peak.
        """
        if len(timestamps) < 3:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        ts_array = np.array(timestamps, dtype=np.float64)
        iats = np.diff(ts_array)
        
        # Filter out 0 or negative IAT anomalies
        iats = iats[iats > 0]
        if len(iats) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_cv = float(iat_std / max(1e-5, iat_mean))

        # Skewness
        if iat_std > 1e-6:
            iat_skewness = float(np.mean(((iats - iat_mean) / iat_std) ** 3))
        else:
            iat_skewness = 0.0

        # FFT Periodicity Analysis
        fft_peak = 0.0
        if len(iats) >= 8:
            centered_iats = iats - iat_mean
            fft_vals = np.abs(np.fft.rfft(centered_iats))
            if len(fft_vals) > 1:
                total_power = np.sum(fft_vals[1:])
                if total_power > 1e-6:
                    fft_peak = float(np.max(fft_vals[1:]) / total_power)

        # Autocorrelation Peak
        autocorr_peak = 0.0
        if len(iats) >= 6 and iat_std > 1e-6:
            norm_iats = (iats - iat_mean) / (iat_std * len(iats))
            autocorr = np.correlate(norm_iats, norm_iats, mode='full')
            mid = len(autocorr) // 2
            positive_lags = autocorr[mid + 1 : mid + 10]
            if len(positive_lags) > 0:
                autocorr_peak = float(np.max(positive_lags))

        return iat_mean, iat_std, iat_cv, iat_skewness, fft_peak, autocorr_peak

    @classmethod
    def extract_features(
        cls,
        state: FlowState,
        tracker: StreamingFlowTracker,
        window_duration: float = 1.0
    ) -> FeatureVector_v1:
        """
        Extract complete 32-feature vector for the given flow state.
        """
        now = state.last_seen
        first = state.first_seen
        duration = max(1e-3, now - first)
        
        # 1. Volumetric / DDoS features
        packet_rate = float(state.packet_count / duration)
        byte_rate = float(state.byte_count / duration)
        
        total_tcp = max(1, state.total_tcp_packets)
        syn_ratio = float(state.tcp_syn_count / total_tcp)
        ack_ratio = float(state.tcp_ack_count / total_tcp)
        rst_ratio = float(state.tcp_rst_count / total_tcp)
        fin_ratio = float(state.tcp_fin_count / total_tcp)
        syn_ack_ratio = float(state.tcp_syn_ack_count / total_tcp)

        # Source IP entropy targeting destination
        dst_ip = state.flow_key.dst_ip
        src_ip = state.flow_key.src_ip
        recent_srcs = [ip for ts, ip in tracker.dst_src_ips[dst_ip] if (now - ts) <= max(duration, 5.0)]
        unique_src_ips = float(len(set(recent_srcs)))
        
        src_ip_entropy = 0.0
        if recent_srcs:
            src_counts = Counter(recent_srcs)
            tot_src = len(recent_srcs)
            for c in src_counts.values():
                p = c / tot_src
                src_ip_entropy -= p * math.log2(p)

        # 2. Port Scanning / Reconnaissance Features
        recent_ports = [p for ts, p in tracker.src_dst_ports[src_ip] if (now - ts) <= max(duration, 5.0)]
        recent_hosts = [h for ts, h in tracker.src_dst_hosts[src_ip] if (now - ts) <= max(duration, 5.0)]
        recent_syns = [ts for ts in tracker.src_syn_times[src_ip] if (now - ts) <= max(duration, 5.0)]
        
        unique_dst_ports = float(len(set(recent_ports)))
        unique_dst_hosts = float(len(set(recent_hosts)))
        effective_win = max(duration, 1.0)
        dst_port_fanout = float(unique_dst_ports / effective_win)
        dst_host_fanout = float(unique_dst_hosts / effective_win)
        connection_attempt_rate = float(len(recent_syns) / effective_win)

        # 3. C2 Beaconing Features
        iat_mean, iat_std, iat_cv, iat_skew, fft_peak, autocorr_peak = cls.calculate_beaconing_signal_features(
            list(state.timestamps)
        )

        # 4. DNS / DGA Features
        dns_query_len_mean = 0.0
        dns_entropy_mean = 0.0
        dns_txt_record_ratio = 0.0
        dns_consonant_ratio = 0.0
        dns_digit_ratio = 0.0
        dns_ngram_score = 0.0

        if state.dns_queries:
            q_list = list(state.dns_queries)
            dns_query_len_mean = float(np.mean([len(q) for q in q_list]))
            dns_entropy_mean = float(np.mean([cls.shannon_entropy(q) for q in q_list]))
            
            # Record type ratio
            txt_count = sum(1 for r in state.dns_record_types if r in ("TXT", "NULL", "ANY"))
            dns_txt_record_ratio = float(txt_count / max(1, len(state.dns_record_types)))

            # Character distributions
            all_chars = "".join(q_list).lower()
            if all_chars:
                vowels = set("aeiou")
                letters = [c for c in all_chars if c.isalpha()]
                consonants = [c for c in letters if c not in vowels]
                digits = [c for c in all_chars if c.isdigit()]
                
                dns_consonant_ratio = float(len(consonants) / max(1, len(letters)))
                dns_digit_ratio = float(len(digits) / max(1, len(all_chars)))
                
            dns_ngram_score = float(np.mean([cls.calculate_dga_ngram_score(q) for q in q_list]))

        # 5. Encrypted Traffic Features
        sizes = list(state.packet_sizes)
        pkt_size_mean = float(np.mean(sizes)) if sizes else 0.0
        pkt_size_std = float(np.std(sizes)) if sizes else 0.0
        
        pkt_size_entropy = 0.0
        if sizes:
            size_counts = Counter(sizes)
            tot_sizes = len(sizes)
            for count in size_counts.values():
                p = count / tot_sizes
                pkt_size_entropy -= p * math.log2(p)

        has_tls_sni = 1.0 if (state.tls_sni is not None or state.has_tls_handshake) else 0.0

        # 6. Exfiltration & Overview
        outbound_bytes_total = float(state.byte_count)
        byte_velocity = float(state.byte_count / duration)

        return FeatureVector_v1(
            flow_id=state.flow_key.unidirectional_id,
            timestamp=state.last_seen,
            window_duration_sec=duration,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            syn_ratio=syn_ratio,
            ack_ratio=ack_ratio,
            rst_ratio=rst_ratio,
            fin_ratio=fin_ratio,
            syn_ack_ratio=syn_ack_ratio,
            src_ip_entropy=float(src_ip_entropy),
            unique_src_ips=unique_src_ips,
            unique_dst_ports=unique_dst_ports,
            unique_dst_hosts=unique_dst_hosts,
            dst_port_fanout=dst_port_fanout,
            dst_host_fanout=dst_host_fanout,
            connection_attempt_rate=connection_attempt_rate,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_cv=iat_cv,
            iat_skewness=iat_skew,
            fft_peak_magnitude=fft_peak,
            autocorr_max_peak=autocorr_peak,
            dns_query_len_mean=dns_query_len_mean,
            dns_entropy_mean=dns_entropy_mean,
            dns_txt_record_ratio=dns_txt_record_ratio,
            dns_consonant_ratio=dns_consonant_ratio,
            dns_digit_ratio=dns_digit_ratio,
            dns_ngram_score=dns_ngram_score,
            pkt_size_mean=pkt_size_mean,
            pkt_size_std=pkt_size_std,
            pkt_size_entropy=float(pkt_size_entropy),
            has_tls_sni=has_tls_sni,
            outbound_bytes_total=outbound_bytes_total,
            byte_velocity=byte_velocity,
            flow_duration_sec=duration
        )
