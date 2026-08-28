"""
Interactive Demonstration Script: Deterministic Behavioral Detectors.
Demonstrates:
  1. Individual detector outputs across all 6 threat categories.
  2. Supporting evidence dictionaries and explainable reasons.
  3. Integration into the central ThreatFusionEngine.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.detectors.models import BehavioralDetectorsConfig
from app.detectors.behavioral_engine import BehavioralDetectionEngine
from app.telemetry.feature_schema import TelemetryFeatureVector_v2
from app.ml.hybrid_inference import HybridInferenceEngine

def run_demo():
    print("=" * 95)
    print("DETERMINISTIC BEHAVIORAL DETECTORS DEMONSTRATION")
    print("=" * 95)

    engine = BehavioralDetectionEngine()
    hybrid = HybridInferenceEngine()

    test_scenarios = [
        (
            "Normal Browsing Traffic",
            TelemetryFeatureVector_v2(
                flow_id="192.168.1.100:54321 -> 142.250.190.46:443 [TCP]",
                timestamp=1724832000.0,
                packet_rate=4.5,
                syn_ratio=0.08,
                unique_dst_ports=1.0,
                shannon_entropy_mean=2.1,
                iat_cv=0.75,
                outbound_bytes=1500.0,
                inbound_bytes=45000.0,
                out_in_byte_ratio=0.033,
                asymmetric_traffic_score=-0.935,
                tls_version_num=1.3,
                has_tls_sni=1.0
            )
        ),
        (
            "Distributed SYN Flood (DDoS)",
            TelemetryFeatureVector_v2(
                flow_id="172.16.4.32:65519 -> 10.0.0.1:80 [TCP]",
                timestamp=1724832000.0,
                packet_rate=1200.0,
                syn_ratio=1.0,
                src_ip_entropy=4.91,
                unique_src_count=50.0,
                dst_in_degree=50.0,
                byte_amplification_ratio=0.0
            )
        ),
        (
            "Vertical Port Scan",
            TelemetryFeatureVector_v2(
                flow_id="192.168.1.50:51722 -> 192.168.1.1:69 [TCP]",
                timestamp=1724832000.0,
                unique_dst_ports=35.0,
                dst_port_fanout=12.5,
                failed_conn_ratio=0.92,
                conn_attempts=35.0
            )
        ),
        (
            "DNS Tunnelling / DGA Exfil",
            TelemetryFeatureVector_v2(
                flow_id="192.168.1.75:51696 -> 8.8.8.8:53 [UDP]",
                timestamp=1724832000.0,
                shannon_entropy_mean=3.79,
                query_len_mean=32.0,
                txt_record_ratio=1.0,
                ngram_log_likelihood=-9.21,
                query_frequency=12.0
            )
        ),
        (
            "C2 Cobalt Strike Beaconing",
            TelemetryFeatureVector_v2(
                flow_id="10.0.5.12:49152 -> 198.51.100.42:8443 [TCP]",
                timestamp=1724832000.0,
                iat_mean=1.001,
                iat_cv=0.012,
                periodicity_score=0.42,
                repeated_conn_count=25.0,
                repeated_dst_freq=60.0
            )
        ),
        (
            "Unauthorized Data Exfiltration",
            TelemetryFeatureVector_v2(
                flow_id="192.168.1.105:54321 -> 203.0.113.50:443 [TCP]",
                timestamp=1724832000.0,
                outbound_bytes=120_000_000.0,
                inbound_bytes=45_000.0,
                out_in_byte_ratio=2666.6,
                asymmetric_traffic_score=0.999,
                outbound_rate=1_500_000.0
            )
        ),
        (
            "Direct IP TLS Malware C2 (No SNI)",
            TelemetryFeatureVector_v2(
                flow_id="192.168.1.105:54321 -> 198.51.100.5:443 [TCP]",
                timestamp=1724832000.0,
                tls_version_num=1.2,
                has_tls_sni=0.0,
                directionality_ratio=0.96,
                pkt_size_entropy=0.45
            )
        )
    ]

    for title, fv in test_scenarios:
        print(f"\n[+] SCENARIO: {title}")
        print(f"    Flow: {fv.flow_id}")
        
        # 1. Evaluate individual behavioral detectors
        results = engine.evaluate_all(fv)
        triggered = [r for r in results if r.triggered]
        print(f"    Behavioral Triggers: {len(triggered)} / {len(results)}")
        
        for r in results:
            status = "TRIGGERED [!]" if r.triggered else "OK"
            print(f"      * {r.category:<20}: {status:<15} score={r.score:.2f} | {r.human_readable_reason}")
            if r.triggered and r.supporting_evidence:
                print(f"        Evidence: {r.supporting_evidence}")

        # 2. Evaluate Central Fusion Engine
        fusion = hybrid.predict(fv)
        print(f"    >>> FUSION VERDICT: {fusion.threat_label} (Confidence: {fusion.confidence * 100:.1f}%)")
        print(f"        Decision State: {fusion.decision_state} | Method: {fusion.detection_method}")

    print("\n" + "=" * 95)
    print("DEMO COMPLETE: All Deterministic Behavioral Detectors Operational & Integrated.")
    print("=" * 95)

if __name__ == "__main__":
    run_demo()
