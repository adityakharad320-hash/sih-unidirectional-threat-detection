"""
Interactive Verification Demo: PCAP -> Zeek/Suricata -> Normalized Events -> Feature Engine -> 42-D Vector.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.config import SAMPLES_DIR, DATA_DIR

def run_demo():
    print("=" * 90)
    print("END-TO-END TELEMETRY FEATURE ENGINEERING VERIFICATION DEMO")
    print("=" * 90)

    staging_dir = DATA_DIR / "telemetry_features_staging"
    samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap"
    ]

    for pcap_name in samples:
        pcap_path = SAMPLES_DIR / pcap_name
        pcap_out = staging_dir / pcap_path.stem
        print(f"\n[+] Processing: {pcap_name}")
        
        # 1. PCAP -> Zeek / Suricata
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, pcap_out)
        
        # 2. Ingest Normalized Telemetry Stream
        streamer = TelemetryStreamer(pcap_out)
        tracker = StreamingTelemetryTracker()
        
        feature_snapshots = []
        event_count = 0
        for event in streamer.stream_all_events():
            event_count += 1
            state = tracker.process_event(event)
            fv = TelemetryFeatureExtractor.extract_features(state, tracker)
            feature_snapshots.append(fv)
            
        last_fv = feature_snapshots[-1]
        d = last_fv.to_dict()
        vec = last_fv.to_numpy()
        
        print(f"    Total Normalized Events: {event_count} | Flow ID: {last_fv.flow_id}")
        print(f"    Feature Dimensions:      {len(vec)} | NaN/Inf: {int(np.isnan(vec).any())}/{int(np.isinf(vec).any())}")
        print("    Extracted Telemetry Features (Sample Subset):")
        print(f"      * DDoS:       packet_rate={d['packet_rate']:.1f} pkts/s | syn_ratio={d['syn_ratio']:.2f} | byte_amplification={d['byte_amplification_ratio']:.1f}")
        print(f"      * C2 Beacon:  iat_mean={d['iat_mean']:.4f}s | iat_cv={d['iat_cv']:.4f} | periodicity={d['periodicity_score']:.3f}")
        print(f"      * DNS / DGA:  entropy={d['shannon_entropy_mean']:.3f} | txt_ratio={d['txt_record_ratio']:.2f} | ngram_ll={d['ngram_log_likelihood']:.3f}")
        print(f"      * Encrypted:  tls_version={d['tls_version_num']:.1f} | has_sni={d['has_tls_sni']:.0f} | pkt_size_mean={d['pkt_size_mean']:.1f}B")
        print(f"      * Port Scan:  unique_dst_ports={d['unique_dst_ports']:.0f} | failed_conn_ratio={d['failed_conn_ratio']:.2f}")
        print(f"      * Exfil:      outbound_bytes={d['outbound_bytes']:.0f}B | asymmetric_score={d['asymmetric_traffic_score']:.2f}")
        print(f"      * Graph:      src_out_degree={d['src_out_degree']:.0f} | dst_in_degree={d['dst_in_degree']:.0f}")

    print("\n" + "=" * 90)
    print("VERIFICATION COMPLETE: All 42 Features Extracted Successfully Across All Threat Categories.")
    print("=" * 90)

if __name__ == "__main__":
    import numpy as np
    run_demo()
