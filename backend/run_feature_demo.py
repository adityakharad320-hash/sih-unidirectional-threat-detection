"""
Interactive Feature Extraction Verification Demo
Processes sample PCAPs through Ingestion -> Flow Tracking -> Feature Extraction,
and prints key numerical feature vectors.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.ingestion import PcapStreamReader
from app.core.flow_tracker import StreamingFlowTracker
from app.core.feature_extractor import StreamingFeatureExtractor
from app.config import SAMPLES_DIR

def run_feature_inspection(sample_name: str):
    pcap_path = SAMPLES_DIR / sample_name
    print("\n" + "=" * 90)
    print(f"FEATURE EXTRACTION DEMO: {sample_name}")
    print("=" * 90)
    
    reader = PcapStreamReader(pcap_path)
    tracker = StreamingFlowTracker()
    
    feature_snapshots = []
    
    for pkt in reader.stream_packets():
        state = tracker.process_packet(pkt)
        # Snapshot when flow has processed a batch or completed
        fv = StreamingFeatureExtractor.extract_features(state, tracker)
        feature_snapshots.append(fv)
        
    last_fv = feature_snapshots[-1]
    d = last_fv.to_dict()
    
    print(f"Flow ID:          {last_fv.flow_id}")
    print(f"Window Duration:  {last_fv.window_duration_sec:.4f} s")
    print("-" * 90)
    print("EXTRACTED NUMERICAL FEATURES (Sample Subset):")
    print(f"  * Volumetric:     packet_rate={d['packet_rate']:.1f} pkts/s, syn_ratio={d['syn_ratio']:.2f}, ack_ratio={d['ack_ratio']:.2f}")
    print(f"  * Recon / Scan:   unique_dst_ports={d['unique_dst_ports']:.0f}, dst_port_fanout={d['dst_port_fanout']:.1f} ports/s")
    print(f"  * C2 Beaconing:   iat_mean={d['iat_mean']:.4f}s, iat_std={d['iat_std']:.4f}s, iat_cv={d['iat_cv']:.4f}, fft_peak={d['fft_peak_magnitude']:.3f}")
    print(f"  * DNS / DGA:      dns_entropy={d['dns_entropy_mean']:.3f} bits, txt_ratio={d['dns_txt_record_ratio']:.2f}, ngram_score={d['dns_ngram_score']:.3f}")
    print(f"  * Encrypted L7:   pkt_size_mean={d['pkt_size_mean']:.1f} B, has_tls_sni={d['has_tls_sni']:.0f}")
    print(f"  * Exfiltration:   outbound_bytes={d['outbound_bytes_total']:.0f} B, byte_velocity={d['byte_velocity']:.1f} B/s")
    print("-" * 90)
    print(f"Total Feature Dimensions in Dense NumPy Vector: {len(last_fv.to_numpy())}")
    print(f"NumPy Vector Preview: {last_fv.to_numpy()[:6]} ...")

def main():
    samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap"
    ]
    for s in samples:
        run_feature_inspection(s)

if __name__ == "__main__":
    main()
