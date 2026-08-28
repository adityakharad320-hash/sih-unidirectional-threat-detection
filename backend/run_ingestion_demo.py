"""
Module 1 Live Ingestion Demonstration Script
Streams through sample PCAPs passively and displays live parsed packet/flow observations.
"""
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.ingestion import PcapStreamReader
from app.config import SAMPLES_DIR

def demonstrate_pcap(sample_name: str, max_display: int = 5):
    pcap_path = SAMPLES_DIR / sample_name
    print("\n" + "=" * 80)
    print(f"STREAMING PCAP: {sample_name} (Passive Read-Only Mode)")
    print("=" * 80)
    
    reader = PcapStreamReader(pcap_path)
    count = 0
    
    for pkt in reader.stream_packets():
        count += 1
        if count <= max_display:
            flags_info = f"Flags: [{pkt.tcp_flags.summary_string}]" if pkt.tcp_flags else ""
            dns_info = f"DNS Query: '{pkt.dns_meta.query_name}' ({pkt.dns_meta.query_type_name})" if pkt.dns_meta and pkt.dns_meta.query_name else ""
            tls_info = f"TLS SNI: '{pkt.tls_meta.sni}'" if pkt.tls_meta and pkt.tls_meta.sni else ""
            extra = " | ".join(filter(None, [flags_info, dns_info, tls_info]))
            
            print(f"[{count:03d}] ts={pkt.timestamp:.6f} | {pkt.flow_key.unidirectional_id:<45} | len={pkt.wire_length:<4} | {extra}")

    if count > max_display:
        print(f"... and {count - max_display} more packets streamed incrementally.")
        
    s = reader.stats
    print("-" * 80)
    print(f"Summary: {s.total_packets_read} packets | {s.total_bytes:,} bytes | Elapsed: {s.elapsed_processing_time*1000:.2f}ms | Throughput: {s.throughput_pps:,.0f} pkts/s ({s.throughput_mbps:.2f} Mbps)")
    print("-" * 80)

def main():
    samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap"
    ]
    for s in samples:
        demonstrate_pcap(s)

if __name__ == "__main__":
    main()
