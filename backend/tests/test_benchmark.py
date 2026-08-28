import time
from pathlib import Path
from app.core.ingestion import PcapStreamReader
from app.config import SAMPLES_DIR

def run_performance_benchmark():
    pcap_file = SAMPLES_DIR / "syn_flood.pcap"
    reader = PcapStreamReader(pcap_file)
    
    start = time.perf_counter()
    packet_count = 0
    byte_count = 0
    
    # Process 5 iterations to test sustained streaming throughput
    for _ in range(5):
        for pkt in reader.stream_packets():
            packet_count += 1
            byte_count += pkt.wire_length
            
    elapsed = time.perf_counter() - start
    pps = packet_count / elapsed
    mbps = (byte_count * 8) / (elapsed * 1_000_000)
    
    print("=" * 60)
    print("MODULE 1 PERFORMANCE BENCHMARK RESULT")
    print("=" * 60)
    print(f"Total Packets Ingested & Parsed: {packet_count:,}")
    print(f"Total Bytes Streamed:            {byte_count:,} bytes")
    print(f"Total Processing Time:           {elapsed:.4f} s")
    print(f"Throughput (Packets/sec):        {pps:,.0f} pkts/s")
    print(f"Throughput (Bandwidth):          {mbps:,.2f} Mbps")
    print("=" * 60)
    assert pps > 5000, f"Expected > 5000 pkts/s, got {pps:.0f}"

if __name__ == "__main__":
    run_performance_benchmark()
