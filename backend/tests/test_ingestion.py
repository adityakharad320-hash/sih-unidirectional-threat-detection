import pytest
from pathlib import Path
from app.core.ingestion import PcapStreamReader
from app.config import SAMPLES_DIR

def test_stream_benign_pcap():
    pcap_file = SAMPLES_DIR / "benign_traffic.pcap"
    assert pcap_file.exists(), "Sample PCAP missing"
    
    reader = PcapStreamReader(pcap_file)
    packets = list(reader.stream_packets())
    
    assert len(packets) > 0
    assert reader.stats.total_packets_read == len(packets)
    assert reader.stats.valid_packets > 0
    assert reader.stats.malformed_packets == 0
    assert reader.stats.start_timestamp is not None
    assert reader.stats.end_timestamp >= reader.stats.start_timestamp
    
    # Verify DNS parsing
    dns_packets = [p for p in packets if p.dns_meta is not None]
    assert len(dns_packets) > 0
    assert any("google.com" in (p.dns_meta.query_name or "") for p in dns_packets)
    
    # Verify TCP flags
    tcp_packets = [p for p in packets if p.tcp_flags is not None]
    assert len(tcp_packets) > 0
    assert any(p.tcp_flags.syn for p in tcp_packets)

def test_stream_syn_flood():
    pcap_file = SAMPLES_DIR / "syn_flood.pcap"
    reader = PcapStreamReader(pcap_file)
    packets = list(reader.stream_packets())
    
    assert len(packets) == 500
    assert all(p.tcp_flags.syn and not p.tcp_flags.ack for p in packets)
    assert all(p.flow_key.dst_ip == "10.0.0.1" and p.flow_key.dst_port == 80 for p in packets)

def test_stream_port_scan():
    pcap_file = SAMPLES_DIR / "port_scan.pcap"
    reader = PcapStreamReader(pcap_file)
    packets = list(reader.stream_packets())
    
    assert len(packets) == 100
    unique_dst_ports = {p.flow_key.dst_port for p in packets}
    assert len(unique_dst_ports) == 100
