import pytest
from app.core.ingestion import PcapStreamReader
from app.core.flow_tracker import StreamingFlowTracker
from app.core.feature_extractor import StreamingFeatureExtractor
from app.config import SAMPLES_DIR

def test_syn_flood_feature_extraction():
    pcap_path = SAMPLES_DIR / "syn_flood.pcap"
    reader = PcapStreamReader(pcap_path)
    tracker = StreamingFlowTracker()
    
    last_fv = None
    for pkt in reader.stream_packets():
        state = tracker.process_packet(pkt)
        last_fv = StreamingFeatureExtractor.extract_features(state, tracker)
        
    assert last_fv is not None
    # High SYN ratio
    assert last_fv.syn_ratio == 1.0
    # High packet rate
    assert last_fv.packet_rate > 100.0

def test_port_scan_feature_extraction():
    pcap_path = SAMPLES_DIR / "port_scan.pcap"
    reader = PcapStreamReader(pcap_path)
    tracker = StreamingFlowTracker()
    
    last_fv = None
    for pkt in reader.stream_packets():
        state = tracker.process_packet(pkt)
        last_fv = StreamingFeatureExtractor.extract_features(state, tracker)
        
    assert last_fv is not None
    # Unique destination ports targeted
    assert last_fv.unique_dst_ports >= 50
    assert last_fv.dst_port_fanout > 10.0

def test_dga_dns_feature_extraction():
    pcap_path = SAMPLES_DIR / "dga_dns_tunnel.pcap"
    reader = PcapStreamReader(pcap_path)
    tracker = StreamingFlowTracker()
    
    last_fv = None
    for pkt in reader.stream_packets():
        state = tracker.process_packet(pkt)
        last_fv = StreamingFeatureExtractor.extract_features(state, tracker)
        
    assert last_fv is not None
    assert last_fv.dns_entropy_mean > 3.0
    assert last_fv.dns_txt_record_ratio == 1.0

def test_c2_beaconing_feature_extraction():
    pcap_path = SAMPLES_DIR / "c2_beaconing.pcap"
    reader = PcapStreamReader(pcap_path)
    tracker = StreamingFlowTracker()
    
    last_fv = None
    for pkt in reader.stream_packets():
        state = tracker.process_packet(pkt)
        last_fv = StreamingFeatureExtractor.extract_features(state, tracker)
        
    assert last_fv is not None
    assert 0.9 <= last_fv.iat_mean <= 1.1
    assert last_fv.iat_cv < 0.10
