import pytest
from app.core.parser import PassivePacketParser
from app.core.models import FlowKey, TCPFlags

def test_parse_truncated_packet():
    ts = 1724832000.0
    truncated_bytes = b"\x00\x01\x02\x03"
    meta = PassivePacketParser.parse_raw_packet(ts, truncated_bytes)
    assert meta.is_malformed is True
    assert meta.wire_length == 4
    assert "smaller than Ethernet" in meta.error_message

def test_parse_corrupt_packet():
    ts = 1724832000.0
    corrupt_bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\xff\xff\xff"
    meta = PassivePacketParser.parse_raw_packet(ts, corrupt_bytes)
    assert meta.is_malformed is True or meta.flow_key.protocol in ("UNKNOWN", "CORRUPT", "IP_PROTO_255")

def test_flow_key_unidirectional_and_bidirectional():
    key1 = FlowKey(src_ip="192.168.1.5", dst_ip="10.0.0.1", src_port=54321, dst_port=80, protocol="TCP")
    key2 = FlowKey(src_ip="10.0.0.1", dst_ip="192.168.1.5", src_port=80, dst_port=54321, protocol="TCP")
    
    # Unidirectional must distinguish client-to-server vs server-to-client
    assert key1.unidirectional_id == "192.168.1.5:54321 -> 10.0.0.1:80 [TCP]"
    assert key2.unidirectional_id == "10.0.0.1:80 -> 192.168.1.5:54321 [TCP]"
    assert key1.unidirectional_id != key2.unidirectional_id
    
    # Bidirectional normalized form must match
    assert key1.bidirectional_id == key2.bidirectional_id
    assert len(key1.flow_hash) == 32
