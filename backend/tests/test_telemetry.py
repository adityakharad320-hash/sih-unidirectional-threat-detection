"""
Unit & Integration Tests for Telemetry Layer (Zeek & Suricata Parsers & Schema).
"""
import pytest
import tempfile
import json
from pathlib import Path
from app.telemetry.schema import (
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedSecurityAlert
)
from app.telemetry.zeek_parser import ZeekLogParser
from app.telemetry.suricata_parser import SuricataEveParser
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.replay_runner import PcapReplayRunner
from app.config import SAMPLES_DIR

def test_zeek_tsv_conn_parser(tmp_path):
    conn_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
        "1724832000.123456\tC000001\t192.168.1.100\t54321\t10.0.0.1\t80\ttcp\thttp\t1.500000\t1024\t4096\tSF\tShADdFaf\t10\t12\n"
        "1724832001.000000\tC000002\t192.168.1.50\t49152\t10.0.0.2\t443\ttcp\t-\t-\t-\t-\tS0\tS\t1\t0\n"
    )
    log_file = tmp_path / "conn.log"
    log_file.write_text(conn_content, encoding="utf-8")

    records = list(ZeekLogParser.stream_log_file(log_file))
    assert len(records) == 2
    
    # First record validation
    event1 = ZeekLogParser.normalize_conn_record(records[0])
    assert event1 is not None
    assert event1.src_ip == "192.168.1.100"
    assert event1.dst_port == 80
    assert event1.protocol == "TCP"
    assert event1.duration == 1.5
    assert event1.orig_bytes == 1024
    assert event1.resp_bytes == 4096
    assert event1.conn_state == "SF"
    assert event1.orig_pkts == 10
    
    # Second record with null / '-' fields
    event2 = ZeekLogParser.normalize_conn_record(records[1])
    assert event2 is not None
    assert event2.conn_state == "S0"
    assert event2.duration == 0.0
    assert event2.orig_bytes == 0

def test_zeek_tsv_dns_parser(tmp_path):
    dns_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name\trcode\trcode_name\tanswers\n"
        "1724832000.500000\tD000001\t192.168.1.100\t48820\t8.8.8.8\t53\tudp\t1234\txq89zlkj4v91a0c8.badc2.org\tTXT\t0\tNOERROR\t\"payload_data_base64\",192.0.2.1\n"
    )
    log_file = tmp_path / "dns.log"
    log_file.write_text(dns_content, encoding="utf-8")

    records = list(ZeekLogParser.stream_log_file(log_file))
    assert len(records) == 1
    event = ZeekLogParser.normalize_dns_record(records[0])
    assert event is not None
    assert event.query_name == "xq89zlkj4v91a0c8.badc2.org"
    assert event.query_type_name == "TXT"
    assert len(event.answers) == 2
    assert event.response_code_name == "NOERROR"

def test_zeek_tsv_ssl_parser(tmp_path):
    ssl_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tserver_name\testablished\tja3\tja3s\n"
        "1724832000.750000\tS000001\t192.168.1.100\t51234\t142.250.190.46\t443\tTLSv1.3\tTLS_AES_128_GCM_SHA256\tgoogle.com\tT\tde350869b8c85de67a350c8d186f11e6\t-\n"
    )
    log_file = tmp_path / "ssl.log"
    log_file.write_text(ssl_content, encoding="utf-8")

    records = list(ZeekLogParser.stream_log_file(log_file))
    assert len(records) == 1
    event = ZeekLogParser.normalize_ssl_record(records[0])
    assert event is not None
    assert event.version == "TLSv1.3"
    assert event.sni_server_name == "google.com"
    assert event.established is True
    assert event.ja3 == "de350869b8c85de67a350c8d186f11e6"

def test_suricata_eve_parser(tmp_path):
    eve_content = (
        json.dumps({
            "timestamp": "2026-08-28T16:30:00.123456+00:00",
            "flow_id": 999123,
            "event_type": "alert",
            "src_ip": "172.16.4.152",
            "src_port": 48820,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2001219,
                "signature": "ET DOS Possible SYN Flood Inbound",
                "category": "Attempted Denial of Service",
                "severity": 1
            }
        }) + "\n" +
        json.dumps({
            "timestamp": "2026-08-28T16:30:01.000000+00:00",
            "flow_id": 999124,
            "event_type": "flow",
            "src_ip": "192.168.1.50",
            "src_port": 41356,
            "dest_ip": "192.168.1.1",
            "dest_port": 20,
            "proto": "TCP",
            "flow": {
                "bytes_toserver": 54,
                "bytes_toclient": 0,
                "pkts_toserver": 1,
                "pkts_toclient": 0,
                "age": 1
            }
        }) + "\n"
    )
    eve_file = tmp_path / "eve.json"
    eve_file.write_text(eve_content, encoding="utf-8")

    events = list(SuricataEveParser.stream_eve_file(eve_file))
    assert len(events) == 2

    # Verify Alert
    alert = events[0]
    assert isinstance(alert, NormalizedSecurityAlert)
    assert alert.signature_id == 2001219
    assert alert.severity == 1
    assert alert.action == "allowed"

    # Verify Flow
    flow = events[1]
    assert isinstance(flow, NormalizedConnectionEvent)
    assert flow.orig_bytes == 54
    assert flow.dst_port == 20

def test_pcap_replay_runner_and_telemetry_streamer(tmp_path):
    syn_pcap = SAMPLES_DIR / "syn_flood.pcap"
    out_dir = tmp_path / "telemetry_logs"
    
    # Replay PCAP to generate Zeek & Suricata telemetry
    PcapReplayRunner.replay_pcap_to_telemetry(syn_pcap, out_dir)
    assert (out_dir / "conn.log").exists()
    assert (out_dir / "eve.json").exists()

    # Stream through unified TelemetryStreamer
    streamer = TelemetryStreamer(out_dir)
    events = list(streamer.stream_all_events())
    assert len(events) > 0
    
    # Check that events are sorted chronologically
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)

def test_malformed_telemetry_resilience(tmp_path):
    corrupt_tsv = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\n"
        "1724832000.0\tC1\n"  # Too few columns
        "CORRUPT_TIMESTAMP\tC2\t10.0.0.1\n"
    )
    (tmp_path / "conn.log").write_text(corrupt_tsv, encoding="utf-8")
    
    corrupt_eve = "NOT_JSON\n{\"event_type\": \"unknown\"}\n"
    (tmp_path / "eve.json").write_text(corrupt_eve, encoding="utf-8")
    
    streamer = TelemetryStreamer(tmp_path)
    # Should not crash, returns valid/skipped events gracefully
    events = list(streamer.stream_all_events())
    assert isinstance(events, list)
