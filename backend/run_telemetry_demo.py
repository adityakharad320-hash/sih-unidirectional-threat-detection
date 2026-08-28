"""
Interactive Telemetry Layer Demonstration Script.
Replays sample PCAPs to produce Zeek and Suricata telemetry logs,
then streams normalized events through the unified internal schema.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.schema import (
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedSecurityAlert
)
from app.config import SAMPLES_DIR, DATA_DIR

def run_demo():
    print("=" * 85)
    print("TELEMETRY LAYER DEMO: ZEEK + SURICATA PASSIVE REPLAY & NORMALIZATION")
    print("=" * 85)

    staging_dir = DATA_DIR / "telemetry_staging"
    samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap"
    ]

    for pcap_name in samples:
        pcap_path = SAMPLES_DIR / pcap_name
        pcap_out = staging_dir / pcap_path.stem
        print(f"\n[+] Replaying PCAP: {pcap_name}")
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, pcap_out)
        print(f"    Generated logs in: {pcap_out}")

        streamer = TelemetryStreamer(pcap_out)
        events = list(streamer.stream_all_events())
        print(f"    Normalized Telemetry Events Extracted: {len(events)}")

        # Print sample records by type
        for e in events[:4]:
            if isinstance(e, NormalizedConnectionEvent):
                print(f"    - [CONN] {e.source_engine.upper()}: {e.flow_id} | dur={e.duration:.4f}s | orig_bytes={e.orig_bytes} | state={e.conn_state}")
            elif isinstance(e, NormalizedDNSEvent):
                print(f"    - [DNS ] {e.source_engine.upper()}: {e.flow_id} | query='{e.query_name}' ({e.query_type_name}) | answers={e.answers}")
            elif isinstance(e, NormalizedTLSEvent):
                print(f"    - [TLS ] {e.source_engine.upper()}: {e.flow_id} | version={e.version} | sni='{e.sni_server_name}' | cipher={e.cipher}")
            elif isinstance(e, NormalizedSecurityAlert):
                print(f"    - [ALRT] {e.source_engine.upper()}: {e.flow_id} | signature='{e.signature}' | sev={e.severity} | action={e.action}")

    print("\n" + "=" * 85)
    print("DEMO COMPLETE: Normalized Telemetry Stream Ready for Downstream ML & Feature Extraction.")
    print("=" * 85)

if __name__ == "__main__":
    run_demo()
