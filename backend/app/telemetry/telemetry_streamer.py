"""
Telemetry Streamer & Chronological Aggregator.

Ingests Zeek log directories and Suricata EVE streams, merges them,
and yields normalized events sorted by timestamp for downstream feature extraction.
"""
import logging
from pathlib import Path
from typing import Generator, List, Optional, Union
from app.telemetry.schema import (
    NormalizedBaseEvent,
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedSecurityAlert
)
from app.telemetry.zeek_parser import ZeekLogParser
from app.telemetry.suricata_parser import SuricataEveParser

logger = logging.getLogger(__name__)

class TelemetryStreamer:
    """
    Streams and normalizes heterogeneous telemetry sources (Zeek + Suricata).
    """

    def __init__(self, telemetry_dir: Union[str, Path]):
        self.telemetry_dir = Path(telemetry_dir)
        if not self.telemetry_dir.exists():
            raise FileNotFoundError(f"Telemetry directory does not exist: {self.telemetry_dir}")

    def stream_all_events(self) -> Generator[NormalizedBaseEvent, None, None]:
        """
        Gathers all available Zeek logs and Suricata EVE files in telemetry_dir,
        normalizes them, and yields events in chronological order.
        """
        all_events: List[NormalizedBaseEvent] = []

        # 1. Parse Zeek Logs
        # Look for conn.log / conn.log.gz / conn.json
        conn_files = list(self.telemetry_dir.glob("conn.*")) + list(self.telemetry_dir.glob("**/conn.*"))
        for cf in conn_files:
            for row in ZeekLogParser.stream_log_file(cf):
                event = ZeekLogParser.normalize_conn_record(row)
                if event:
                    all_events.append(event)

        dns_files = list(self.telemetry_dir.glob("dns.*")) + list(self.telemetry_dir.glob("**/dns.*"))
        for df in dns_files:
            for row in ZeekLogParser.stream_log_file(df):
                event = ZeekLogParser.normalize_dns_record(row)
                if event:
                    all_events.append(event)

        ssl_files = list(self.telemetry_dir.glob("ssl.*")) + list(self.telemetry_dir.glob("**/ssl.*"))
        for sf in ssl_files:
            for row in ZeekLogParser.stream_log_file(sf):
                event = ZeekLogParser.normalize_ssl_record(row)
                if event:
                    all_events.append(event)

        http_files = list(self.telemetry_dir.glob("http.*")) + list(self.telemetry_dir.glob("**/http.*"))
        for hf in http_files:
            for row in ZeekLogParser.stream_log_file(hf):
                event = ZeekLogParser.normalize_http_record(row)
                if event:
                    all_events.append(event)

        # 2. Parse Suricata EVE logs
        eve_files = list(self.telemetry_dir.glob("eve*.json")) + list(self.telemetry_dir.glob("**/eve*.json"))
        for ef in eve_files:
            for event in SuricataEveParser.stream_eve_file(ef):
                all_events.append(event)

        # Sort chronologically by timestamp
        all_events.sort(key=lambda e: e.timestamp)

        for e in all_events:
            yield e
