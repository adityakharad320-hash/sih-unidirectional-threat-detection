import os
import time
import logging
from typing import Generator, Optional, List
from pathlib import Path
import dpkt
from app.core.models import PacketMetadata, IngestionStats
from app.core.parser import PassivePacketParser

logger = logging.getLogger(__name__)

class PcapStreamReader:
    """
    Incremental, memory-bounded streaming PCAP reader.
    Passively yields PacketMetadata records without loading the whole file.
    """

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        self.stats = IngestionStats()

    def stream_packets(
        self,
        speed_factor: Optional[float] = None,
        max_packets: Optional[int] = None
    ) -> Generator[PacketMetadata, None, None]:
        self.stats = IngestionStats()
        start_wall_time = time.perf_counter()
        first_pcap_ts: Optional[float] = None

        with open(self.pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(f)
                except Exception as e:
                    logger.error(f"Failed to open PCAP file {self.pcap_path}: {e}")
                    raise

            for ts, buf in pcap:
                if self.stats.start_timestamp is None:
                    self.stats.start_timestamp = float(ts)
                    first_pcap_ts = float(ts)

                self.stats.end_timestamp = float(ts)
                self.stats.total_packets_read += 1
                self.stats.total_bytes += len(buf)

                if speed_factor is not None and speed_factor > 0 and first_pcap_ts is not None:
                    pcap_offset = (float(ts) - first_pcap_ts) / speed_factor
                    wall_offset = time.perf_counter() - start_wall_time
                    delay = pcap_offset - wall_offset
                    if delay > 0:
                        time.sleep(min(delay, 0.05))

                meta = PassivePacketParser.parse_raw_packet(float(ts), buf)
                if meta.is_malformed:
                    self.stats.malformed_packets += 1
                else:
                    self.stats.valid_packets += 1

                yield meta

                if max_packets and self.stats.total_packets_read >= max_packets:
                    break

        elapsed = time.perf_counter() - start_wall_time
        self.stats.elapsed_processing_time = elapsed
        if elapsed > 0:
            self.stats.throughput_pps = self.stats.total_packets_read / elapsed
            self.stats.throughput_mbps = (self.stats.total_bytes * 8) / (elapsed * 1_000_000)

        logger.info(
            f"PCAP Stream finished: {self.stats.total_packets_read} packets "
            f"({self.stats.valid_packets} valid, {self.stats.malformed_packets} malformed) in "
            f"{elapsed:.3f}s ({self.stats.throughput_pps:.0f} pkts/s, {self.stats.throughput_mbps:.2f} Mbps)"
        )
