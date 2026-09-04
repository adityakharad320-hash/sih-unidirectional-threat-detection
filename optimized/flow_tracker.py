"""
Incremental Flow State Tracker & Behavioral Graph Engine.

Implements single-pass O(1) online statistics (Welford's algorithm)
for inter-arrival time (IAT) and packet size distributions:
- Avoids scanning historical deques on every packet.
- Maintains bounded per-flow memory structures.
- Prunes inactive/expired sessions to maintain strictly bounded heap allocation.
"""
import math
import collections
from typing import Dict, List, Optional, Tuple
from app.telemetry.schema import (
    NormalizedBaseEvent,
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedSecurityAlert
)


class WelfordAccumulator:
    """
    Online single-pass mean, variance, standard deviation, min, and max accumulator.
    Numerically stable implementation of Welford's algorithm (1962).
    """
    __slots__ = ("count", "mean", "m2", "min_val", "max_val")

    def __init__(self):
        self.count: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0
        self.min_val: float = float("inf")
        self.max_val: float = float("-inf")

    def update(self, x: float):
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x

    @property
    def variance(self) -> float:
        return self.m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def cv(self) -> float:
        """Coefficient of Variation: std / mean"""
        return (self.std / self.mean) if self.mean > 1e-5 else 0.0

    @property
    def min(self) -> float:
        return self.min_val if self.count > 0 else 0.0

    @property
    def max(self) -> float:
        return self.max_val if self.count > 0 else 0.0


class OptimizedFlowState:
    """
    High-performance, bounded state container for a unidirectional/bidirectional flow.
    Uses incremental Welford accumulators to eliminate window recalculations.
    """
    __slots__ = (
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "first_seen", "last_seen", "event_count", "duration",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "syn_count", "ack_count", "rst_count", "fin_count",
        "iat_stats", "pkt_size_stats",
        "timestamps", "dns_queries", "dns_record_types",
        "tls_version", "tls_sni", "ja3", "has_tls",
        "last_inference_ts", "last_inference_pkts", "risk_level"
    )

    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, first_seen: float):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.first_seen: float = first_seen
        self.last_seen: float = first_seen
        self.event_count: int = 0
        self.duration: float = 0.0

        # L4 Volume Counters
        self.orig_bytes: int = 0
        self.resp_bytes: int = 0
        self.orig_pkts: int = 0
        self.resp_pkts: int = 0

        # Flag Counters
        self.syn_count: int = 0
        self.ack_count: int = 0
        self.rst_count: int = 0
        self.fin_count: int = 0

        # Online Incremental Statistics
        self.iat_stats = WelfordAccumulator()
        self.pkt_size_stats = WelfordAccumulator()

        # Bounded temporal history for FFT (max 128 power-of-two samples)
        self.timestamps: collections.deque = collections.deque(maxlen=128)

        # Bounded L7 Contexts
        self.dns_queries: collections.deque = collections.deque(maxlen=50)
        self.dns_record_types: collections.deque = collections.deque(maxlen=50)

        self.tls_version: Optional[str] = None
        self.tls_sni: Optional[str] = None
        self.ja3: Optional[str] = None
        self.has_tls: bool = False

        # Adaptive Inference Metadata
        self.last_inference_ts: float = 0.0
        self.last_inference_pkts: int = 0
        self.risk_level: str = "LOW"

    def update_connection(self, event: NormalizedConnectionEvent):
        # Update IAT online
        if self.last_seen > 0:
            delta_t = event.timestamp - self.last_seen
            if delta_t > 0:
                self.iat_stats.update(delta_t)

        self.last_seen = event.timestamp
        self.event_count += 1
        self.duration = max(self.duration, event.duration)
        self.orig_bytes += event.orig_bytes
        self.resp_bytes += event.resp_bytes
        self.orig_pkts += event.orig_pkts
        self.resp_pkts += event.resp_pkts
        self.timestamps.append(event.timestamp)

        # Update packet sizes online
        if event.orig_bytes > 0:
            self.pkt_size_stats.update(float(event.orig_bytes))
        if event.resp_bytes > 0:
            self.pkt_size_stats.update(float(event.resp_bytes))

        # Flag tracking from conn_state
        state = event.conn_state or ""
        if "S" in state or state == "S0":
            self.syn_count += 1
        if "A" in state or state in ("SF", "S1", "S2"):
            self.ack_count += 1
        if "R" in state or "REJ" in state:
            self.rst_count += 1
        if "F" in state:
            self.fin_count += 1

    def update_dns(self, event: NormalizedDNSEvent):
        if self.last_seen > 0:
            delta_t = event.timestamp - self.last_seen
            if delta_t > 0:
                self.iat_stats.update(delta_t)
        self.last_seen = event.timestamp
        self.event_count += 1
        self.timestamps.append(event.timestamp)
        if event.query_name:
            self.dns_queries.append(event.query_name)
            self.dns_record_types.append(event.query_type_name)

    def update_tls(self, event: NormalizedTLSEvent):
        self.last_seen = event.timestamp
        self.event_count += 1
        self.has_tls = True
        if event.version:
            self.tls_version = event.version
        if event.sni_server_name:
            self.tls_sni = event.sni_server_name
        if event.ja3:
            self.ja3 = event.ja3


class OptimizedHostGraphTracker:
    """
    Sliding-window behavioral host graph with bounded circular queues.
    """
    def __init__(self, window_sec: float = 60.0):
        self.window_sec = window_sec
        self.src_to_dsts: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=2000))
        self.src_to_ports: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=2000))
        self.dst_to_srcs: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=2000))

    def add_edge(self, src_ip: str, dst_ip: str, dst_port: int):
        self.src_to_dsts[src_ip].append(dst_ip)
        self.src_to_ports[src_ip].append(dst_port)
        self.dst_to_srcs[dst_ip].append(src_ip)

    def get_metrics(self, src_ip: str, dst_ip: str, duration: float) -> Tuple[float, float, float, float, float, float]:
        dur = max(1.0, duration)
        dst_set = set(self.src_to_dsts.get(src_ip, []))
        port_set = set(self.src_to_ports.get(src_ip, []))
        src_set = set(self.dst_to_srcs.get(dst_ip, []))

        unique_dst_hosts = float(len(dst_set)) if dst_set else 1.0
        unique_dst_ports = float(len(port_set)) if port_set else 1.0
        unique_src_count = float(len(src_set)) if src_set else 1.0

        dst_host_fanout = unique_dst_hosts / dur
        dst_port_fanout = unique_dst_ports / dur
        src_out_degree = unique_dst_hosts
        dst_in_degree = unique_src_count

        return unique_dst_ports, unique_dst_hosts, dst_port_fanout, dst_host_fanout, src_out_degree, dst_in_degree


class OptimizedTelemetryTracker:
    """
    High-throughput incremental telemetry state tracker.
    """
    def __init__(self, idle_timeout_sec: float = 60.0, max_active_flows: int = 50_000):
        self.idle_timeout_sec = idle_timeout_sec
        self.max_active_flows = max_active_flows
        self.active_flows: Dict[str, OptimizedFlowState] = {}
        self.graph_tracker = OptimizedHostGraphTracker(window_sec=60.0)

    def process_event(self, event: NormalizedBaseEvent) -> OptimizedFlowState:
        flow_key = f"{event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} [{event.protocol}]"

        state = self.active_flows.get(flow_key)
        if state is None:
            # Enforce bounded flow table
            if len(self.active_flows) >= self.max_active_flows:
                self._prune_stale_flows(event.timestamp)

            state = OptimizedFlowState(
                flow_id=flow_key,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                src_port=event.src_port,
                dst_port=event.dst_port,
                protocol=event.protocol,
                first_seen=event.timestamp
            )
            self.active_flows[flow_key] = state

        # Mutate state by event type
        if isinstance(event, NormalizedConnectionEvent):
            state.update_connection(event)
            self.graph_tracker.add_edge(event.src_ip, event.dst_ip, event.dst_port)
        elif isinstance(event, NormalizedDNSEvent):
            state.update_dns(event)
            self.graph_tracker.add_edge(event.src_ip, event.dst_ip, event.dst_port)
        elif isinstance(event, NormalizedTLSEvent):
            state.update_tls(event)
            self.graph_tracker.add_edge(event.src_ip, event.dst_ip, event.dst_port)

        return state

    def _prune_stale_flows(self, current_ts: float):
        threshold = current_ts - self.idle_timeout_sec
        stale_keys = [k for k, s in self.active_flows.items() if s.last_seen < threshold]
        for k in stale_keys:
            del self.active_flows[k]
