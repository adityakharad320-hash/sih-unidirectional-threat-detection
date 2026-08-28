"""
Streaming Telemetry Flow Tracker & Behavioral Graph Engine.

Maintains sliding-window states across:
1. 5-Tuple L4 connection flows.
2. Host communication graphs (in-degree, out-degree, bipartite neighbors).
3. L7 DNS query buffers and TLS handshake contexts.
"""
import time
import math
import collections
from typing import Dict, List, Optional, Set, Tuple
from app.telemetry.schema import (
    NormalizedBaseEvent,
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedSecurityAlert
)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

class TelemetryFlowState:
    """
    State container for an active unidirectional/bidirectional flow session.
    Uses bounded deques for strictly bounded O(1) memory per flow.
    """
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
        
        # Volumetric & L4 Accumulators
        self.duration: float = 0.0
        self.orig_bytes: int = 0
        self.resp_bytes: int = 0
        self.orig_pkts: int = 0
        self.resp_pkts: int = 0
        self.conn_states: collections.deque = collections.deque(maxlen=100)
        self.history: Optional[str] = None
        
        # Bounded temporal history for IAT / beaconing
        self.timestamps: collections.deque = collections.deque(maxlen=500)
        self.packet_sizes: collections.deque = collections.deque(maxlen=500)
        
        # L7 DNS Context
        self.dns_queries: collections.deque = collections.deque(maxlen=100)
        self.dns_record_types: collections.deque = collections.deque(maxlen=100)
        
        # L7 TLS Context
        self.tls_version: Optional[str] = None
        self.tls_sni: Optional[str] = None
        self.ja3: Optional[str] = None
        self.has_tls: bool = False

    def update_connection(self, event: NormalizedConnectionEvent):
        self.last_seen = event.timestamp
        self.event_count += 1
        self.duration = max(self.duration, event.duration)
        self.orig_bytes += event.orig_bytes
        self.resp_bytes += event.resp_bytes
        self.orig_pkts += event.orig_pkts
        self.resp_pkts += event.resp_pkts
        self.timestamps.append(event.timestamp)
        
        if event.orig_bytes > 0:
            self.packet_sizes.append(event.orig_bytes)
        if event.resp_bytes > 0:
            self.packet_sizes.append(event.resp_bytes)
            
        if event.conn_state:
            self.conn_states.append(event.conn_state)
        if event.history:
            self.history = event.history

    def update_dns(self, event: NormalizedDNSEvent):
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

class HostGraphTracker:
    """
    Sliding-window behavioral graph tracking communication edges,
    in-degree, out-degree, and fan-out/fan-in metrics.
    """
    def __init__(self, window_sec: float = 60.0):
        self.window_sec = window_sec
        # Edge buffer: (timestamp, src_ip, dst_ip, dst_port)
        self.edges: collections.deque = collections.deque(maxlen=10000)
        
        # High-speed in-memory adjacency
        self.src_to_dsts: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        self.src_to_ports: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        self.dst_to_srcs: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        self.total_network_packets: int = 0
        self.dst_packet_counts: Dict[str, int] = collections.defaultdict(int)

    def add_event(self, ts: float, src_ip: str, dst_ip: str, dst_port: int, pkts: int = 1):
        self.edges.append((ts, src_ip, dst_ip, dst_port))
        self.src_to_dsts[src_ip].append((ts, dst_ip))
        self.src_to_ports[src_ip].append((ts, dst_port))
        self.dst_to_srcs[dst_ip].append((ts, src_ip))
        self.total_network_packets += max(1, pkts)
        self.dst_packet_counts[dst_ip] += max(1, pkts)

    def get_graph_metrics(self, src_ip: str, dst_ip: str, current_ts: float) -> Tuple[float, float, float, float]:
        cutoff = current_ts - self.window_sec
        
        # Out-degree & unique targets
        recent_dsts = {d for ts, d in self.src_to_dsts[src_ip] if ts >= cutoff}
        src_out_degree = float(len(recent_dsts))
        
        # In-degree & unique sources targeting victim
        recent_srcs = {s for ts, s in self.dst_to_srcs[dst_ip] if ts >= cutoff}
        dst_in_degree = float(len(recent_srcs))
        
        # Communication partner count (neighbors)
        comm_partners = src_out_degree + float(len({s for ts, s in self.dst_to_srcs[src_ip] if ts >= cutoff}))
        
        # Fanout ratio
        total_out_attempts = sum(1 for ts, d in self.src_to_dsts[src_ip] if ts >= cutoff)
        graph_fanout_ratio = float(src_out_degree / max(1, total_out_attempts))
        
        return src_out_degree, dst_in_degree, comm_partners, graph_fanout_ratio

class StreamingTelemetryTracker:
    """
    Global Telemetry State Engine managing flow tables, graphs, and TTL cleanups.
    """
    def __init__(self, idle_timeout: float = 60.0, max_active_flows: int = 50_000):
        self.idle_timeout = idle_timeout
        self.max_active_flows = max_active_flows
        self.active_flows: Dict[str, TelemetryFlowState] = {}
        self.graph_tracker = HostGraphTracker(window_sec=60.0)
        self.host_conn_timestamps: Dict[Tuple[str, str], collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=500))

    def process_event(self, event: NormalizedBaseEvent) -> TelemetryFlowState:
        fid = event.flow_id
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        dst_port = event.dst_port

        if fid not in self.active_flows:
            if len(self.active_flows) >= self.max_active_flows:
                self.evict_stale_flows(event.timestamp)
            self.active_flows[fid] = TelemetryFlowState(
                fid, src_ip, dst_ip, event.src_port, dst_port, event.protocol, event.timestamp
            )

        state = self.active_flows[fid]

        # Track persistent host communication timestamps for C2 beaconing analysis across ephemeral flows
        self.host_conn_timestamps[(src_ip, dst_ip)].append(event.timestamp)

        # Update specific telemetry context
        pkts = 1
        if isinstance(event, NormalizedConnectionEvent):
            state.update_connection(event)
            pkts = event.orig_pkts + event.resp_pkts
        elif isinstance(event, NormalizedDNSEvent):
            state.update_dns(event)
        elif isinstance(event, NormalizedTLSEvent):
            state.update_tls(event)
        else:
            state.last_seen = event.timestamp
            state.timestamps.append(event.timestamp)

        # Update behavioral graph
        self.graph_tracker.add_event(event.timestamp, src_ip, dst_ip, dst_port, pkts=pkts)

        return state

    def evict_stale_flows(self, current_ts: float):
        cutoff = current_ts - self.idle_timeout
        stale_keys = [k for k, state in self.active_flows.items() if state.last_seen < cutoff]
        for k in stale_keys:
            del self.active_flows[k]
