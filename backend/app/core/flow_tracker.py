"""
Stateful Streaming Flow Tracker and Window Aggregator.
Maintains unidirectional flow states in bounded ring-buffers with automated TTL eviction.
"""
import time
import math
import collections
from typing import Dict, List, Optional, Set, Tuple
from app.core.models import PacketMetadata, FlowKey

class FlowState:
    """
    State container for an active unidirectional flow.
    Uses collections.deque with maxlen to strictly bound memory.
    """
    def __init__(self, flow_key: FlowKey, first_seen: float, max_history: int = 1000):
        self.flow_key = flow_key
        self.first_seen: float = first_seen
        self.last_seen: float = first_seen
        self.packet_count: int = 0
        self.byte_count: int = 0
        
        # Bounded ring buffers
        self.timestamps: collections.deque = collections.deque(maxlen=max_history)
        self.packet_sizes: collections.deque = collections.deque(maxlen=max_history)
        
        # TCP Flag Counters
        self.tcp_syn_count: int = 0
        self.tcp_ack_count: int = 0
        self.tcp_rst_count: int = 0
        self.tcp_fin_count: int = 0
        self.tcp_psh_count: int = 0
        self.tcp_syn_ack_count: int = 0
        self.total_tcp_packets: int = 0
        
        # DNS & TLS buffers
        self.dns_queries: collections.deque = collections.deque(maxlen=100)
        self.dns_record_types: collections.deque = collections.deque(maxlen=100)
        self.tls_sni: Optional[str] = None
        self.has_tls_handshake: bool = False

    def update(self, pkt: PacketMetadata):
        self.last_seen = pkt.timestamp
        self.packet_count += 1
        self.byte_count += pkt.wire_length
        self.timestamps.append(pkt.timestamp)
        self.packet_sizes.append(pkt.wire_length)

        if pkt.tcp_flags:
            self.total_tcp_packets += 1
            if pkt.tcp_flags.syn and not pkt.tcp_flags.ack:
                self.tcp_syn_count += 1
            if pkt.tcp_flags.syn and pkt.tcp_flags.ack:
                self.tcp_syn_ack_count += 1
            if pkt.tcp_flags.ack and not pkt.tcp_flags.syn:
                self.tcp_ack_count += 1
            if pkt.tcp_flags.rst:
                self.tcp_rst_count += 1
            if pkt.tcp_flags.fin:
                self.tcp_fin_count += 1
            if pkt.tcp_flags.psh:
                self.tcp_psh_count += 1

        if pkt.dns_meta and pkt.dns_meta.query_name:
            self.dns_queries.append(pkt.dns_meta.query_name)
            if pkt.dns_meta.query_type_name:
                self.dns_record_types.append(pkt.dns_meta.query_type_name)

        if pkt.tls_meta:
            self.has_tls_handshake = True
            if pkt.tls_meta.sni:
                self.tls_sni = pkt.tls_meta.sni

class StreamingFlowTracker:
    """
    Global flow registry managing active flows, host fanout, and TTL cleanups.
    """
    def __init__(self, idle_timeout: float = 30.0, max_active_flows: int = 50_000):
        self.idle_timeout = idle_timeout
        self.max_active_flows = max_active_flows
        self.active_flows: Dict[str, FlowState] = {}
        
        # Reconnaissance / Scan trackers (Key: src_ip -> set of destinations within window)
        self.src_dst_ports: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        self.src_dst_hosts: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        self.src_syn_times: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=5000))
        
        # Destination incoming source tracker for DDoS entropy (Key: dst_ip -> set of src_ips)
        self.dst_src_ips: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=10000))

    def process_packet(self, pkt: PacketMetadata) -> FlowState:
        flow_id = pkt.flow_key.unidirectional_id
        src_ip = pkt.flow_key.src_ip
        dst_ip = pkt.flow_key.dst_ip
        dst_port = pkt.flow_key.dst_port

        # Update or create flow state
        if flow_id not in self.active_flows:
            # Capacity guard
            if len(self.active_flows) >= self.max_active_flows:
                self.evict_stale_flows(pkt.timestamp)
            self.active_flows[flow_id] = FlowState(pkt.flow_key, pkt.timestamp)

        state = self.active_flows[flow_id]
        state.update(pkt)

        # Update host/port reconnaissance records
        self.src_dst_ports[src_ip].append((pkt.timestamp, dst_port))
        self.src_dst_hosts[src_ip].append((pkt.timestamp, dst_ip))
        self.dst_src_ips[dst_ip].append((pkt.timestamp, src_ip))

        if pkt.tcp_flags and pkt.tcp_flags.syn:
            self.src_syn_times[src_ip].append(pkt.timestamp)

        return state

    def evict_stale_flows(self, current_ts: float):
        """Evict flows that have been idle longer than idle_timeout."""
        stale_keys = [
            k for k, state in self.active_flows.items()
            if (current_ts - state.last_seen) > self.idle_timeout
        ]
        for k in stale_keys:
            del self.active_flows[k]
