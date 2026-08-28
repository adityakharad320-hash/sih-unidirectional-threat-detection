from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import hashlib

class FlowKey(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    @property
    def unidirectional_id(self) -> str:
        return f'{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}]'

    @property
    def bidirectional_id(self) -> str:
        ep1 = (self.src_ip, self.src_port)
        ep2 = (self.dst_ip, self.dst_port)
        if ep1 <= ep2:
            return f'{ep1[0]}:{ep1[1]} <-> {ep2[0]}:{ep2[1]} [{self.protocol}]'
        else:
            return f'{ep2[0]}:{ep2[1]} <-> {ep1[0]}:{ep1[1]} [{self.protocol}]'

    @property
    def flow_hash(self) -> str:
        return hashlib.md5(self.unidirectional_id.encode('utf-8')).hexdigest()

class DNSMetadata(BaseModel):
    query_name: Optional[str] = None
    query_type: Optional[int] = None
    query_type_name: Optional[str] = None
    is_response: bool = False
    response_code: Optional[int] = None
    answers: List[str] = Field(default_factory=list)

class TLSMetadata(BaseModel):
    sni: Optional[str] = None
    cipher_suites: List[int] = Field(default_factory=list)
    ja3_string: Optional[str] = None
    ja3_hash: Optional[str] = None
    handshake_type: Optional[int] = None

class TCPFlags(BaseModel):
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False

    @property
    def summary_string(self) -> str:
        flags = []
        if self.syn: flags.append('SYN')
        if self.ack: flags.append('ACK')
        if self.fin: flags.append('FIN')
        if self.rst: flags.append('RST')
        if self.psh: flags.append('PSH')
        if self.urg: flags.append('URG')
        if self.ece: flags.append('ECE')
        if self.cwr: flags.append('CWR')
        return '+'.join(flags) if flags else 'NONE'

class PacketMetadata(BaseModel):
    timestamp: float
    wire_length: int
    ip_length: int
    header_length: int
    payload_length: int
    flow_key: FlowKey
    tcp_flags: Optional[TCPFlags] = None
    tcp_window_size: Optional[int] = None
    tcp_seq_num: Optional[int] = None
    tcp_ack_num: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    dns_meta: Optional[DNSMetadata] = None
    tls_meta: Optional[TLSMetadata] = None
    is_malformed: bool = False
    error_message: Optional[str] = None

class IngestionStats(BaseModel):
    total_packets_read: int = 0
    valid_packets: int = 0
    malformed_packets: int = 0
    total_bytes: int = 0
    start_timestamp: Optional[float] = None
    end_timestamp: Optional[float] = None
    elapsed_processing_time: float = 0.0
    throughput_pps: float = 0.0
    throughput_mbps: float = 0.0
