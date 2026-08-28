"""
Normalized Internal Event Telemetry Schema.

Decouples downstream feature engineering, ML models, and SOC dashboards
from vendor-specific log formats (Zeek ASCII/JSON, Suricata EVE, etc.).
"""
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
import hashlib

EventType = Literal["connection", "dns", "tls", "http", "alert", "file", "generic"]

class NormalizedBaseEvent(BaseModel):
    """Common foundation for all network and security telemetry events."""
    event_id: str
    timestamp: float  # Epoch timestamp in seconds (microsecond resolution)
    event_type: EventType
    source_engine: str  # "zeek", "suricata", "custom"
    
    # Network 5-tuple
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"  # TCP, UDP, ICMP, etc.

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}]"

    @property
    def flow_hash(self) -> str:
        return hashlib.md5(self.flow_id.encode("utf-8")).hexdigest()

class NormalizedConnectionEvent(NormalizedBaseEvent):
    """Normalized L4 Connection telemetry (Zeek conn.log / Suricata flow)."""
    event_type: EventType = "connection"
    
    duration: float = 0.0
    orig_bytes: int = 0      # Outbound/Source-to-Destination bytes
    resp_bytes: int = 0      # Inbound/Destination-to-Source bytes
    orig_pkts: int = 0       # Outbound packets
    resp_pkts: int = 0       # Inbound packets
    conn_state: Optional[str] = None  # S0, S1, SF, REJ, OTH, etc. (Zeek state)
    history: Optional[str] = None     # Flag history e.g. "ShADdFaf"
    service: Optional[str] = None     # Detected service e.g. "dns", "http", "ssl"
    missed_bytes: int = 0

class NormalizedDNSEvent(NormalizedBaseEvent):
    """Normalized DNS transaction telemetry (Zeek dns.log / Suricata dns)."""
    event_type: EventType = "dns"
    
    trans_id: Optional[int] = None
    query_name: str
    query_type: Optional[int] = None
    query_type_name: str = "A"       # A, AAAA, TXT, MX, PTR, ANY, etc.
    response_code: int = 0           # 0=NOERROR, 3=NXDOMAIN, etc.
    response_code_name: str = "NOERROR"
    answers: List[str] = Field(default_factory=list)
    ttls: List[int] = Field(default_factory=list)
    rejected: bool = False

class NormalizedTLSEvent(NormalizedBaseEvent):
    """
    Normalized unencrypted TLS/SSL handshake metadata (Zeek ssl.log / Suricata tls).
    Strictly observes ClientHello/ServerHello/Certificates WITHOUT payload decryption.
    """
    event_type: EventType = "tls"
    
    version: Optional[str] = None         # "TLSv1.2", "TLSv1.3", etc.
    cipher: Optional[str] = None          # Negotiated cipher suite
    sni_server_name: Optional[str] = None # Cleartext Server Name Indication
    established: bool = False
    resumed: bool = False
    
    # Fingerprints & Validation
    ja3: Optional[str] = None             # Client fingerprint MD5
    ja3s: Optional[str] = None            # Server fingerprint MD5
    ja4: Optional[str] = None             # JA4 fingerprint
    validation_status: Optional[str] = None
    subject: Optional[str] = None         # Certificate Subject DN
    issuer: Optional[str] = None          # Certificate Issuer DN

class NormalizedHTTPEvent(NormalizedBaseEvent):
    """Normalized HTTP transaction metadata (Zeek http.log / Suricata http)."""
    event_type: EventType = "http"
    
    method: str = "GET"
    host: str = ""
    uri: str = "/"
    user_agent: Optional[str] = None
    status_code: int = 200
    status_msg: Optional[str] = None
    request_body_len: int = 0
    response_body_len: int = 0
    mime_type: Optional[str] = None

class NormalizedSecurityAlert(NormalizedBaseEvent):
    """Normalized security detection event (Suricata alert)."""
    event_type: EventType = "alert"
    
    signature_id: int
    signature: str
    category: str = "Generic Security Event"
    severity: int = 3                # 1=High, 2=Medium, 3=Low, 4=Info (Suricata scale)
    action: str = "allowed"          # "allowed" (passive), "blocked"
    gid: int = 1
    rev: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
