import socket
import struct
import logging
from typing import Optional
import dpkt
from app.core.models import PacketMetadata, FlowKey, TCPFlags, DNSMetadata, TLSMetadata

logger = logging.getLogger(__name__)

DNS_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
}

class PassivePacketParser:
    """
    Ultra-fast passive packet parser using dpkt.
    Zero packet transmission, zero payload decryption.
    Extracts L3/L4/L7 metadata and handles malformed packets gracefully.
    """

    @staticmethod
    def _ip_to_str(inet_bytes: bytes) -> str:
        try:
            if len(inet_bytes) == 4:
                return socket.inet_ntoa(inet_bytes)
            elif len(inet_bytes) == 16:
                return socket.inet_ntop(socket.AF_INET6, inet_bytes)
        except Exception:
            pass
        return "0.0.0.0"

    @classmethod
    def parse_raw_packet(cls, ts: float, raw_bytes: bytes) -> PacketMetadata:
        wire_len = len(raw_bytes)
        if wire_len < 14:
            return PacketMetadata(
                timestamp=ts,
                wire_length=wire_len,
                ip_length=0,
                header_length=0,
                payload_length=0,
                flow_key=FlowKey(src_ip="0.0.0.0", dst_ip="0.0.0.0", src_port=0, dst_port=0, protocol="UNKNOWN"),
                is_malformed=True,
                error_message="Packet length smaller than Ethernet header (14 bytes)"
            )

        try:
            eth_type = 0
            try:
                eth = dpkt.ethernet.Ethernet(raw_bytes)
                ip_obj = eth.data
                eth_type = eth.type
            except Exception:
                try:
                    ip_obj = dpkt.ip.IP(raw_bytes)
                    eth_type = dpkt.ethernet.ETH_TYPE_IP
                except Exception:
                    ip_obj = dpkt.ip6.IP6(raw_bytes)
                    eth_type = dpkt.ethernet.ETH_TYPE_IP6

            # If Ethernet claimed IPv4/IPv6 but decoding failed to produce an IP object
            if (eth_type in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6) or eth_type == 0x0800) and not isinstance(ip_obj, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return PacketMetadata(
                    timestamp=ts,
                    wire_length=wire_len,
                    ip_length=0,
                    header_length=14,
                    payload_length=len(ip_obj) if isinstance(ip_obj, (bytes, bytearray)) else 0,
                    flow_key=FlowKey(src_ip="0.0.0.0", dst_ip="0.0.0.0", src_port=0, dst_port=0, protocol="MALFORMED_IP"),
                    is_malformed=True,
                    error_message="Truncated or malformed IP header in Ethernet frame"
                )

            if isinstance(ip_obj, dpkt.ip.IP):
                src_ip = cls._ip_to_str(ip_obj.src)
                dst_ip = cls._ip_to_str(ip_obj.dst)
                ip_proto = ip_obj.p
                ip_len = ip_obj.len
                ip_hl = ip_obj.hl * 4
                l4_obj = ip_obj.data
            elif isinstance(ip_obj, dpkt.ip6.IP6):
                src_ip = cls._ip_to_str(ip_obj.src)
                dst_ip = cls._ip_to_str(ip_obj.dst)
                ip_proto = ip_obj.nxt
                ip_len = ip_obj.plen + 40
                ip_hl = 40
                l4_obj = ip_obj.data
            else:
                return PacketMetadata(
                    timestamp=ts,
                    wire_length=wire_len,
                    ip_length=0,
                    header_length=14,
                    payload_length=0,
                    flow_key=FlowKey(src_ip="0.0.0.0", dst_ip="0.0.0.0", src_port=0, dst_port=0, protocol="NON_IP"),
                    is_malformed=False,
                    error_message="Non-IP packet"
                )

            src_port = 0
            dst_port = 0
            proto_str = "OTHER"
            tcp_flags = None
            tcp_window = None
            tcp_seq = None
            tcp_ack = None
            icmp_type = None
            icmp_code = None
            dns_meta = None
            tls_meta = None
            l4_hl = 0
            payload_len = 0

            if isinstance(l4_obj, dpkt.tcp.TCP):
                proto_str = "TCP"
                src_port = l4_obj.sport
                dst_port = l4_obj.dport
                l4_hl = l4_obj.off * 4
                flags_val = l4_obj.flags
                tcp_flags = TCPFlags(
                    fin=bool(flags_val & dpkt.tcp.TH_FIN),
                    syn=bool(flags_val & dpkt.tcp.TH_SYN),
                    rst=bool(flags_val & dpkt.tcp.TH_RST),
                    psh=bool(flags_val & dpkt.tcp.TH_PUSH),
                    ack=bool(flags_val & dpkt.tcp.TH_ACK),
                    urg=bool(flags_val & dpkt.tcp.TH_URG),
                    ece=bool(flags_val & dpkt.tcp.TH_ECE),
                    cwr=bool(flags_val & dpkt.tcp.TH_CWR)
                )
                tcp_window = l4_obj.win
                tcp_seq = l4_obj.seq
                tcp_ack = l4_obj.ack
                payload_len = len(l4_obj.data)

                if (dst_port == 443 or src_port == 443) and payload_len > 5:
                    tls_meta = cls._extract_tls_metadata(l4_obj.data)

            elif isinstance(l4_obj, dpkt.udp.UDP):
                proto_str = "UDP"
                src_port = l4_obj.sport
                dst_port = l4_obj.dport
                l4_hl = 8
                payload_len = len(l4_obj.data)

                if src_port == 53 or dst_port == 53:
                    dns_meta = cls._extract_dns_metadata(l4_obj.data)

            elif isinstance(l4_obj, dpkt.icmp.ICMP) or ip_proto == 1:
                proto_str = "ICMP"
                if isinstance(l4_obj, dpkt.icmp.ICMP):
                    icmp_type = l4_obj.type
                    icmp_code = l4_obj.code
                    payload_len = len(l4_obj.data) if hasattr(l4_obj, "data") else 0
                l4_hl = 8
            else:
                proto_str = f"IP_PROTO_{ip_proto}"
                payload_len = len(l4_obj) if isinstance(l4_obj, (bytes, bytearray)) else 0

            flow_key = FlowKey(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_str
            )

            return PacketMetadata(
                timestamp=ts,
                wire_length=wire_len,
                ip_length=ip_len,
                header_length=ip_hl + l4_hl,
                payload_length=payload_len,
                flow_key=flow_key,
                tcp_flags=tcp_flags,
                tcp_window_size=tcp_window,
                tcp_seq_num=tcp_seq,
                tcp_ack_num=tcp_ack,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                dns_meta=dns_meta,
                tls_meta=tls_meta,
                is_malformed=False
            )

        except Exception as e:
            return PacketMetadata(
                timestamp=ts,
                wire_length=wire_len,
                ip_length=0,
                header_length=0,
                payload_length=0,
                flow_key=FlowKey(src_ip="0.0.0.0", dst_ip="0.0.0.0", src_port=0, dst_port=0, protocol="CORRUPT"),
                is_malformed=True,
                error_message=str(e)
            )

    @classmethod
    def _extract_dns_metadata(cls, payload: bytes) -> Optional[DNSMetadata]:
        try:
            dns = dpkt.dns.DNS(payload)
            q_name = None
            q_type = None
            q_type_str = None
            if dns.qd:
                q = dns.qd[0]
                q_name = str(q.name) if q.name else None
                q_type = q.type
                q_type_str = DNS_TYPE_MAP.get(q_type, f"TYPE_{q_type}")

            answers = []
            if dns.an:
                for an in dns.an:
                    if hasattr(an, "name") and an.name:
                        answers.append(str(an.name))

            return DNSMetadata(
                query_name=q_name,
                query_type=q_type,
                query_type_name=q_type_str,
                is_response=bool(dns.qr),
                response_code=dns.rcode,
                answers=answers
            )
        except Exception:
            return None

    @classmethod
    def _extract_tls_metadata(cls, payload: bytes) -> Optional[TLSMetadata]:
        try:
            if len(payload) < 9:
                return None
            record_type = payload[0]
            if record_type != 0x16:
                return None
            handshake_type = payload[5]
            if handshake_type != 0x01:
                return TLSMetadata(handshake_type=handshake_type)

            sni = None
            idx = 43
            if idx < len(payload):
                sess_len = payload[idx]
                idx += 1 + sess_len
                if idx + 2 <= len(payload):
                    cipher_len = struct.unpack("!H", payload[idx:idx+2])[0]
                    idx += 2 + cipher_len
                    if idx + 1 <= len(payload):
                        comp_len = payload[idx]
                        idx += 1 + comp_len
                        if idx + 2 <= len(payload):
                            ext_total_len = struct.unpack("!H", payload[idx:idx+2])[0]
                            idx += 2
                            end_ext = min(len(payload), idx + ext_total_len)
                            while idx + 4 <= end_ext:
                                ext_type, ext_len = struct.unpack("!HH", payload[idx:idx+4])
                                idx += 4
                                if ext_type == 0x0000 and idx + ext_len <= end_ext:
                                    sni_idx = idx + 2
                                    if sni_idx + 3 <= idx + ext_len:
                                        name_type = payload[sni_idx]
                                        name_len = struct.unpack("!H", payload[sni_idx+1:sni_idx+3])[0]
                                        sni_idx += 3
                                        if name_type == 0 and sni_idx + name_len <= idx + ext_len:
                                            sni = payload[sni_idx:sni_idx+name_len].decode("utf-8", errors="ignore")
                                    break
                                idx += ext_len

            return TLSMetadata(
                sni=sni,
                handshake_type=handshake_type
            )
        except Exception:
            return None
