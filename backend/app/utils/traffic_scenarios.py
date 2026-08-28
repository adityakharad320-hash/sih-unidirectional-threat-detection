"""
Controlled Traffic Scenario Generator using Scapy.

Generates 6 distinct, high-fidelity synthetic PCAPs in sandboxed, non-routable
IP ranges for deterministic testing and demonstration:
1. BENIGN: Multi-session DNS + HTTPS TLS web traffic.
2. SYN FLOOD (DDoS): Distributed SYN flood targeting 10.0.0.1:80 from 50 spoofed IPs.
3. PORT SCAN: Vertical reconnaissance scanning across 100 ports on 192.168.1.1.
4. DNS / DGA TUNNEL: Algorithmic high-entropy TXT record queries.
5. C2 BEACONING: Periodic 1.0s interval heartbeats with ultra-low jitter.
6. DATA EXFILTRATION: Asymmetric heavy outbound TCP payload upload.
"""
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

from app.config import SAMPLES_DIR

logger = logging.getLogger(__name__)

class ControlledTrafficGenerator:
    """Generates synthetic PCAPs for controlled evaluation."""
    
    @staticmethod
    def generate_benign(output_path: Path) -> Path:
        """Scenario 1: Normal bidirectional DNS and HTTPS web traffic."""
        pkts = []
        base_t = 1724832000.0
        
        # 1. DNS Query & Response
        t = base_t
        pkts.append(Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/
                    DNS(rd=1, qd=DNSQR(qname="google.com", qtype="A")))
        pkts[-1].time = t
        
        t += 0.02
        pkts.append(Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=54321)/
                    DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="google.com", qtype="A"),
                        an=DNSRR(rrname="google.com", rdata="142.250.190.46", ttl=300)))
        pkts[-1].time = t
        
        # 2. HTTPS TLS Handshake to 142.250.190.46:443
        t += 0.05
        # Client SYN
        pkts.append(Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=50004, dport=443, flags="S", seq=1000))
        pkts[-1].time = t
        # Server SYN-ACK
        t += 0.015
        pkts.append(Ether()/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=443, dport=50004, flags="SA", seq=2000, ack=1001))
        pkts[-1].time = t
        # Client ACK
        t += 0.005
        pkts.append(Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=50004, dport=443, flags="A", seq=1001, ack=2001))
        pkts[-1].time = t
        
        # Client TLS ClientHello with SNI "google.com"
        t += 0.01
        sni_payload = (
            b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03" + b"\x00" * 32 + b"\x00"
            b"\x00\x02\x13\x01\x01\x00\x00\x8b\x00\x00\x00\x0f\x00\x0d\x00\x00\n"
            b"google.com"
        )
        pkts.append(Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=50004, dport=443, flags="PA", seq=1001, ack=2001)/Raw(load=sni_payload))
        pkts[-1].time = t
        
        # Server Data & Response
        for i in range(12):
            t += 0.05 + (i * 0.02)  # Natural human timing variance
            pkts.append(Ether()/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=443, dport=50004, flags="PA", seq=2001 + (i*1000), ack=1001 + len(sni_payload))/Raw(load=b"X" * 900))
            pkts[-1].time = t

        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 1 (BENIGN): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_syn_flood(output_path: Path, count: int = 500) -> Path:
        """Scenario 2: Distributed Volumetric SYN Flood targeting 10.0.0.1:80."""
        pkts = []
        base_t = 1724832000.0
        
        for i in range(count):
            t = base_t + (i * 0.001)  # 1000 pkts/s
            src_ip = f"172.16.{i % 10}.{(i % 50) + 1}"  # 50 spoofed source IPs -> high entropy
            sport = 1024 + (i % 64000)
            pkt = Ether()/IP(src=src_ip, dst="10.0.0.1")/TCP(sport=sport, dport=80, flags="S", seq=100000 + i)
            pkt.time = t
            pkts.append(pkt)
            
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 2 (SYN FLOOD): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_port_scan(output_path: Path, ports_count: int = 100) -> Path:
        """Scenario 3: Vertical Reconnaissance Port Scan probing ports 1-100."""
        pkts = []
        base_t = 1724832000.0
        
        for i in range(ports_count):
            t = base_t + (i * 0.01)  # 100 probes/s
            dport = i + 1
            sport = 40000 + (i % 5000)
            pkt = Ether()/IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="S", seq=50000 + i)
            pkt.time = t
            pkts.append(pkt)
            
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 3 (PORT SCAN): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_dga_dns_tunnel(output_path: Path) -> Path:
        """Scenario 4: Algorithmic high-entropy TXT record DNS tunnelling queries."""
        pkts = []
        base_t = 1724832000.0
        
        dga_domains = [
            "v8x9a2k1z7q3m5p8.tunnel.corp.internal",
            "b3m7x9q1z8k2v5p4.exfil.data.security",
            "q1w2e3r4t5y6u7i8.covert.channel.net",
            "z9y8x7w6v5u4t3s2.dga.malware.beacon"
        ]
        
        for i, domain in enumerate(dga_domains):
            t = base_t + (i * 0.25)
            sport = 50000 + i
            # TXT record query with long payload subdomain
            pkt = Ether()/IP(src="192.168.1.75", dst="8.8.8.8")/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
            pkt.time = t
            pkts.append(pkt)
            
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 4 (DNS/DGA TUNNEL): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_c2_beaconing(output_path: Path, count: int = 20) -> Path:
        """Scenario 5: Periodic 1.0s interval C2 heartbeats with ultra-low jitter."""
        pkts = []
        base_t = 1724832000.0
        
        for i in range(count):
            # 1.0s rigid periodic timing
            t = base_t + (i * 1.0)
            payload = b"C2_HEARTBEAT_STATUS_OK_ID_" + str(i).encode()
            pkt = Ether()/IP(src="10.0.5.12", dst="198.51.100.42")/TCP(
                sport=49152, dport=8443, flags="PA", seq=1000 + (i*50), ack=2000
            )/Raw(load=payload)
            pkt.time = t
            pkts.append(pkt)
            
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 5 (C2 BEACONING): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_data_exfiltration(output_path: Path, chunk_count: int = 40) -> Path:
        """Scenario 6: Asymmetric heavy outbound TCP payload upload to external IP."""
        pkts = []
        base_t = 1724832000.0
        
        # 1. Handshake to 203.0.113.50:443
        t = base_t
        pkts.append(Ether()/IP(src="192.168.1.105", dst="203.0.113.50")/TCP(sport=54321, dport=443, flags="S", seq=1000))
        pkts[-1].time = t
        t += 0.02
        pkts.append(Ether()/IP(src="203.0.113.50", dst="192.168.1.105")/TCP(sport=443, dport=54321, flags="SA", seq=5000, ack=1001))
        pkts[-1].time = t
        t += 0.005
        pkts.append(Ether()/IP(src="192.168.1.105", dst="203.0.113.50")/TCP(sport=54321, dport=443, flags="A", seq=1001, ack=5001))
        pkts[-1].time = t
        
        # 2. Outbound heavy data burst (40 chunks x 1400 bytes = 56,000 bytes outbound)
        for i in range(chunk_count):
            t += 0.01
            payload = b"EXFILTRATED_DATA_BLOCK_" + (b"A" * 1350)
            pkt = Ether()/IP(src="192.168.1.105", dst="203.0.113.50")/TCP(
                sport=54321, dport=443, flags="PA", seq=1001 + (i * 1400), ack=5001
            )/Raw(load=payload)
            pkt.time = t
            pkts.append(pkt)
            
            # Occasional small ACK from server
            if i % 10 == 0:
                t += 0.002
                ack_pkt = Ether()/IP(src="203.0.113.50", dst="192.168.1.105")/TCP(
                    sport=443, dport=54321, flags="A", seq=5001, ack=1001 + ((i+1) * 1400)
                )
                ack_pkt.time = t
                pkts.append(ack_pkt)

        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 6 (DATA EXFILTRATION): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @classmethod
    def generate_all_scenarios(cls, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        out = output_dir or SAMPLES_DIR
        out.mkdir(parents=True, exist_ok=True)
        return {
            "BENIGN": cls.generate_benign(out / "benign_traffic.pcap"),
            "SYN_FLOOD": cls.generate_syn_flood(out / "syn_flood.pcap"),
            "PORT_SCAN": cls.generate_port_scan(out / "port_scan.pcap"),
            "DGA_DNS_TUNNEL": cls.generate_dga_dns_tunnel(out / "dga_dns_tunnel.pcap"),
            "C2_BEACONING": cls.generate_c2_beaconing(out / "c2_beaconing.pcap"),
            "DATA_EXFILTRATION": cls.generate_data_exfiltration(out / "data_exfiltration.pcap")
        }
