from pathlib import Path
import random
import time
from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

def generate_sample_pcaps(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Benign Web & DNS Traffic PCAP
    benign_pkts = []
    base_time = 1724832000.0
    t = base_time
    
    domains = ["google.com", "github.com", "microsoft.com", "wikipedia.org"]
    for d in domains:
        dns_req = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=DNSQR(qname=d))
        dns_req.time = t
        benign_pkts.append(dns_req)
        t += 0.05
        
        dns_resp = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=dns_req[UDP].sport)/DNS(qr=1, aa=1, qd=DNSQR(qname=d), an=DNSRR(rrname=d, rdata="93.184.216.34"))
        dns_resp.time = t
        benign_pkts.append(dns_resp)
        t += 0.02
        
    for i in range(5):
        sport = 50000 + i
        syn = Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=sport, dport=443, flags="S", seq=1000)
        syn.time = t
        benign_pkts.append(syn)
        t += 0.01
        
        psh = Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001)/Raw(load=b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c" + b"A"*20)
        psh.time = t
        benign_pkts.append(psh)
        t += 0.05

    wrpcap(str(output_dir / "benign_traffic.pcap"), benign_pkts)

    # 2. SYN Flood Attack PCAP
    syn_flood_pkts = []
    t = base_time
    target_ip = "10.0.0.1"
    target_port = 80
    for i in range(500):
        fake_src = f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}"
        pkt = Ether()/IP(src=fake_src, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S", seq=random.randint(1000, 999999))
        pkt.time = t
        syn_flood_pkts.append(pkt)
        t += 0.001
    wrpcap(str(output_dir / "syn_flood.pcap"), syn_flood_pkts)

    # 3. Port Scan PCAP
    scan_pkts = []
    t = base_time
    scanner_ip = "192.168.1.50"
    victim_ip = "192.168.1.1"
    for port in range(20, 120):
        pkt = Ether()/IP(src=scanner_ip, dst=victim_ip)/TCP(sport=random.randint(30000, 60000), dport=port, flags="S", seq=port*100)
        pkt.time = t
        scan_pkts.append(pkt)
        t += 0.005
    wrpcap(str(output_dir / "port_scan.pcap"), scan_pkts)

    # 4. DGA / DNS Tunnel Queries PCAP
    dga_pkts = []
    t = base_time
    dga_domains = [
        "xq89zlkj4v91a0c8.badc2.org",
        "m9a1c77f02d948ea.xyz",
        "dGVzdF9leGZpbHRyYXRpb25fZGF0YQ.tunnel.net",
        "3a7f8e1b2c4d9a0f.cc"
    ]
    for d in dga_domains:
        pkt = Ether()/IP(src="192.168.1.75", dst="8.8.8.8")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=DNSQR(qname=d, qtype="TXT"))
        pkt.time = t
        dga_pkts.append(pkt)
        t += 0.02
    wrpcap(str(output_dir / "dga_dns_tunnel.pcap"), dga_pkts)

    # 5. C2 Periodic Beaconing PCAP
    beacon_pkts = []
    t = base_time
    c2_ip = "198.51.100.42"
    infected_host = "10.0.5.12"
    interval = 1.0
    for i in range(20):
        pkt = Ether()/IP(src=infected_host, dst=c2_ip)/TCP(sport=49152, dport=8443, flags="PA", seq=i*100)/Raw(load=b"HEARTBEAT_BEACON_ID=99")
        pkt.time = t + random.uniform(-0.02, 0.02)
        beacon_pkts.append(pkt)
        t += interval
    wrpcap(str(output_dir / "c2_beaconing.pcap"), beacon_pkts)

    print(f"Generated 5 sample PCAP files in {output_dir}")

if __name__ == "__main__":
    generate_sample_pcaps(Path(r"C:\Users\ADITYA\.gemini\antigravity\scratch\sih2026_threat_detection\backend\data\samples"))
