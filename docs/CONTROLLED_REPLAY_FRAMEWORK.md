# Controlled Demonstration & Traffic Replay Framework

## Overview
This document specifies the **Controlled Demonstration and Replay Framework** for the **AI-Based Unidirectional Threat Detection Platform (SIH 2026 Problem Statement 26145 - NTRO)**.

The framework produces controlled synthetic network traffic using **Scapy** in a sandboxed, non-routable environment (`RFC 1918` and `RFC 5737` test blocks). Generated PCAPs are replayed through the **exact same passive ingestion, feature extraction, hybrid ML, fusion, and alert pipeline**.

---

## 1. Scenario Documentation Matrix

### Scenario 1: Normal Benign Web Traffic (`benign_traffic.pcap`)
* **Simulated Behavior**: Standard client DNS lookup for `google.com` followed by an HTTPS TLS v1.3 handshake with valid Server Name Indication (SNI) and download-heavy HTTP response payloads with natural human inter-arrival timing.
* **Key Feature Signatures**: `syn_ratio: 0.10`, `ack_ratio: 0.90`, `iat_cv: >0.50` (high variance), `asymmetric_traffic_score: <0.0` (inbound download dominant), `has_tls_sni: 1.0`.
* **Responsible Detection Layer**: Random Forest Classifier (`BENIGN`) + Baseline Isolation Forest.
* **Expected Alert**: `BENIGN` / `INFO` (Zero threat alerts generated).

---

### Scenario 2: Distributed Volumetric SYN Flood (`syn_flood.pcap`)
* **Simulated Behavior**: 500 TCP SYN-only packets transmitted at high velocity ($1,000\text{ pkts/s}$) targeting server `10.0.0.1:80` with 50 distinct spoofed source IP addresses.
* **Key Feature Signatures**: `syn_ratio: 1.00`, `src_ip_entropy: 4.91 bits`, `unique_src_count: 50`, `dst_in_degree: 50`, `packet_rate: >500 pkts/s`.
* **Responsible Detection Layer**: Supervised Random Forest (`DDOS`) + `ddos_behavioral_detector`.
* **Expected Alert**: `DDOS` / `CRITICAL` (Decision State: `A: KNOWN_THREAT_CONFIRMED`).

---

### Scenario 3: Vertical Reconnaissance Port Scan (`port_scan.pcap`)
* **Simulated Behavior**: 100 single-SYN probes from scanner `192.168.1.50` sequentially scanning ports 1 through 100 on victim host `192.168.1.1` without completing TCP handshakes.
* **Key Feature Signatures**: `unique_dst_ports: 100`, `dst_port_fanout: >10.0 ports/s`, `failed_conn_ratio: >0.85` (unestablished S0 states), `conn_attempts: 100`.
* **Responsible Detection Layer**: Supervised Random Forest (`PORT_SCAN`) + `port_scan_behavioral_detector`.
* **Expected Alert**: `PORT_SCAN` / `HIGH` (Decision State: `A: KNOWN_THREAT_CONFIRMED`).

---

### Scenario 4: Algorithmic DNS / DGA Tunnelling (`dga_dns_tunnel.pcap`)
* **Simulated Behavior**: High-entropy algorithmic subdomain DNS requests querying TXT records (`v8x9a2k1z7q3m5p8.tunnel.corp.internal`, `b3m7x9q1z8k2v5p4.exfil.data.security`).
* **Key Feature Signatures**: `shannon_entropy_mean: >3.60 bits`, `query_len_mean: >25 chars`, `txt_record_ratio: 1.00`, `ngram_log_likelihood: <-5.00`.
* **Responsible Detection Layer**: `dns_dga_behavioral_detector`.
* **Expected Alert**: `DGA_DNS_TUNNELLING` / `HIGH` (Decision State: `B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)`).

---

### Scenario 5: Command & Control (C2) Beaconing (`c2_beaconing.pcap`)
* **Simulated Behavior**: 20 periodic TCP PSH-ACK status heartbeats transmitted with rigid $1.0\text{s}$ spacing ($\text{jitter} \le 0.002\text{s}$) to external C2 server `198.51.100.42:8443`.
* **Key Feature Signatures**: `iat_mean: 1.001s`, `iat_cv: <0.05` (ultra-rigid timing), `periodicity_score: >0.30` (dominant FFT spectral peak), `repeated_conn_count: 20`.
* **Responsible Detection Layer**: `c2_beaconing_behavioral_detector` + Isolation Forest Anomaly Detection.
* **Expected Alert**: `C2_BEACONING` / `CRITICAL` (Decision State: `B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)` or `C: UNKNOWN_ANOMALY`).

---

### Scenario 6: Unauthorized Data Exfiltration (`data_exfiltration.pcap`)
* **Simulated Behavior**: Massive asymmetric outbound TCP payload transfer ($56,000\text{ bytes}$ outbound vs $<500\text{ bytes}$ inbound ACKs) to foreign server `203.0.113.50:443`.
* **Key Feature Signatures**: `outbound_bytes: >50,000 B`, `out_in_byte_ratio: >50.0x`, `asymmetric_traffic_score: >+0.95` (heavy upload asymmetry), `outbound_rate: >10,000 B/s`.
* **Responsible Detection Layer**: `data_exfiltration_behavioral_detector`.
* **Expected Alert**: `DATA_EXFILTRATION` / `CRITICAL` (Decision State: `B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)`).
