# SIH 2026 Feature Schema & Extraction Catalog (v1)

This catalog details the 32 numerical features extracted incrementally from unidirectional network traffic metadata.

## Summary Table

| Category | Feature Name | Type | Unit / Range | Meaning | Calculation | Threat Relevance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Volumetric / DDoS** | `packet_rate` | `float64` | pkts/sec | Packet transmission rate in active window | $N_{\text{packets}} / \Delta t$ | High surges indicate volumetric floods |
| **Volumetric / DDoS** | `byte_rate` | `float64` | bytes/sec | Byte transmission rate in active window | $N_{\text{bytes}} / \Delta t$ | Indicates bandwidth exhaustion |
| **Volumetric / DDoS** | `syn_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of SYN packets to total TCP packets | $N_{\text{SYN}} / N_{\text{TCP}}$ | Approaches $1.0$ in unidirectional SYN floods |
| **Volumetric / DDoS** | `ack_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of ACK packets to total TCP packets | $N_{\text{ACK}} / N_{\text{TCP}}$ | Assesses handshake completion and ACK-floods |
| **Volumetric / DDoS** | `rst_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of RST packets to total TCP packets | $N_{\text{RST}} / N_{\text{TCP}}$ | Teardown storms & scanner aborts |
| **Volumetric / DDoS** | `fin_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of FIN packets to total TCP packets | $N_{\text{FIN}} / N_{\text{TCP}}$ | FIN scan detection |
| **Volumetric / DDoS** | `syn_ack_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of SYN-ACK packets | $N_{\text{SYN-ACK}} / N_{\text{TCP}}$ | Server reflection flood identification |
| **Volumetric / DDoS** | `src_ip_entropy`| `float64` | bits | Shannon entropy of source IPs targeting destination | $-\sum p_i \log_2(p_i)$ | High entropy indicates distributed spoofed DDoS |
| **Volumetric / DDoS** | `unique_src_ips`| `float64` | count | Unique source IPs targeting destination | $|\{ \text{src\_ip}_i \}|$ | Distinguishes single-host from botnet floods |
| **Recon / Scan** | `unique_dst_ports` | `float64` | count | Unique ports targeted by source IP | $|\{ \text{dst\_port}_i \}|$ | Direct indicator of vertical port scan |
| **Recon / Scan** | `unique_dst_hosts` | `float64` | count | Unique hosts targeted by source IP | $|\{ \text{dst\_ip}_i \}|$ | Direct indicator of horizontal subnet scan |
| **Recon / Scan** | `dst_port_fanout` | `float64` | ports/sec | Rate of distinct ports contacted | $N_{\text{dst\_ports}} / \Delta t$ | Fast scanning tool velocity (Masscan/Nmap) |
| **Recon / Scan** | `dst_host_fanout` | `float64` | hosts/sec | Rate of distinct hosts contacted | $N_{\text{dst\_hosts}} / \Delta t$ | Subnet sweeping and worm spreading velocity |
| **Recon / Scan** | `connection_attempt_rate` | `float64` | attempts/sec | Initial connection attempts (SYN) per sec | $N_{\text{SYN}} / \Delta t$ | High brute-force probing rate |
| **C2 Beaconing** | `iat_mean` | `float64` | seconds | Mean packet inter-arrival time | $\mu(\Delta t)$ | Base heartbeat interval |
| **C2 Beaconing** | `iat_std` | `float64` | seconds | Standard deviation of inter-arrival time | $\sigma(\Delta t)$ | Low variance indicates rigid non-human polling |
| **C2 Beaconing** | `iat_cv` | `float64` | ratio | Jitter Coefficient of Variation | $\sigma / \mu$ | Values $< 0.15$ strongly signify C2 beacons |
| **C2 Beaconing** | `iat_skewness` | `float64` | dimensionless | Skewness of IAT distribution | $E[((X-\mu)/\sigma)^3]$ | Detects asymmetry in sleep-wake cycles |
| **C2 Beaconing** | `fft_peak_magnitude`| `float64` | $[0.0, 1.0]$ | Dominant FFT power peak fraction | $\max |FFT| / \sum |FFT|$ | Reveals hidden periodic signals with jitter |
| **C2 Beaconing** | `autocorr_max_peak` | `float64` | $[-1.0, 1.0]$ | Max secondary autocorrelation peak | $\max R_{xx}(\tau > 0)$ | Confirms repeating temporal signatures |
| **DNS / DGA** | `dns_query_len_mean`| `float64` | characters | Mean domain name query length | $\text{mean}(\text{len}(\text{domain}))$ | Elevated in DNS exfiltration tunnels |
| **DNS / DGA** | `dns_entropy_mean` | `float64` | bits | Mean Shannon character entropy of domain | $-\sum p_c \log_2 p_c$ | Values $> 3.8$ reveal algorithmic DGAs |
| **DNS / DGA** | `dns_txt_record_ratio`| `float64` | $[0.0, 1.0]$ | Ratio of TXT/NULL queries | $N_{\text{TXT}} / N_{\text{DNS}}$ | Heavy TXT ratio marks DNS tunnels (dnscat2) |
| **DNS / DGA** | `dns_consonant_ratio`| `float64` | $[0.0, 1.0]$ | Ratio of consonants in domain | $N_{\text{consonants}} / N_{\text{letters}}$ | Unnatural consonant/vowel ratio in DGAs |
| **DNS / DGA** | `dns_digit_ratio` | `float64` | $[0.0, 1.0]$ | Ratio of digits in domain | $N_{\text{digits}} / \text{len}(\text{domain})$ | Hex/Base32 encoded subdomains |
| **DNS / DGA** | `dns_ngram_score` | `float64` | log-likelihood | Bi-gram score vs English corpus | $\text{mean}(\log P(c_i, c_{i+1}))$ | Low scores indicate unpronounceable DGAs |
| **Encrypted Traffic** | `pkt_size_mean` | `float64` | bytes | Mean packet wire length | $\mu(\text{size})$ | Distinguishes keepalives from large payloads |
| **Encrypted Traffic** | `pkt_size_std` | `float64` | bytes | Standard deviation of packet sizes | $\sigma(\text{size})$ | Behavioral variance of encrypted sessions |
| **Encrypted Traffic** | `pkt_size_entropy`| `float64` | bits | Shannon entropy of packet size distribution | $-\sum p_s \log_2 p_s$ | Structural SPLT variance |
| **Encrypted Traffic** | `has_tls_sni` | `float64` | $0.0$ or $1.0$ | Presence of cleartext TLS SNI | $\mathbb{I}(\text{SNI is present})$ | Missing SNI on 443 often marks raw C2 |
| **Exfiltration** | `outbound_bytes_total`| `float64` | bytes | Cumulative outbound bytes in flow | $\sum \text{bytes}_{\text{out}}$ | Detects large unauthorized data transfers |
| **Exfiltration** | `byte_velocity` | `float64` | bytes/sec | Outbound transfer velocity | $\Delta \text{bytes} / \Delta t$ | Captures sudden bursty exfiltration transfers |
