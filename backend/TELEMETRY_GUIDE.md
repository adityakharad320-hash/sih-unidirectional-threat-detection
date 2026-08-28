# Enterprise NSM Telemetry Layer: Zeek & Suricata Guide

This guide documents the installation, offline PCAP replay workflows, log locations, and the vendor-agnostic Normalized Event Schema for the SIH 2026 / PS 26145 AI Threat Detection Engine.

---

## 1. Architectural Role of Zeek & Suricata

In this updated architecture, **Zeek** acts as the primary network metadata sensor and **Suricata** acts as the auxiliary signature/security event engine:

```
+-----------------------------------------------------------------------------------+
|                              Passive Ingress Stream                               |
|                         (Hardware TAP / PCAP Replay)                              |
+-----------------------------------------+-----------------------------------------+
                                          │
                     ┌────────────────────┴────────────────────┐
                     ▼                                         ▼
         +-----------------------+                 +-----------------------+
         |      Zeek Sensor      |                 |    Suricata Sensor    |
         |  (Protocol Metadata)  |                 |  (Alerts & L7 Flows)  |
         +-----------┬-----------+                 +-----------┬-----------+
                     │                                         │
                     ▼ TSV/JSON Logs                           ▼ EVE JSON (eve.json)
               - conn.log                                - alert events
               - dns.log                                 - flow events
               - ssl.log                                 - tls / dns events
               - http.log                                │
                     │                                   │
                     └────────────────────┬──────────────┘
                                          ▼
                     +-----------------------------------------+
                     |    Telemetry Ingestion & Normalizer     |
                     +--------------------+--------------------+
                                          │
                                          ▼
                     +-----------------------------------------+
                     |   Normalized Internal Event Schema      |
                     |  - NormalizedConnectionEvent            |
                     |  - NormalizedDNSEvent                   |
                     |  - NormalizedTLSEvent                   |
                     |  - NormalizedHTTPEvent                  |
                     |  - NormalizedSecurityAlert              |
                     +--------------------+--------------------+
                                          │
                                          ▼
                     +-----------------------------------------+
                     |   Feature Engineering & ML Inference    |
                     +-----------------------------------------+
```

---

## 2. Installation Guide

### 2.1 Installing Zeek

#### On Ubuntu / Debian / WSL 2:
```bash
# Add openSUSE Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update
sudo apt install zeek-lts -y

# Add Zeek binary path to PATH
export PATH=$PATH:/opt/zeek/bin
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
```

#### Via Docker (Zero-install option):
```bash
docker pull zeek/zeek:latest
# Run PCAP through Zeek container:
docker run --rm -v $(pwd):/pcap zeek/zeek:latest zeek -r /pcap/traffic.pcap
```

---

### 2.2 Installing Suricata

#### On Ubuntu / Debian / WSL 2:
```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install suricata -y

# Update Emerging Threats (ET) open ruleset
sudo suricata-update
```

#### Via Docker:
```bash
docker pull jasonish/suricata:latest
# Run PCAP through Suricata container:
docker run --rm -v $(pwd):/pcap jasonish/suricata:latest -r /pcap/traffic.pcap -l /pcap/suricata_logs
```

---

## 3. PCAP Replay Workflow

### 3.1 Zeek Offline PCAP Replay
To generate connection, DNS, SSL/TLS, and HTTP logs from an ingested PCAP:
```bash
# Run Zeek on PCAP (generates ASCII TSV logs in current directory)
zeek -r /path/to/capture.pcap

# To generate JSON logs instead:
zeek -r /path/to/capture.pcap LogAscii::use_json=T
```

**Expected Zeek Output Files**:
* `conn.log`: L4 connection states, duration, byte and packet volumes.
* `dns.log`: DNS query names, record types (A, TXT, ANY), and answer IP lists.
* `ssl.log`: TLS handshake parameters (SNI, cipher suites, JA3/JA4, certificate subjects).
* `http.log`: HTTP methods, hosts, URIs, user agents, status codes.

---

### 3.2 Suricata Offline PCAP Replay
To generate EVE JSON telemetry and signature alerts:
```bash
suricata -r /path/to/capture.pcap -l /path/to/output_dir
```

**Expected Suricata Output File**:
* `eve.json`: Single multi-event stream containing `alert`, `flow`, `dns`, `tls`, and `http` records in streaming JSON format.

---

## 4. Normalized Internal Event Schema Reference

All events inherit from `NormalizedBaseEvent`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `event_id` | `string` | Unique identifier (Zeek UID or Suricata flow_id) |
| `timestamp` | `float` | Epoch timestamp in seconds with microsecond resolution |
| `event_type` | `enum` | `"connection"`, `"dns"`, `"tls"`, `"http"`, `"alert"` |
| `source_engine` | `string` | `"zeek"` or `"suricata"` |
| `src_ip`, `dst_ip` | `string` | Source and Destination IP addresses |
| `src_port`, `dst_port`| `int` | Source and Destination L4 ports |
| `protocol` | `string` | `"TCP"`, `"UDP"`, `"ICMP"` |

### 4.1 Normalized Event Classes

1. **`NormalizedConnectionEvent`**:
   * `duration`: Connection duration in seconds.
   * `orig_bytes`, `resp_bytes`: Outbound and Inbound byte volumes.
   * `orig_pkts`, `resp_pkts`: Outbound and Inbound packet counts.
   * `conn_state`: State signature (`"SF"`, `"S0"`, `"REJ"`, etc.).
   * `history`: TCP flag history string.
2. **`NormalizedDNSEvent`**:
   * `query_name`: Requested domain string (for entropy & DGA analysis).
   * `query_type_name`: `"A"`, `"TXT"`, `"ANY"`, etc.
   * `response_code_name`: `"NOERROR"`, `"NXDOMAIN"`, etc.
   * `answers`: List of resolved IP/string answers.
3. **`NormalizedTLSEvent`**:
   * `version`: `"TLSv1.2"`, `"TLSv1.3"`.
   * `cipher`: Negotiated cipher suite string.
   * `sni_server_name`: Cleartext Server Name Indication.
   * `ja3`, `ja3s`: Client/Server cryptographic fingerprints.
4. **`NormalizedHTTPEvent`**:
   * `method`: `"GET"`, `"POST"`, etc.
   * `host`, `uri`, `user_agent`: L7 request parameters.
   * `status_code`: HTTP response code (e.g. 200, 404).
5. **`NormalizedSecurityAlert`**:
   * `signature_id`: Suricata rule SID.
   * `signature`: Human-readable threat signature name.
   * `category`: Threat classification.
   * `severity`: 1 (High), 2 (Medium), 3 (Low).
   * `action`: `"allowed"` (passive inspection).
