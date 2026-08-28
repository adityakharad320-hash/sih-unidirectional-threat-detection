# AI-Based Threat Detection in Unidirectional IP Traffic

[![SIH 2026](https://img.shields.io/badge/SIH%202026-Problem%20Statement%2026145-blue.svg)](https://sih.gov.in)
[![Organization](https://img.shields.io/badge/Organization-NTRO-red.svg)](https://ntro.gov.in)
[![Tests](https://img.shields.io/badge/Tests-68%2F68%20Passing-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

Production-grade, passive, unidirectional cyber threat detection platform for **Smart India Hackathon (SIH) 2026 Problem Statement 26145**, sponsored by the **National Technical Research Organisation (NTRO)**.

---

## Architecture Overview

```
Physical / Virtual Tap (Optical Diode / Rx-Only)
                     │
                     ▼
           Zeek + Suricata Engines
                     │
                     ▼
         Normalized Telemetry Stream
    (TSV conn/dns/ssl + Suricata EVE JSON)
                     │
                     ▼
     Streaming 54-D Feature Extractor
(Temporal Jitter, Shannon Entropy, Graph Topology)
                     │
                     ▼
          Hybrid AI Detection Core
┌─────────────────────────────────────────────────┐
│ • Supervised Random Forest (Multi-Class Probs) │
│ • Unsupervised Isolation Forest (Anomaly Score) │
│ • 6 Deterministic Behavioral Detectors          │
└─────────────────────────────────────────────────┘
                     │
                     ▼
          Threat Fusion & Resolver
                     │
                     ▼
           Security Alert Engine
  (Deduplication + Factual Evidence Mapping)
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
FastAPI Streaming REST/WS   Streamlit Dashboard
(http://localhost:8000)     (http://localhost:8501)
```

---

## Supported Threat Categories

1. **DDoS / SYN Flood**: Volumetric rate bursts, source IP entropy ($> 4.5	ext{ bits}$), destination concentration ($> 0.90$).
2. **Port Scanning**: Vertical and horizontal reconnaissance, fan-out velocity ($> 2.0	ext{ targets/s}$), connection failure ratios.
3. **DNS / DGA Tunnelling**: High-entropy query strings ($> 3.4	ext{ bits}$), English bigram log-likelihood anomaly, TXT record ratio ($> 50\%$).
4. **C2 Beaconing**: Sub-second inter-arrival stability ($	ext{CV} \le 0.15$), FFT spectral periodicity peaks, recurring destination frequency.
5. **Data Exfiltration**: Outbound/inbound volume asymmetry ($> 5.0	ext{x}$), upload throughput spikes ($> 25	ext{ KB/s}$).
6. **Encrypted Malware**: Direct IP TLS handshakes without SNI, low-entropy unidirectional packet size signatures ($< 1.0	ext{ bits}$).
7. **Unknown Novel Anomalies**: Unsupervised Isolation Forest novelty detection without pre-trained signatures.

---

## 10/10 SIH Compliance Guarantees

* **Read-Only Ingest**: Stream processing operates via file-descriptor `open(..., 'rb')` iterators and generator streams.
* **Zero Return Path**: Zero calls to packet transmission sockets (`send()`, `sendto()`).
* **Zero Live Querying**: Zero external DNS lookups, WHOIS queries, or cloud threat-intel API dependencies.
* **Zero Inline Blocking**: Strictly out-of-band monitoring without iptables/nftables manipulation.
* **Zero Payload Decryption**: Operates exclusively on unencrypted L3/L4/L7 metadata (SNI, cipher suites, JA3/JA4 fingerprints).
* **Streaming & $O(1)$ Memory**: Incremental sliding deques with dynamic TTL eviction.
* **Sub-50ms Latency**: Measured median detection latency of $36.05	ext{ ms}$ ($p99 = 68.71	ext{ ms}$).

---

## Quickstart Guide

### 1. Installation
```powershell
git clone <YOUR_REPO_URL> sih2026_threat_detection
cd sih2026_threat_detection/backend
python -m pip install -r requirements.txt
```

### 2. Run the Full Test Suite (68 Tests)
```powershell
python -m pytest tests -v
```

### 3. Run the Controlled Demonstration Scenarios
```powershell
python run_controlled_scenarios.py
```

### 4. Run the SIH Performance & Resource Benchmark
```powershell
python run_sih_benchmark.py
```

### 5. Launch Live Services

**Start FastAPI Backend**:
```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Start Streamlit Cybersecurity Dashboard**:
```powershell
streamlit run dashboard/app.py --server.port 8501
```

Open [http://localhost:8501](http://localhost:8501) to view the monitoring interface.

---

## Project Structure

```
sih2026_threat_detection/
├── backend/
│   ├── app/
│   │   ├── alerts/          # SecurityAlert_v2 engine & deduplication
│   │   ├── detectors/       # 6 behavioral detection engines
│   │   ├── ingestion/       # PCAP & raw packet stream readers
│   │   ├── ml/              # Hybrid RF + IF inference & dataset builder
│   │   ├── pipeline/        # In-memory streaming orchestrator & Kafka
│   │   ├── telemetry/       # Zeek / Suricata log parsers & 54-D feature engine
│   │   └── main.py          # FastAPI application & WebSocket router
│   ├── tests/               # 68 automated pytest test cases
│   ├── run_controlled_scenarios.py
│   ├── run_pipeline_benchmark.py
│   └── run_sih_benchmark.py
├── dashboard/
│   ├── app.py               # Streamlit application layout
│   ├── api_client.py        # Resilient API client with in-process fallback
│   └── components/          # Overview, Alerts, Details, Analytics, Governance
├── data/
│   ├── pcap_samples/        # Controlled scenario PCAP captures
│   └── telemetry_logs/      # Zeek TSV and Suricata EVE logs
├── models/
│   └── weights/             # Serialized model weights & scalers
└── docs/
    ├── CONTROLLED_REPLAY_FRAMEWORK.md
    ├── KAFKA_ARCHITECTURE_EVALUATION.md
    └── SIH_COMPLIANCE_AUDIT.md
```

---

## Hardware Benchmarks (Actual Recorded Measurements)

| Metric | Measured Value | SLA Target |
| :--- | :--- | :--- |
| **Feature Extraction Latency ($p50$)** | **$0.338	ext{ ms}$** | $< 5.0	ext{ ms}$ |
| **ML / Fusion Latency ($p50$)** | **$35.651	ext{ ms}$** | $< 100.0	ext{ ms}$ |
| **Alert Generation & Dedup ($p50$)** | **$0.023	ext{ ms}$** | $< 1.0	ext{ ms}$ |
| **Total End-to-End Latency ($p50$)** | **$36.051	ext{ ms}$** | $< 500.0	ext{ ms}$ |
| **Total End-to-End Latency ($p99$)** | **$68.713	ext{ ms}$** | $< 1000.0	ext{ ms}$ |
| **Peak Resident RAM (RSS)** | **$236.8	ext{ MB}$** | $< 1024.0	ext{ MB}$ |
| **Feature Schema Parity** | **54 / 54 Dimensions** | $100\%$ Exact Match |

---

## License
MIT License. Developed for SIH 2026 (Problem Statement 26145).
