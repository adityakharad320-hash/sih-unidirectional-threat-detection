# AI-Based Threat Detection in Unidirectional IP Traffic

[![SIH 2026](https://img.shields.io/badge/SIH%202026-Problem%20Statement%2026145-blue.svg)](https://sih.gov.in)
[![Organization](https://img.shields.io/badge/Organization-NTRO-red.svg)](https://ntro.gov.in)
[![Tests](https://img.shields.io/badge/Tests-80%2F80%20Passing-brightgreen.svg)]()
[![Inference Engine](https://img.shields.io/badge/Inference-ONNX%20Runtime%20SIMD-orange.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

High-performance, passive, unidirectional cyber threat detection platform engineered for **Smart India Hackathon (SIH) 2026 Problem Statement 26145**, sponsored by the **National Technical Research Organisation (NTRO)**.

Operating strictly behind an isolated **optical hardware data diode**, this system performs real-time threat detection on simplex, receive-only IP network traffic streams with zero transmission capability, sub-millisecond classification, and bounded memory footprint.

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
                         ┌───────────────────────────────────────┐
                         │      Fast Behavioral Gate (<1 µs)     │
                         │   (L4/L7 Header Screening & Heuristics)│
                         └───────────────────┬───────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │ PASS_NORMAL                               │ SUSPICIOUS / UNKNOWN
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │  Welford O(1)     │                       │  54-D Vectorized  │
             │  Flow State       │                       │  Feature Extractor│
             │  (Moments & Jitter│                       │  (Contiguous Pool)│
             └───────────────────┘                       └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Inlined Fast      │
                                                         │ Z-Score Scaler    │
                                                         └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ ONNX Runtime RF   │
                                                         │ (100 Trees SIMD)  │
                                                         └─────────┬─────────┘
                                                                   │
                                                         ┌─────────┴─────────┐
                                    rf_conf >= 0.75      │                   │ rf_conf < 0.75
                                    (High Certainty)     ▼                   ▼ (Ambiguous Anomaly)
                                                ┌────────────────┐   ┌────────────────┐
                                                │ Bypass Iso-    │   │ Selective Iso- │
                                                │ Forest (0 ms)  │   │ Forest Engine  │
                                                └────────┬───────┘   └────────┬───────┘
                                                         │                    │
                                                         └─────────┬──────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Prioritized Threat│
                                                         │ Fusion Resolver   │
                                                         └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Security Alert    │
                                                         │ Deduplication     │
                                                         └─────────┬─────────┘
                                                                   │
                                                     ┌─────────────┴─────────────┐
                                                     ▼                           ▼
                                            FastAPI Streaming REST/WS   Streamlit SOC Dashboard
                                            (http://localhost:8000)     (http://localhost:8501)
```

---

## Key Performance Innovations

1. **Sub-Microsecond Behavioral Screening Gate**:
   - Evaluates inexpensive observables (packet counts, byte rates, SYN/ACK ratios, fan-out, port diversity) in $< 1\ \mu s$.
   - Safely passes steady-state benign traffic, bypassing full ML feature generation for $> 80\%$ of normal events.
2. **Welford's Algorithm $O(1)$ Statistical Flow Tracker**:
   - Replaces historical deque array conversions with single-pass incremental calculation of running mean, sample variance, standard deviation, and inter-arrival jitter.
   - Flow state object uses explicit `__slots__`, eliminating Python dynamic dict overhead and cutting per-flow memory by **56.9%** (down to $3,175\text{ bytes/flow}$).
3. **ONNX Runtime Random Forest Inference**:
   - Retains all **100 decision trees** to guarantee full classification accuracy while accelerating execution via compiled C++ and CPU SIMD instructions (`intra_op_num_threads=1`).
   - Single-predict execution time dropped from **$15.898\text{ ms}$** (Scikit-Learn) to **$0.0815\text{ ms}$** (ONNX Runtime) — a **195x acceleration**.
4. **Adaptive Selective Isolation Forest Escalation**:
   - Isolates the computationally intensive Isolation Forest (mean $17.3\text{ ms}$) to evaluate only ambiguous or novel flows ($rf\_conf < 0.75$).
   - High-confidence flows skip unsupervised tree projection entirely, slashing pipeline latency without sacrificing anomaly discovery.
5. **Prioritized Threat Resolution**:
   - Enforces deterministic rule hierarchy (`DATA_EXFILTRATION` > `C2_BEACONING` > `DGA_DNS_TUNNELLING` > `PORT_SCAN` > `ENCRYPTED_MALWARE` > `DDOS`).
   - Eliminates legacy bug where asymmetric data exfiltration was masked by volumetric DDoS rules.

---

## Hardware Benchmarks (Empirical A/B Measurements)

Evaluated on the exact same CPU-only hardware environment across all 6 realistic replay scenarios (1,618 events, 613 active flows):

| Metric | Baseline (Scikit-Learn) | Optimized (Integrated ONNX) | Improvement Factor |
| :--- | :--- | :--- | :--- |
| **Pipeline Replay Duration** | $71.02\text{ s}$ | **$35.47\text{ s}$** | **2.0x faster** |
| **Throughput (Replay)** | $22.8\text{ evt/s}$ | **$45.6\text{ evt/s}$** | **2.0x higher** |
| **Throughput (Synthetic Burst)** | $5,800\text{ evt/s}$ | **$131,442\text{ evt/s}$** | **22.6x higher** |
| **End-to-End Latency ($p50$)** | $42.66\text{ ms}$ | **$21.58\text{ ms}$** | **1.98x faster** |
| **End-to-End Latency ($p95$)** | $50.16\text{ ms}$ | **$23.32\text{ ms}$** | **2.15x faster** |
| **End-to-End Latency ($p99$)** | $63.88\text{ ms}$ | **$27.51\text{ ms}$** | **2.32x lower tail jitter** |
| **Random Forest Inference ($p50$)** | $15.898\text{ ms}$ | **$0.0815\text{ ms}$** | **195x faster** |
| **Memory per 5,000 Active Flows** | $35.10\text{ MB}$ | **$15.14\text{ MB}$** | **56.9% memory savings** |
| **Cold Start to First Prediction** | $0.2222\text{ s}$ | **$0.0427\text{ s}$** | **5.2x faster startup** |
| **Model Size on Disk (RF)** | $309.7\text{ KB}$ | **$105.1\text{ KB}$** | **2.95x smaller** |
| **Feature Schema Parity** | 54 / 54 Dimensions | **54 / 54 Dimensions** | **100% Identical** |

---

## Supported Threat Categories

1. **DDoS / SYN Flood**: Volumetric packet bursts, source IP entropy ($> 4.5\text{ bits}$), destination concentration ($> 0.90$).
2. **Port Scanning**: Vertical and horizontal reconnaissance, fan-out velocity ($> 2.0\text{ targets/s}$), connection failure ratios.
3. **DNS / DGA Tunnelling**: High-entropy query strings ($> 3.4\text{ bits}$), English bigram log-likelihood anomaly, TXT record ratio ($> 50\%$).
4. **C2 Beaconing**: Sub-second inter-arrival stability ($\text{CV} \le 0.15$), FFT spectral periodicity peaks, recurring destination frequency.
5. **Data Exfiltration**: Outbound/inbound volume asymmetry ($> 5.0\text{x}$), upload throughput spikes ($> 25\text{ KB/s}$).
6. **Encrypted Malware**: Direct IP TLS handshakes without SNI, low-entropy unidirectional packet size signatures ($< 1.0\text{ bits}$).
7. **Unknown Novel Anomalies**: Unsupervised Isolation Forest novelty detection without pre-trained signatures.

---

## 10/10 SIH & NTRO Compliance Guarantees

* **Read-Only Ingest**: Stream processing operates via file-descriptor `open(..., 'rb')` iterators and generator streams.
* **Zero Return Path**: Zero calls to packet transmission sockets (`send()`, `sendto()`).
* **Zero Active Probing**: Zero ping sweeps, TCP handshakes, ICMP messages, or DNS queries generated back to the monitored network.
* **Zero Live Querying**: Zero external DNS lookups, WHOIS queries, or cloud threat-intel API dependencies. Fully air-gapped.
* **Zero Inline Blocking**: Strictly out-of-band monitoring without iptables/nftables manipulation.
* **Zero Payload Decryption**: Operates exclusively on unencrypted L3/L4/L7 metadata (SNI, cipher suites, JA3/JA4 fingerprints).
* **Missing Reverse Packets Not Malicious**: Missing SYN-ACK, reverse ACK, or FIN is treated as standard diode behavior, not an anomaly.
* **Flow Eviction Without FIN/RST**: State tables infer termination exclusively via temporal sliding-window TTLs.
* **Streaming & $O(1)$ Memory**: Incremental sliding deques with dynamic TTL eviction.
* **Explainable Evidence**: Generates empirical telemetry metrics (SYN ratio, inter-arrival variance, entropy) without sensationalist claims.

---

## Tiered Dependency Architecture

The repository enforces modular separation between the headless sensor appliance and the management plane:

| Tier | Requirements File | Target Environment | Footprint |
| :--- | :--- | :--- | :--- |
| **Core Passive Sensor** | `requirements-sensor.txt` | Headless Data Diode Sensor Appliance | **< 85 MB** (6 packages: `numpy`, `pydantic`, `onnxruntime`, `scikit-learn`, `joblib`, `dpkt`) |
| **Full SOC & Management** | `requirements.txt` | Central SOC, Streamlit Dashboard, FastAPI Server | Standard deployment with UI & benchmark suites |

---

## Quickstart Guide

### 1. Minimal Headless Sensor Installation
```powershell
git clone https://github.com/adityakharad320-hash/sih-unidirectional-threat-detection.git
cd sih-unidirectional-threat-detection
python -m pip install -r requirements-sensor.txt
```

### 2. Full Installation (Dashboard + API + Benchmarks)
```powershell
python -m pip install -r requirements.txt
```

### 3. Run the Full Test Suite (80 Automated Tests)
```powershell
python -m pytest backend/tests -v
```

### 4. Run the Controlled Demonstration Scenarios
```powershell
cd backend
python run_controlled_scenarios.py
```

### 5. Run the SIH Performance Benchmark
```powershell
cd backend
python run_sih_benchmark.py
```

### 6. Launch Live Services

**Start FastAPI Streaming Backend**:
```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Start Streamlit SOC Cybersecurity Dashboard**:
```powershell
streamlit run dashboard/app.py --server.port 8501
```

Open [http://localhost:8501](http://localhost:8501) to view the monitoring interface.

---

## Project Structure

```
sih-unidirectional-threat-detection/
├── backend/
│   ├── app/
│   │   ├── alerts/          # SecurityAlert_v2 engine & deduplication
│   │   ├── detectors/       # 6 behavioral detection engines
│   │   ├── ingestion/       # PCAP & raw packet stream readers
│   │   ├── ml/              # Hybrid RF (ONNX) + IF inference & dataset builder
│   │   ├── pipeline/        # In-memory streaming orchestrator (Gate + Welford)
│   │   ├── telemetry/       # Zeek / Suricata log parsers & 54-D feature schema
│   │   └── main.py          # FastAPI application & WebSocket router
│   ├── models/
│   │   └── weights/         # Pre-trained weights & random_forest_v2.0.onnx
│   ├── tests/               # 80 automated pytest test cases
│   ├── run_controlled_scenarios.py
│   ├── run_pipeline_benchmark.py
│   └── run_sih_benchmark.py
├── dashboard/
│   ├── app.py               # Streamlit application layout
│   ├── api_client.py        # Resilient API client with in-process fallback
│   └── components/          # Overview, Alerts, Details, Analytics, Governance
├── optimized/               # Modular optimized reference implementation
│   ├── gate.py              # Fast behavioral screening gate (<1 µs)
│   ├── flow_tracker.py      # Welford O(1) statistical flow engine
│   ├── feature_pipeline.py  # Zero-copy contiguous 54-D feature buffer
│   ├── inference_engine.py  # Vectorized inlined Z-scaler
│   ├── fusion.py            # Streamlined threat fusion & IF escalation
│   └── onnx_converter.py    # Sklearn-to-ONNX conversion pipeline
├── benchmarks/              # Microsecond profiling harnesses & raw JSON results
├── reports/                 # Comprehensive forensic & performance engineering reports
├── requirements.txt         # Full platform dependencies
├── requirements-sensor.txt  # Headless passive diode sensor dependencies (<85 MB)
└── docs/                    # Technical architecture & compliance specifications
```

---

## License
MIT License. Developed for Smart India Hackathon 2026 (Problem Statement 26145).
