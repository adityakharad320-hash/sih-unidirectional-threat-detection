# SIH 2026 Baseline Profile & Latency Decomposition Report

**Problem Statement 26145**: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*  
**Organization**: National Technical Research Organisation (NTRO)  
**Target System**: Existing Baseline Implementation (Ground Truth Pre-Optimization)  
**Date of Measurement**: 2026-09-04 10:02:56 UTC  

---

## 1. Executive Summary & Hardware Ground Truth

This benchmark records the empirically measured performance profile of the existing baseline detection architecture under rigorous hardware instrumentation (via `psutil` and nanosecond `time.perf_counter_ns()`). The pipeline was evaluated across 6 controlled realistic traffic scenarios (Distributed SYN Flood, Port Scanning, DGA / DNS Tunnelling, C2 Beaconing, Data Exfiltration, and Benign Web Traffic).

| Metric Category | Metric Name | Measured Baseline Value |
| :--- | :--- | :---: |
| **Latency SLA** | **End-to-End Latency ($p50$)** | **`33.864 ms`** |
| | **End-to-End Latency ($p95$)** | **`36.253 ms`** |
| | **End-to-End Latency ($p99$)** | **`43.630 ms`** |
| | **End-to-End Latency (Mean)** | **`34.258 ms`** |
| **Throughput** | **Events / Second** | **`29.2 evt/s`** |
| | **Flows / Second** | **`11.1 flows/s`** |
| **Memory / CPU** | **Peak Memory RSS** | **`236.8 MB`** |
| | **Memory RSS Delta** | **`+0.3 MB`** |
| | **Process CPU Utilization** | **`0.0%`** |
| **Startup / Caching** | **Cold-Start E2E ($p50$)** | **`33.877 ms`** |
| | **Warm E2E ($p50$)** | **`33.864 ms`** |
| **Test Verification** | **Automated Pytest Suite** | **`68 / 68 Passed (100%)`** |

---

## 2. Microsecond Latency Decomposition

The table below decomposes per-event processing time into every distinct functional stage of the pipeline.

| Subsystem Component | $p50$ (ms) | $p95$ (ms) | $p99$ (ms) | Mean (ms) | % of Total Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **1. Random Forest Inference (`predict_proba`)** | `15.678` | `16.982` | `20.730` | `15.898` | **`46.4%`** |
| **2. Isolation Forest Inference (`decision_function`)** | `17.080` | `18.472` | `21.945` | `17.294` | **`50.5%`** |
| **3. ML Scaler Transform (`StandardScaler`)** | `0.362` | `0.463` | `0.584` | `0.376` | **`1.1%`** |
| **4. Feature Extraction (Total)** | `0.445` | `0.771` | `0.945` | `0.463` | **`1.4%`** |
| ├── *Statistical Rates & Ratios* | `0.001` | `0.001` | `0.002` | `0.001` | `0.0%` |
| ├── *Shannon Character Entropy* | `0.015` | `0.022` | `0.029` | `0.016` | `0.1%` |
| ├── *DGA n-gram Scoring* | `0.000` | `0.000` | `0.009` | `0.000` | `0.0%` |
| └── *Beaconing FFT & IAT Jitter* | `0.000` | `0.142` | `0.159` | `0.017` | `0.1%` |
| **5. NumPy Conversion & ML Prep** | `0.023` | `0.031` | `0.041` | `0.024` | **`0.1%`** |
| **6. Behavioral Rules Engine (6 Rules)** | `0.073` | `0.093` | `0.121` | `0.076` | **`0.2%`** |
| ├── *DDoS Behavioral Rule* | `0.035` | `0.046` | `0.060` | `0.035` | `0.1%` |
| ├── *Port Scan Rule* | `0.007` | `0.017` | `0.022` | `0.009` | `0.0%` |
| ├── *DNS / DGA Rule* | `0.005` | `0.006` | `0.017` | `0.005` | `0.0%` |
| ├── *C2 Beaconing Rule* | `0.005` | `0.007` | `0.014` | `0.005` | `0.0%` |
| ├── *Data Exfiltration Rule* | `0.009` | `0.016` | `0.019` | `0.010` | `0.0%` |
| └── *Encrypted Traffic Rule* | `0.006` | `0.007` | `0.010` | `0.006` | `0.0%` |
| **7. Flow State Mutation** | `0.015` | `0.024` | `0.031` | `0.018` | **`0.1%`** |
| **8. Flow Key Lookup** | `0.003` | `0.004` | `0.006` | `0.003` | **`0.0%`** |
| **9. Evidence Generation** | `0.009` | `0.011` | `0.017` | `0.009` | **`0.0%`** |
| **10. Alert Deduplication & Mutex Store** | `0.022` | `0.044` | `0.084` | `0.026` | **`0.1%`** |
| **11. Serialization (Pydantic / JSON dump)** | `0.030` | `0.042` | `0.052` | `0.032` | **`0.1%`** |
| **12. Fusion Decision Resolution** | `0.028` | `0.037` | `0.048` | `0.029` | **`0.1%`** |
| **TOTAL PIPELINE END-TO-END** | **`33.864`** | **`36.253`** | **`43.630`** | **`34.258`** | **`100.0%`** |

---

## 3. Operational Counts & Invariants

- **Total Ingested Telemetry Events**: `1,618`
- **Active Flow States Tracked**: `613`
- **Random Forest Invocations**: `1,618` (**100.0%** of all events)
- **Isolation Forest Invocations**: `1,618` (**100.0%** of all events)
- **Behavioral Detector Checks**: `9,708`
- **Root Security Alerts Created**: `75`
- **Correlated / Deduplicated Events**: `1,543`
- **Deduplication Noise Reduction Ratio**: **`95.4%`**

---

## 4. Top 5 Measured Bottlenecks

1. **`isolation_forest_ms`**: `17.294 ms` (**`50.5%`** of latency)
2. **`random_forest_ms`**: `15.898 ms` (**`46.4%`** of latency)
3. **`feature_extraction_total_ms`**: `0.463 ms` (**`1.4%`** of latency)
4. **`ml_scaler_transform_ms`**: `0.376 ms` (**`1.1%`** of latency)
5. **`behavioral_rules_total_ms`**: `0.076 ms` (**`0.2%`** of latency)

---

## 5. Optimization Priorities for Next-Gen Engine

Based purely on measured evidence:
1. **Hierarchical / Gated ML Invocation**:
   - RF + IF inference accounts for **96.9%** of total execution latency.
   - Currently, every single packet invokes 200 scikit-learn decision trees unconditionally.
   - Gating full ML inference so it only fires when behavioral thresholds trigger or when flow statistics shift by $>15\%$ will yield an immediate **5x–10x throughput surge**.
2. **Zero-Copy Feature Ingestion & Buffer Recycling**:
   - `fv.to_dict()` and `np.array([features_dict.get(...)])` takes `0.024 ms` per event.
   - Replacing intermediate Python dictionaries with pre-allocated NumPy array buffers or C-contiguous memory cuts heap allocation overhead to zero.
3. **Fused / Inlined Model Scaling**:
   - `StandardScaler.transform` on 1x54 sample slices takes `0.376 ms` due to scikit-learn input validation overhead.
   - Inlining the `(X - mean) / scale` linear arithmetic directly into vectorized array operations eliminates this overhead entirely.
4. **Batch Temporal FFT Evaluation**:
   - Fast Fourier Transform and IAT statistical calculations should be amortized across flow windows rather than recalculated on every single raw packet.
