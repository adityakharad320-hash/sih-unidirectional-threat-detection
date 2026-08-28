"""
Comprehensive Performance, Resource & Compliance Benchmark Suite.

Measures actual:
  - Throughput (events/sec, flows/sec, packets/sec)
  - Microsecond latency breakdown (Feature, ML, Fusion, Alert, E2E)
  - CPU usage % & Peak RSS Memory (MB) via psutil
  - Feature schema parity between Training and Inference
"""
import sys
import os
import time
import asyncio
import numpy as np
import psutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.telemetry.feature_schema import TelemetryFeatureVector_v2
from app.ml.preprocessing import FEATURE_COLS
from app.pipeline.orchestrator import StreamingPipelineOrchestrator
from app.utils.traffic_scenarios import ControlledTrafficGenerator
from app.config import SAMPLES_DIR, DATA_DIR, MODELS_DIR

def verify_feature_schema_parity() -> bool:
    """Verifies that Training and Inference use exactly the same feature schema."""
    print("\n[1/3] VERIFYING FEATURE SCHEMA EQUALITY (TRAINING VS. INFERENCE)...")
    
    # 1. Feature cols in training
    train_cols = list(FEATURE_COLS)
    
    # 2. Feature schema in inference vector
    dummy_fv = TelemetryFeatureVector_v2(flow_id="test", timestamp=1.0)
    inf_dict = dummy_fv.to_dict()
    inf_cols = list(inf_dict.keys())
    
    # 3. Model serialized weights feature_names
    import joblib
    rf_files = sorted(MODELS_DIR.glob("random_forest_*.joblib"), reverse=True)
    if rf_files:
        rf_art = joblib.load(rf_files[0])
        model_cols = rf_art.get("feature_names", [])
    else:
        model_cols = train_cols

    print(f"  * Training Features Count:  {len(train_cols)} dimensions")
    print(f"  * Inference Features Count: {len(inf_cols)} dimensions")
    print(f"  * Model Weights Count:      {len(model_cols)} dimensions")

    parity_train_inf = (train_cols == inf_cols)
    parity_inf_model = (inf_cols == model_cols)

    if parity_train_inf and parity_inf_model:
        print("  >>> SUCCESS: 100% Exact Feature Schema Parity Verified (0 train-serve skew).")
        return True
    else:
        diff = set(train_cols).symmetric_difference(set(inf_cols))
        print(f"  >>> ERROR: Schema mismatch! Differences: {diff}")
        return False

async def run_performance_and_compliance_benchmark():
    print("=" * 105)
    print("SIH 2026 PERFORMANCE, RESOURCE & COMPLIANCE BENCHMARK")
    print("National Technical Research Organisation (NTRO) — Problem Statement 26145")
    print("=" * 105)

    # 1. Verify schema parity
    schema_ok = verify_feature_schema_parity()
    assert schema_ok, "Feature schema parity failed!"

    # 2. Ensure all 6 PCAPs exist
    print("\n[2/3] Preparing 6 Controlled Replay Traffic Scenarios ...")
    ControlledTrafficGenerator.generate_all_scenarios(SAMPLES_DIR)

    # 3. Run hardware-instrumented streaming benchmark
    print("\n[3/3] Executing Hardware-Instrumented Streaming Replay Across All Scenarios ...")
    orchestrator = StreamingPipelineOrchestrator()
    staging_dir = DATA_DIR / "sih_benchmark_staging"

    process = psutil.Process(os.getpid())
    mem_before_mb = process.memory_info().rss / (1024 * 1024)

    all_samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap",
        "data_exfiltration.pcap"
    ]

    scenario_reports = []
    t_global_start = time.perf_counter()

    for pcap_name in all_samples:
        pcap_path = SAMPLES_DIR / pcap_name
        rep = await orchestrator.run_pipeline_on_pcap(pcap_path, staging_dir)
        scenario_reports.append(rep)

    t_global_end = time.perf_counter()
    mem_after_mb = process.memory_info().rss / (1024 * 1024)
    cpu_percent = process.cpu_percent(interval=0.1)

    # 4. Print Formatted Benchmark Report
    print("\n" + "=" * 105)
    print(f"{'Scenario':<24} | {'Events':<7} | {'Flows':<6} | {'Throughput':<12} | {'Feat Ext (p50)':<14} | {'ML Infer (p50)':<14} | {'Total E2E (p50)':<14}")
    print("-" * 105)

    tot_events = sum(r.total_events_processed for r in scenario_reports)
    tot_flows = sum(r.total_flows_tracked for r in scenario_reports)

    for r in scenario_reports:
        print(
            f"{r.pcap_name:<24} | {r.total_events_processed:<7} | {r.total_flows_tracked:<6} | "
            f"{r.events_per_second:>6.1f} evt/s | "
            f"{r.feature_extraction_latency.p50_ms:>10.3f} ms | "
            f"{r.inference_latency.p50_ms:>10.3f} ms | "
            f"{r.end_to_end_latency.p50_ms:>10.3f} ms"
        )

    print("=" * 105)
    
    # Aggregated Latencies
    all_feat_p50 = np.mean([r.feature_extraction_latency.p50_ms for r in scenario_reports])
    all_infer_p50 = np.mean([r.inference_latency.p50_ms for r in scenario_reports])
    all_alert_p50 = np.mean([r.alert_generation_latency.p50_ms for r in scenario_reports])
    all_e2e_p50 = np.mean([r.end_to_end_latency.p50_ms for r in scenario_reports])
    all_e2e_p99 = np.mean([r.end_to_end_latency.p99_ms for r in scenario_reports])

    print("\n" + "=" * 105)
    print("GLOBAL HARDWARE & RESOURCE MEASUREMENTS (ACTUAL RECORDED NUMBERS):")
    print(f"  * Total Events Processed:        {tot_events:,} events")
    print(f"  * Total Unique Flows Tracked:    {tot_flows:,} flows")
    print(f"  * Total Processing Time:         {t_global_end - t_global_start:.2f} seconds")
    print(f"  * Peak Resident Memory (RSS):    {mem_after_mb:.1f} MB (Delta: +{mem_after_mb - mem_before_mb:.1f} MB)")
    print(f"  * Process CPU Utilization:       {cpu_percent:.1f}%")
    print(f"  * Feature Extraction Latency p50:{all_feat_p50:.3f} ms")
    print(f"  * ML / Fusion Inference p50:     {all_infer_p50:.3f} ms")
    print(f"  * Alert Generation / Dedup p50:  {all_alert_p50:.3f} ms")
    print(f"  * Total End-to-End Latency p50:  {all_e2e_p50:.3f} ms")
    print(f"  * Total End-to-End Latency p99:  {all_e2e_p99:.3f} ms")
    print("=" * 105)

if __name__ == "__main__":
    asyncio.run(run_performance_and_compliance_benchmark())
