"""
Pipeline Performance & Latency Benchmark Script.

Measures actual runtime metrics (flows/sec, packets/sec, feature extraction latency,
inference latency, end-to-end alert latency) using real PCAP replays.
"""
import sys
import asyncio
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.pipeline.orchestrator import StreamingPipelineOrchestrator
from app.config import SAMPLES_DIR, DATA_DIR

async def run_benchmark():
    print("=" * 95)
    print("INCREMENTAL STREAMING PIPELINE: PERFORMANCE & LATENCY BENCHMARK")
    print("=" * 95)

    orchestrator = StreamingPipelineOrchestrator()
    staging_dir = DATA_DIR / "benchmark_staging"

    samples = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap"
    ]

    all_reports = []

    for pcap_name in samples:
        pcap_path = SAMPLES_DIR / pcap_name
        print(f"\n[+] Benchmarking Stream: {pcap_name}")
        report = await orchestrator.run_pipeline_on_pcap(pcap_path, staging_dir)
        all_reports.append(report)

        print(f"    Total Events Processed:   {report.total_events_processed} events")
        print(f"    Unique Flows Tracked:     {report.total_flows_tracked} flows")
        print(f"    Replay Duration:          {report.duration_seconds:.4f} seconds")
        print(f"    >>> THROUGHPUT:")
        print(f"        Events / Second:      {report.events_per_second:,.1f} events/s")
        print(f"        Flows / Second:       {report.flows_per_second:,.1f} flows/s")
        print(f"    >>> LATENCY METRICS (Measured via time.perf_counter_ns):")
        print(f"        Feature Extraction:   mean={report.feature_extraction_latency.mean_ms:.3f}ms | p50={report.feature_extraction_latency.p50_ms:.3f}ms | p95={report.feature_extraction_latency.p95_ms:.3f}ms | p99={report.feature_extraction_latency.p99_ms:.3f}ms")
        print(f"        ML / Fusion Inference:mean={report.inference_latency.mean_ms:.3f}ms | p50={report.inference_latency.p50_ms:.3f}ms | p95={report.inference_latency.p95_ms:.3f}ms | p99={report.inference_latency.p99_ms:.3f}ms")
        print(f"        Alert Generation:     mean={report.alert_generation_latency.mean_ms:.3f}ms | p50={report.alert_generation_latency.p50_ms:.3f}ms | p95={report.alert_generation_latency.p95_ms:.3f}ms")
        print(f"        TOTAL END-TO-END:     mean={report.end_to_end_latency.mean_ms:.3f}ms | p50={report.end_to_end_latency.p50_ms:.3f}ms | p95={report.end_to_end_latency.p95_ms:.3f}ms | p99={report.end_to_end_latency.p99_ms:.3f}ms")

    # Aggregated Summary
    tot_events = sum(r.total_events_processed for r in all_reports)
    tot_dur = sum(r.duration_seconds for r in all_reports)
    avg_e2e_p50 = sum(r.end_to_end_latency.p50_ms for r in all_reports) / len(all_reports)
    avg_e2e_p99 = sum(r.end_to_end_latency.p99_ms for r in all_reports) / len(all_reports)

    print("\n" + "=" * 95)
    print("GLOBAL PIPELINE PERFORMANCE SUMMARY:")
    print(f"  * Total Events Benchmarked:       {tot_events:,} events")
    print(f"  * Combined Pipeline Throughput:   {tot_events / tot_dur:,.1f} events/sec")
    print(f"  * Average End-to-End Latency p50: {avg_e2e_p50:.3f} ms")
    print(f"  * Average End-to-End Latency p99: {avg_e2e_p99:.3f} ms")
    print("=" * 95)

if __name__ == "__main__":
    asyncio.run(run_benchmark())
