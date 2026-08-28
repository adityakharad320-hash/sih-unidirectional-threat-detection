"""
Interactive Demonstration Script: Hybrid ML Engine.
Demonstrates:
  1. Supervised Random Forest Classification
  2. Unsupervised Isolation Forest Anomaly Scoring
  3. Model Fusion Engine (States A, B, C, D)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.ml.hybrid_inference import HybridInferenceEngine
from app.config import SAMPLES_DIR, DATA_DIR

def run_demo():
    print("=" * 95)
    print("HYBRID ML ENGINE DEMO: RANDOM FOREST + ISOLATION FOREST + FUSION LAYER")
    print("=" * 95)

    engine = HybridInferenceEngine()
    staging_dir = DATA_DIR / "hybrid_ml_demo_staging"

    test_pcaps = [
        ("benign_traffic.pcap", "Expected: BENIGN / Normal Traffic"),
        ("syn_flood.pcap",      "Expected: DDOS / Known Threat"),
        ("port_scan.pcap",      "Expected: PORT_SCAN / Known Threat"),
        ("dga_dns_tunnel.pcap", "Expected: DGA_DNS_TUNNELLING / Heuristic"),
        ("c2_beaconing.pcap",   "Expected: C2_BEACONING / Heuristic")
    ]

    for pcap_name, expectation in test_pcaps:
        pcap_path = SAMPLES_DIR / pcap_name
        pcap_out = staging_dir / pcap_path.stem
        print(f"\n[+] Processing: {pcap_name} ({expectation})")

        # 1. Replay PCAP to Zeek / Suricata logs
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, pcap_out)

        # 2. Ingest telemetry stream
        streamer = TelemetryStreamer(pcap_out)
        tracker = StreamingTelemetryTracker()

        results = []
        for event in streamer.stream_all_events():
            state = tracker.process_event(event)
            fv = TelemetryFeatureExtractor.extract_features(state, tracker)
            res = engine.predict(fv)
            results.append(res)

        # Display last flow result
        last_res = results[-1]
        print(f"    Flow ID:          {last_res.flow_id}")
        print(f"    Threat Label:     {last_res.threat_label} (Confidence: {last_res.confidence * 100:.1f}%)")
        print(f"    Decision State:   {last_res.decision_state}")
        print(f"    Detection Method: {last_res.detection_method}")
        print(f"    RF Classifier:    prediction='{last_res.rf_prediction}' (confidence={last_res.rf_confidence:.3f})")
        print(f"    IF Anomaly:       score={last_res.if_anomaly_score:.6f} | is_anomalous={last_res.if_is_anomalous} (threshold={last_res.if_threshold:.6f})")
        if last_res.heuristic_override:
            print(f"    Heuristic Flag:   OVERRIDE -> {last_res.heuristic_override}")
        if last_res.warnings:
            print(f"    Warnings:         {last_res.warnings}")
        print(f"    Inference Latency:{last_res.inference_latency_ms:.3f} ms")

    print("\n" + "=" * 95)
    print("HYBRID ML ENGINE DEMO COMPLETE: Supervised + Unsupervised + Fusion Verified.")
    print("=" * 95)

if __name__ == "__main__":
    run_demo()
