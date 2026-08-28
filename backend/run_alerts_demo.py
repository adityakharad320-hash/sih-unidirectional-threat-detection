"""
Interactive Demonstration Script: Full Alert & Explainability Engine.
Processes PCAP streams through the entire pipeline:
  PCAP -> Zeek/Suricata -> Telemetry Features -> Hybrid ML + Detectors -> Alert Engine -> Deduplication
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.ml.hybrid_inference import HybridInferenceEngine
from app.alerts.engine import AlertEngine
from app.config import SAMPLES_DIR, DATA_DIR

def run_demo():
    print("=" * 95)
    print("SECURITY ALERT & EXPLAINABILITY ENGINE END-TO-END DEMONSTRATION")
    print("=" * 95)

    hybrid = HybridInferenceEngine()
    alert_engine = AlertEngine(dedup_window_sec=30.0)
    staging_dir = DATA_DIR / "alerts_demo_staging"

    test_pcaps = [
        "benign_traffic.pcap",
        "syn_flood.pcap",
        "port_scan.pcap",
        "dga_dns_tunnel.pcap",
        "c2_beaconing.pcap"
    ]

    for pcap_name in test_pcaps:
        pcap_path = SAMPLES_DIR / pcap_name
        pcap_out = staging_dir / pcap_path.stem
        print(f"\n[+] Ingesting & Analyzing: {pcap_name}")

        # 1. Replay PCAP to Zeek / Suricata
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, pcap_out)

        # 2. Stream normalized events into Feature & ML Engine
        streamer = TelemetryStreamer(pcap_out)
        tracker = StreamingTelemetryTracker()

        new_alerts = []
        correlated_count = 0

        for event in streamer.stream_all_events():
            state = tracker.process_event(event)
            fv = TelemetryFeatureExtractor.extract_features(state, tracker)
            fusion = hybrid.predict(fv)
            
            alert, is_new = alert_engine.process_detection(fv, fusion)
            if is_new:
                new_alerts.append(alert)
            else:
                correlated_count += 1

        print(f"    New Security Alerts: {len(new_alerts)} | Correlated Duplicate Events: {correlated_count}")
        
        # Display the primary alert for this capture
        if new_alerts:
            top_alert = new_alerts[0]
            print(f"    >>> ALERT ID:        {top_alert.alert_id} [{top_alert.severity.value}]")
            print(f"        Threat Category: {top_alert.threat_class} (Confidence: {top_alert.confidence_score * 100:.1f}%)")
            print(f"        Flow ID:         {top_alert.flow_id}")
            print(f"        Primary Reason:  {top_alert.primary_reason}")
            print(f"        Occurrences:     {top_alert.occurrence_count} flow instances correlated")
            print(f"        Detection Method:{top_alert.detection_method}")
            print(f"        Supporting Evidence:")
            for ev_line in top_alert.supporting_evidence:
                print(f"          - {ev_line}")

    print("\n" + "=" * 95)
    print("AGGREGATED SOC STATISTICS:")
    stats = alert_engine.get_statistics()
    print(f"  * Total Unique Alerts Created:  {stats.total_alerts}")
    print(f"  * Total Flow Events Processed:  {stats.total_events_processed}")
    print(f"  * Deduplication Savings Ratio:  {stats.deduplication_savings_ratio * 100:.1f}%")
    print(f"  * Severity Breakdown:           {stats.severity_breakdown}")
    print(f"  * Threat Class Breakdown:       {stats.threat_class_breakdown}")
    print(f"  * Detection Method Breakdown:   {stats.detection_method_breakdown}")
    print("=" * 95)

if __name__ == "__main__":
    run_demo()
