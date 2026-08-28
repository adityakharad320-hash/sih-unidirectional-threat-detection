"""
Dataset Builder: PCAP → Telemetry → Feature Vectors → Labeled DataFrame.

HONEST AUDIT RESULTS (synthetic data only):
  BENIGN             13 flows
  DDOS              500 flows
  PORT_SCAN         100 flows
  DGA_DNS_TUNNELLING  4 flows  ← heuristic-only (< 10 samples)
  C2_BEACONING        1 flow   ← heuristic-only (< 10 samples)
  ENCRYPTED_MALWARE   0 flows  ← NOT SUPPORTED
  DATA_EXFILTRATION   0 flows  ← NOT SUPPORTED
"""
import sys, logging
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter
from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.telemetry.feature_schema import ORDERED_TELEMETRY_FEATURE_NAMES
from app.config import SAMPLES_DIR, DATA_DIR

logger = logging.getLogger(__name__)

PCAP_LABEL_MAP = {
    "benign_traffic.pcap": "BENIGN",
    "syn_flood.pcap": "DDOS",
    "port_scan.pcap": "PORT_SCAN",
    "dga_dns_tunnel.pcap": "DGA_DNS_TUNNELLING",
    "c2_beaconing.pcap": "C2_BEACONING",
}
MIN_SAMPLES_FOR_SUPERVISED = 10

# Classes with enough samples to train/evaluate
TRAINABLE_CLASSES = {"BENIGN", "DDOS", "PORT_SCAN"}
# Too few samples — heuristic detectors only
HEURISTIC_ONLY = {"DGA_DNS_TUNNELLING", "C2_BEACONING"}
# No data at all
UNSUPPORTED_CLASSES = {"ENCRYPTED_MALWARE", "DATA_EXFILTRATION"}


def build_labeled_dataframe(staging_dir: Path = None) -> pd.DataFrame:
    if staging_dir is None:
        staging_dir = DATA_DIR / "ml_staging"

    records = []
    for pcap_name, label in PCAP_LABEL_MAP.items():
        pcap_path = SAMPLES_DIR / pcap_name
        out_dir = staging_dir / pcap_path.stem
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, out_dir)

        streamer = TelemetryStreamer(out_dir)
        tracker = StreamingTelemetryTracker()
        flow_fvs = {}
        for event in streamer.stream_all_events():
            state = tracker.process_event(event)
            fv = TelemetryFeatureExtractor.extract_features(state, tracker)
            flow_fvs[state.flow_id] = fv

        for fv in flow_fvs.values():
            row = {name: float(getattr(fv, name, 0.0)) for name in ORDERED_TELEMETRY_FEATURE_NAMES}
            row["_label"] = label
            row["_flow_id"] = fv.flow_id
            row["_pcap_source"] = pcap_name
            records.append(row)

    df = pd.DataFrame(records)
    logger.info(f"Dataset built: {len(df)} flows | {Counter(df['_label'].tolist())}")
    return df


def get_audit_report(df: pd.DataFrame) -> dict:
    feature_cols = list(ORDERED_TELEMETRY_FEATURE_NAMES)
    class_counts = Counter(df["_label"].tolist())
    duplicates = df.duplicated(subset=feature_cols + ["_label"]).sum()
    nan_count = int(df[feature_cols].isna().sum().sum())
    inf_count = int(np.isinf(df[feature_cols].values).sum())
    return {
        "total_flows": len(df),
        "class_distribution": dict(class_counts),
        "trainable_classes": {c: n for c, n in class_counts.items()
                              if c in TRAINABLE_CLASSES and n >= MIN_SAMPLES_FOR_SUPERVISED},
        "heuristic_only": {c: n for c, n in class_counts.items() if c in HEURISTIC_ONLY},
        "unsupported_classes": list(UNSUPPORTED_CLASSES),
        "duplicates": int(duplicates),
        "nan_values": nan_count,
        "inf_values": inf_count,
        "feature_count": len(feature_cols),
        "data_source": "Synthetic PCAPs (in-house generated) — NOT real-world traffic",
        "leakage_note": (
            "Each PCAP maps 1-to-1 with a label; group-based PCAP-level split is used "
            "to avoid leakage between nearly-identical flows from the same capture."
        ),
    }
