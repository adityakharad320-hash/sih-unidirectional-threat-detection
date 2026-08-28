"""
preprocessing.py — Dataset Construction & Preprocessing for Module 3

Builds labeled feature matrix from Module 2 feature vectors.

IMPORTANT:
- Only trains on classes with sufficient samples.
- Reports and handles class imbalance honestly.
- Flags classes that cannot be supervised-trained due to data scarcity.
"""
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.ingestion import PcapStreamReader
from app.core.flow_tracker import StreamingFlowTracker
from app.core.feature_extractor import StreamingFeatureExtractor
from app.core.feature_schema import ORDERED_FEATURE_NAMES
from app.config import SAMPLES_DIR

# ── Class Definitions ─────────────────────────────────────────────────────────
TRAINABLE_CLASSES = {"benign", "syn_flood", "port_scan"}
HEURISTIC_ONLY_CLASSES = {"dns_dga", "c2_beacon"}
UNSUPPORTED_CLASSES = {"exfiltration"}

PCAP_LABEL_MAP = {
    "benign_traffic.pcap": "benign",
    "syn_flood.pcap": "syn_flood",
    "port_scan.pcap": "port_scan",
    "dga_dns_tunnel.pcap": "dns_dga",
    "c2_beaconing.pcap": "c2_beacon",
}

MIN_SAMPLES_FOR_TRAINING = 10  # Hard threshold: below this, class is heuristic-only


def extract_all_feature_vectors(samples_dir: Path = SAMPLES_DIR):
    """
    Streams all PCAPs, extracts flow-level feature vectors, assigns ground-truth labels.
    Returns raw DataFrame before any scaling or filtering.
    """
    records = []

    for pcap_name, label in PCAP_LABEL_MAP.items():
        pcap_path = samples_dir / pcap_name
        if not pcap_path.exists():
            print(f"[WARN] PCAP not found, skipping: {pcap_path}")
            continue

        tracker = StreamingFlowTracker()
        reader = PcapStreamReader(pcap_path)

        flow_snapshots = {}
        for pkt in reader.stream_packets():
            state = tracker.process_packet(pkt)
            fv = StreamingFeatureExtractor.extract_features(state, tracker)
            flow_snapshots[state.flow_key.unidirectional_id] = fv

        for fv in flow_snapshots.values():
            row = fv.to_dict()
            row["_label"] = label
            row["_flow_id"] = fv.flow_id
            records.append(row)

    df = pd.DataFrame(records)
    return df


def build_training_dataset(samples_dir: Path = SAMPLES_DIR):
    """
    Extracts features, filters to trainable classes, checks quality,
    drops duplicates, and returns:
      X_scaled (np.ndarray), y, scaler, X_raw (unscaled), feature_names, audit_report
    """
    df = extract_all_feature_vectors(samples_dir)

    # ── Audit ─────────────────────────────────────────────────────────────────
    class_counts = Counter(df["_label"].tolist())
    trainable = {c: n for c, n in class_counts.items() if c in TRAINABLE_CLASSES and n >= MIN_SAMPLES_FOR_TRAINING}
    heuristic = {c: n for c, n in class_counts.items() if c not in trainable}

    audit_report = {
        "total_flows": len(df),
        "class_counts": dict(class_counts),
        "trainable_classes": trainable,
        "heuristic_only_classes": heuristic,
        "unsupported_classes": list(UNSUPPORTED_CLASSES),
    }

    # ── Filter to trainable classes only ─────────────────────────────────────
    df_train = df[df["_label"].isin(trainable.keys())].copy()

    # ── Drop pure duplicate feature vectors ──────────────────────────────────
    feature_cols = list(ORDERED_FEATURE_NAMES)
    n_before = len(df_train)
    df_train = df_train.drop_duplicates(subset=feature_cols + ["_label"])
    n_after = len(df_train)
    audit_report["duplicates_dropped"] = n_before - n_after

    # ── Sanity checks ─────────────────────────────────────────────────────────
    assert not df_train[feature_cols].isnull().any().any(), "NaN values found in feature matrix"
    assert not np.isinf(df_train[feature_cols].values).any(), "Inf values found in feature matrix"

    X_raw = df_train[feature_cols].values.astype(np.float64)
    y = df_train["_label"].values

    # ── Standardize ──────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    audit_report["samples_for_training"] = len(X_scaled)
    audit_report["feature_count"] = len(feature_cols)
    return X_scaled, y, scaler, X_raw, feature_cols, audit_report


if __name__ == "__main__":
    X_scaled, y, scaler, X_raw, feat_names, report = build_training_dataset()
    print("\n=== PREPROCESSING REPORT ===")
    print(f"  Total flows before filtering:   {report['total_flows']}")
    print(f"  Trainable classes:              {report['trainable_classes']}")
    print(f"  Heuristic-only classes:         {report['heuristic_only_classes']}")
    print(f"  Unsupported classes:            {report['unsupported_classes']}")
    print(f"  Duplicates dropped:             {report['duplicates_dropped']}")
    print(f"  Samples for training:           {report['samples_for_training']}")
    print(f"  Feature dimensions:             {report['feature_count']}")
    print(f"  X shape: {X_scaled.shape}, y distribution: {Counter(y)}")

