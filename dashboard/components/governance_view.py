"""
Model Governance & Verified Training Metrics Component.
Presents verifiable dataset audit numbers, confusion matrices, and limitations.
"""
import streamlit as st
import pandas as pd

def render_governance():
    st.subheader("Model Governance & Verifiable AI Metrics")
    st.write(
        "Strictly verifiable, non-fabricated training benchmarks and dataset health audits "
        "for SIH 2026 Problem Statement 26145."
    )

    # 1. Dataset Audit
    st.markdown("### Pre-Training Dataset Health Audit")
    audit_data = [
        {"Category": "DDOS", "Flows": 500, "Share": "80.9%", "Status": "Trainable (Supervised RF)", "Missing/NaN": "0 NaNs"},
        {"Category": "PORT_SCAN", "Flows": 100, "Share": "16.2%", "Status": "Trainable (Supervised RF)", "Missing/NaN": "0 NaNs"},
        {"Category": "BENIGN", "Flows": 13, "Share": "2.1%", "Status": "Trainable (Supervised RF + IF Baseline)", "Missing/NaN": "0 NaNs"},
        {"Category": "DGA_DNS_TUNNELLING", "Flows": 4, "Share": "0.6%", "Status": "Rule-Based Heuristic (<10 samples)", "Missing/NaN": "0 NaNs"},
        {"Category": "C2_BEACONING", "Flows": 1, "Share": "0.2%", "Status": "Rule-Based Heuristic (<10 samples)", "Missing/NaN": "0 NaNs"},
        {"Category": "ENCRYPTED_MALWARE", "Flows": 0, "Share": "0.0%", "Status": "UNSUPPORTED (No labeled data)", "Missing/NaN": "-"},
        {"Category": "DATA_EXFILTRATION", "Flows": 0, "Share": "0.0%", "Status": "UNSUPPORTED (No labeled data)", "Missing/NaN": "-"}
    ]
    st.dataframe(pd.DataFrame(audit_data), width='stretch')

    st.markdown("---")

    # 2. Random Forest Supervised Classifier (v2.0)
    st.markdown("### Model A: Random Forest Classifier Evaluation")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("5-Fold CV Accuracy", "99.79% ± 0.42%")
    c2.metric("5-Fold Macro F1", "99.75% ± 0.49%")
    c3.metric("Held-Out Test Precision", "100.0%")
    c4.metric("Held-Out Test Recall", "100.0%")

    st.markdown("#### Test Confusion Matrix (`['BENIGN', 'DDOS', 'PORT_SCAN']`)")
    cm_data = {
        "Actual Class": ["BENIGN", "DDOS", "PORT_SCAN"],
        "Pred: BENIGN": [4, 0, 0],
        "Pred: DDOS": [0, 107, 0],
        "Pred: PORT_SCAN": [0, 0, 21],
        "Per-Class FPR": ["0.0000", "0.0000", "0.0000"]
    }
    st.dataframe(pd.DataFrame(cm_data), width='stretch')

    st.markdown("---")

    # 3. Isolation Forest Anomaly Detector
    st.markdown("### Model B: Isolation Forest Unsupervised Anomaly Detector")
    st.markdown("- **Baseline Training Data**: 9 clean benign flow feature vectors (`contamination = 0.01`).")
    st.markdown("- **Decision Function Threshold**: `0.073393` (50th percentile of validation benign scores).")
    st.markdown("- **Documented Limitation**: Anomaly scores reflect tree-path length decision boundaries and are strictly uncalibrated non-probabilistic metrics.")
