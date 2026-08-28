"""
Alert Deep-Dive & Explainability Explorer Component.
Displays exact observed feature snapshots, ML probabilities, IF anomaly scores,
and factual human-readable evidence.
"""
import streamlit as st
from typing import List, Dict, Any

def render_alert_details(alerts: List[Dict[str, Any]]):
    st.subheader("Alert Deep-Dive & Explainability Explorer")

    if not alerts:
        st.info("No security alerts available to inspect.")
        return

    # Alert Selector Dropdown
    alert_options = [f"{a['alert_id']} | {a['threat_class']} ({a['severity']}) - {a['flow_id']}" for a in alerts[:100]]
    selected_option = st.selectbox("Select Security Alert to Inspect", alert_options)
    
    selected_id = selected_option.split(" | ")[0]
    alert = next((a for a in alerts if a["alert_id"] == selected_id), alerts[0])

    # Top Badges
    b1, b2, b3, b4 = st.columns(4)
    b1.metric("Threat Category", alert.get("threat_class"))
    b2.metric("Confidence Score", f"{alert.get('confidence_score', 0.0) * 100:.1f}%")
    b3.metric("Severity Level", alert.get("severity"))
    b4.metric("Detection Engine", alert.get("detection_method"))

    st.markdown("---")

    # Section 1: SOC Operator Summary & Factual Supporting Evidence
    st.markdown("### Factual Supporting Evidence (Observed Metrics)")
    st.info(f"**Primary SOC Operator Summary**: {alert.get('primary_reason')}")

    evidence_list = alert.get("supporting_evidence", [])
    if evidence_list:
        for ev in evidence_list:
            st.markdown(f"- :white_check_mark: {ev}")
    else:
        st.write("No specific abnormal evidence rules triggered.")

    st.markdown("---")

    # Section 2: Multi-Modal AI Attribution Explorer
    col_ml, col_feat = st.columns([1, 1])

    with col_ml:
        st.markdown("#### Dual-Engine AI Classification")
        
        # Random Forest Probabilities
        rf_probs = alert.get("rf_class_probabilities", {})
        if rf_probs:
            st.markdown("**Random Forest Class Probabilities:**")
            for cls, prob in sorted(rf_probs.items(), key=lambda x: -x[1]):
                st.progress(float(prob), text=f"{cls}: {prob * 100:.1f}%")
        
        # Isolation Forest Anomaly Score
        if_score = alert.get("anomaly_score", 0.0)
        is_anom = alert.get("if_is_anomalous", False)
        st.markdown(f"**Isolation Forest Anomaly Status:** `{'ANOMALOUS' if is_anom else 'NORMAL'}`")
        st.caption(f"Raw Decision Function Value: `{if_score:.6f}` (Non-probabilistic tree-path separation)")

        # Triggered Deterministic Detectors
        trig_dets = alert.get("triggered_detectors", [])
        st.markdown(f"**Triggered Behavioral Detectors ({len(trig_dets)}):**")
        if trig_dets:
            for td in trig_dets:
                st.markdown(f"- :warning: `{td}`")
        else:
            st.caption("Zero deterministic rule violations.")

    with col_feat:
        st.markdown("#### Observed Telemetry Feature Snapshot")
        snapshot = alert.get("feature_snapshot", {})
        if snapshot:
            st.json(snapshot)
        else:
            st.caption("No specific feature snapshot attached.")

        st.markdown("#### Flow & Capture Metadata")
        st.markdown(f"- **Flow 5-Tuple**: `{alert.get('flow_id')}`")
        st.markdown(f"- **Timestamp**: `{alert.get('timestamp_iso')}`")
        st.markdown(f"- **Correlated Occurrences**: `{alert.get('occurrence_count', 1)} instances`")
        st.markdown(f"- **Schema & Model Version**: `Schema {alert.get('schema_version')} | Model {alert.get('model_version')}`")
