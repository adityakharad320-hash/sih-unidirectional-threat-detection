"""
Live Alerts Table Component with Search, Severity Filtering, and Selection.
"""
import streamlit as st
import pandas as pd
from typing import List, Dict, Any

def render_alerts_view(alerts: List[Dict[str, Any]]):
    st.subheader("Live Security Alerts & Threat Stream")

    if not alerts:
        st.info("No security alerts currently recorded. Use the Demo Replay tab to stream traffic.")
        return

    # Filter Controls
    f1, f2, f3 = st.columns([2, 2, 3])
    
    threat_classes = ["ALL"] + sorted(list(set(a.get("threat_class", "") for a in alerts)))
    selected_threat = f1.selectbox("Filter Threat Category", threat_classes)

    severities = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    selected_sev = f2.selectbox("Filter Severity Level", severities)

    search_query = f3.text_input("Search Flow ID or IP", placeholder="e.g. 192.168.1.100 or 10.0.0.1")

    # Apply Filters
    filtered = alerts
    if selected_threat != "ALL":
        filtered = [a for a in filtered if a.get("threat_class") == selected_threat]
    if selected_sev != "ALL":
        filtered = [a for a in filtered if a.get("severity") == selected_sev]
    if search_query:
        q = search_query.lower()
        filtered = [a for a in filtered if q in a.get("flow_id", "").lower() or q in a.get("alert_id", "").lower()]

    st.markdown(f"Displaying **{len(filtered)}** of **{len(alerts)}** alerts")

    # Format table records
    table_rows = []
    for a in filtered:
        table_rows.append({
            "Alert ID": a.get("alert_id"),
            "Timestamp (UTC)": a.get("timestamp_iso", "")[:19].replace("T", " "),
            "Threat Category": a.get("threat_class"),
            "Severity": a.get("severity"),
            "Confidence": f"{a.get('confidence_score', 0.0) * 100:.1f}%",
            "Flow 5-Tuple": a.get("flow_id"),
            "Instances": a.get("occurrence_count", 1),
            "Method": a.get("detection_method")
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, height=450)
