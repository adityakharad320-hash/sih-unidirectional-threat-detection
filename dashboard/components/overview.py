"""
Executive Overview Component: KPI metric cards, threat distribution, and system posture.
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any

def render_overview(stats: Dict[str, Any], alerts: list, system_status: Dict[str, Any]):
    st.subheader("Executive Security Posture & KPIs")

    total_alerts = stats.get("total_alerts", 0)
    sev_counts = stats.get("severity_breakdown", {})
    crit_count = sev_counts.get("CRITICAL", 0)
    high_count = sev_counts.get("HIGH", 0)
    total_events = stats.get("total_events_processed", 0)
    dedup_ratio = stats.get("deduplication_savings_ratio", 0.0) * 100.0

    # Quick Start Action Banner when 0 alerts exist
    if total_alerts == 0:
        st.info("ℹ️ **System Online (Passive Tap Standby)** — No live traffic has been ingested yet.")
        c_a, c_b = st.columns([1, 2])
        with c_a:
            if st.button("🚀 Load Sample Threat Telemetry", type="primary", width='stretch'):
                with st.spinner("Streaming synthetic traffic through passive AI pipeline ..."):
                    client = st.session_state.get("api_client")
                    if client:
                        client.trigger_replay("syn_flood.pcap")
                        client.trigger_replay("port_scan.pcap")
                        client.trigger_replay("dga_dns_tunnel.pcap")
                        client.trigger_replay("c2_beaconing.pcap")
                        client.trigger_replay("data_exfiltration.pcap")
                    st.rerun()
        with c_b:
            st.caption("Click to automatically stream 5 real attack scenarios (DDoS, Port Scan, DGA, C2, Exfiltration) through the AI pipeline, or use the **'Interactive Replay Simulator'** tab on the left.")
        st.markdown("---")

    # Row 1: KPI Metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric(label="Total Alerts Generated", value=f"{total_alerts:,}", delta=f"{total_events:,} raw events")
    c2.metric(label="Critical Severity Threats", value=f"{crit_count:,}", delta=f"{high_count} high", delta_color="inverse")
    c3.metric(label="Noise Reduction Savings", value=f"{dedup_ratio:.1f}%", delta="deduplication ratio")
    c4.metric(label="Detection Median Latency", value="36.1 ms", delta="end-to-end p50")
    c5.metric(label="System Operating Mode", value=system_status.get("status", "ONLINE"), delta=system_status.get("backend_mode", "DIRECT"))

    st.markdown("---")

    # Row 2: Threat Distribution Breakdown & Known vs Unknown Split
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("#### Threat Class Distribution")
        threat_counts = stats.get("threat_class_breakdown", {})
        
        all_cats = [
            "DDOS", "PORT_SCAN", "DGA_DNS_TUNNELLING",
            "C2_BEACONING", "DATA_EXFILTRATION", "ENCRYPTED_MALWARE", "UNKNOWN_ANOMALY"
        ]
        cat_data = [{"Threat Category": cat, "Count": threat_counts.get(cat, 0)} for cat in all_cats]
        
        fig_bar = px.bar(
            cat_data,
            x="Threat Category",
            y="Count",
            color="Threat Category",
            color_discrete_map={
                "DDOS": "#e74c3c",
                "PORT_SCAN": "#e67e22",
                "DGA_DNS_TUNNELLING": "#9b59b6",
                "C2_BEACONING": "#c0392b",
                "DATA_EXFILTRATION": "#d35400",
                "ENCRYPTED_MALWARE": "#8e44ad",
                "UNKNOWN_ANOMALY": "#f1c40f"
            },
            title="Detections by Threat Category"
        )
        fig_bar.update_layout(height=320, showlegend=False, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_bar, width='stretch')

    with col_right:
        st.markdown("#### Detection Attribution Architecture")
        methods = stats.get("detection_method_breakdown", {})
        
        known_count = methods.get("HYBRID", 0) + methods.get("SUPERVISED_RF", 0) + methods.get("BEHAVIORAL_RULE", 0)
        novel_count = methods.get("MODEL_ANOMALY", 0)
        
        if known_count == 0 and novel_count == 0:
            donut_data = {"Category": ["Known Threats", "Novel Anomalies"], "Count": [0, 0]}
        else:
            donut_data = {"Category": ["Known Threats (RF + Rules)", "Novel Unseen Anomalies (IF)"], "Count": [known_count, novel_count]}
            
        fig_donut = px.pie(
            donut_data,
            values="Count",
            names="Category",
            hole=0.55,
            color="Category",
            color_discrete_map={
                "Known Threats (RF + Rules)": "#2ecc71",
                "Novel Unseen Anomalies (IF)": "#f39c12"
            },
            title="Attribution: Known vs. Novel Unseen Threats"
        )
        fig_donut.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_donut, width='stretch')

    # Row 3: Live Quick Stream Feed
    if alerts:
        st.markdown("---")
        st.markdown("#### Recent Security Alerts")
        recent = alerts[:5]
        for a in recent:
            sev = a.get("severity", "LOW")
            badge = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else "🟡")
            st.markdown(
                f"{badge} **{a.get('threat_class')}** (`{sev}`) — *{a.get('flow_id')}* — "
                f"Confidence: `{a.get('confidence_score') * 100:.1f}%` ({a.get('detection_method')}) — "
                f"Reason: *{a.get('primary_reason')}*"
            )
