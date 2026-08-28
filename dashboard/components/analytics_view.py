"""
Traffic Analysis & Threat Analytics Charts Component.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import List, Dict, Any

def render_analytics(alerts: List[Dict[str, Any]], stats: Dict[str, Any]):
    st.subheader("Network Security Telemetry & Anomaly Analytics")

    if not alerts:
        st.info("No alert telemetry available for analytics.")
        return

    df = pd.DataFrame(alerts)

    c1, c2 = st.columns(2)

    with c1:
        # Severity Breakdown Chart
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Alert Count"]
        fig_sev = px.pie(
            sev_counts,
            names="Severity",
            values="Alert Count",
            color="Severity",
            color_discrete_map={
                "CRITICAL": "#e74c3c",
                "HIGH": "#e67e22",
                "MEDIUM": "#f39c12",
                "LOW": "#3498db",
                "INFO": "#2ecc71"
            },
            title="Alerts by Risk Severity",
            hole=0.4
        )
        fig_sev.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_sev, use_container_width=True)

    with c2:
        # Detection Methods Breakdown
        meth_counts = df["detection_method"].value_counts().reset_index()
        meth_counts.columns = ["Detection Engine", "Count"]
        fig_meth = px.bar(
            meth_counts,
            x="Detection Engine",
            y="Count",
            color="Detection Engine",
            title="Detection Attribution by Engine Type"
        )
        fig_meth.update_layout(height=320, showlegend=False, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig_meth, use_container_width=True)

    # Anomaly Score Distribution Histogram
    st.markdown("#### Isolation Forest Anomaly Score Distribution")
    if "anomaly_score" in df.columns:
        fig_hist = px.histogram(
            df,
            x="anomaly_score",
            color="threat_class",
            nbins=30,
            title="Isolation Forest Decision Function Separation Across Threats"
        )
        fig_hist.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20), xaxis_title="Raw IF Score (Lower = More Anomalous)")
        st.plotly_chart(fig_hist, use_container_width=True)
