"""
SIH 2026 Cybersecurity Threat Detection Dashboard.
National Technical Research Organisation (NTRO) — Problem Statement 26145.
"""
import streamlit as st
import time
from pathlib import Path

# Streamlit Page Config
st.set_page_config(
    page_title="SIH 2026 | Cyber Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from dashboard.api_client import DashboardApiClient
from dashboard.components.overview import render_overview
from dashboard.components.alerts_view import render_alerts_view
from dashboard.components.alert_details import render_alert_details
from dashboard.components.analytics_view import render_analytics
from dashboard.components.demo_mode import render_demo_mode
from dashboard.components.governance_view import render_governance

# Initialize API Client
if "api_client" not in st.session_state:
    st.session_state["api_client"] = DashboardApiClient()

api_client = st.session_state["api_client"]

# Sidebar Controls
st.sidebar.title("🛡️ SIH 2026 NTRO")
st.sidebar.caption("AI-Based Unidirectional Threat Detection")

# System Status Widget
system_status = api_client.get_system_status()
st.sidebar.success(f"System: {system_status.get('status', 'ONLINE')}")
st.sidebar.info(f"Engine Mode: `{system_status.get('backend_mode')}`")

st.sidebar.markdown("---")
st.sidebar.subheader("Navigation")
active_tab = st.sidebar.radio(
    "Select View",
    [
        "1. Executive Overview",
        "2. Live Alerts Stream",
        "3. Alert Deep-Dive & Explainability",
        "4. Telemetry & Threat Analytics",
        "5. Interactive Demo Replay",
        "6. Model Governance & Metrics"
    ]
)

if st.sidebar.button("Refresh Telemetry", use_container_width=True):
    st.rerun()

# Fetch latest data from backend
stats = api_client.get_statistics()
alerts = api_client.get_alerts(limit=200)

# Main Title Header
st.title("AI-Based Threat Detection in Unidirectional IP Traffic")
st.caption("Passive Network Telemetry (Zeek + Suricata) → Feature Windows → Hybrid ML & Detectors → Alert Engine")

# Route to Active Tab Component
if active_tab == "1. Executive Overview":
    render_overview(stats, alerts, system_status)

elif active_tab == "2. Live Alerts Stream":
    render_alerts_view(alerts)

elif active_tab == "3. Alert Deep-Dive & Explainability":
    render_alert_details(alerts)

elif active_tab == "4. Telemetry & Threat Analytics":
    render_analytics(alerts, stats)

elif active_tab == "5. Interactive Demo Replay":
    render_demo_mode(api_client)

elif active_tab == "6. Model Governance & Metrics":
    render_governance()
