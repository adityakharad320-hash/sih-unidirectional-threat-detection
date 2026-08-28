"""
SIH 2026 Cybersecurity Threat Detection Dashboard.
National Technical Research Organisation (NTRO) — Problem Statement 26145.
"""
import sys
from pathlib import Path

_APP_FILE = Path(__file__).resolve()
ROOT_DIR  = _APP_FILE.parent.parent   # project root
BACKEND_DIR = ROOT_DIR / "backend"
DASHBOARD_DIR = _APP_FILE.parent      # dashboard/

# Strip dashboard/ from sys.path so app.py doesn't shadow backend/app package
sys.path = [p for p in sys.path if Path(p).resolve() != DASHBOARD_DIR]

# Ensure backend and root are at top of sys.path
for p in [str(BACKEND_DIR), str(ROOT_DIR)]:
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)

# If sys.modules['app'] is not a package, clean it
if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

import streamlit as st

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

# Initialize API Client & Preload Live Telemetry
if "api_client" not in st.session_state:
    client = DashboardApiClient()
    if client.get_statistics().get("total_alerts", 0) == 0:
        client.load_demo_scenarios()
    st.session_state["api_client"] = client

api_client = st.session_state["api_client"]

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SIH 2026 Threat Monitor")
st.sidebar.caption("National Technical Research Organisation (NTRO) • PS 26145")

view_selection = st.sidebar.radio(
    "Navigation Console",
    [
        "Executive Overview",
        "Live Security Alerts",
        "Deep Threat Analytics",
        "Interactive Replay Simulator",
        "Model Governance & Audit"
    ],
    index=0,
    key="nav_radio"
)

st.sidebar.markdown("---")
st.sidebar.caption("🔍 **Engine Mode**: Passive Unidirectional Stream")
st.sidebar.caption("⚡ **Latency Target**: Sub-200ms Bounded SLA")

if st.sidebar.button("🔄 Force Refresh Data", width="stretch"):
    st.rerun()

# Data Ingestion
stats = api_client.get_statistics()
alerts = api_client.get_alerts(limit=500)
system_status = api_client.get_system_status()

# Route Views
if view_selection == "Executive Overview":
    render_overview(stats, alerts, system_status)

elif view_selection == "Live Security Alerts":
    selected_alert = render_alerts_view(alerts)
    if selected_alert:
        st.markdown("---")
        render_alert_details(selected_alert)

elif view_selection == "Deep Threat Analytics":
    render_analytics(alerts, stats)

elif view_selection == "Interactive Replay Simulator":
    render_demo_mode(api_client)

elif view_selection == "Model Governance & Audit":
    render_governance()

# Footer
st.markdown("---")
st.caption("🛡️ **SIH 2026 Cybersecurity Defense Platform** | Problem Statement 26145 | Developed for NTRO")
