"""
SIH 2026 Cybersecurity Threat Detection Dashboard.
National Technical Research Organisation (NTRO) — Problem Statement 26145.
"""
import sys
from pathlib import Path

# Path resolution for Streamlit Cloud and local environments.
# On Streamlit Cloud, the working dir is /mount/src/<repo>/ and dashboard/ is
# auto-added to sys.path[0] by Streamlit. This makes dashboard/app.py shadow
# backend/app/ package → "app is not a package" errors.
# Fix: remove dashboard/ from sys.path, then ensure backend/ is first.
_APP_FILE = Path(__file__).resolve()
ROOT_DIR  = _APP_FILE.parent.parent   # project root
BACKEND_DIR = ROOT_DIR / "backend"
DASHBOARD_DIR = _APP_FILE.parent      # dashboard/

# Strip any path that resolves to the dashboard directory
sys.path = [p for p in sys.path if Path(p).resolve() != DASHBOARD_DIR]

# Ensure backend (for `from app.X import Y`) and root are on sys.path
for p in [str(BACKEND_DIR), str(ROOT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import streamlit as st

# Streamlit Page Config
st.set_page_config(
    page_title="SIH 2026 | Cyber Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Imports — use relative paths (no 'dashboard.' prefix) since dashboard/ is
# not on sys.path, but ROOT_DIR is, so we can also reach dashboard/ via ROOT_DIR.
try:
    from dashboard.api_client import DashboardApiClient
    from dashboard.components.overview import render_overview
    from dashboard.components.alerts_view import render_alerts_view
    from dashboard.components.alert_details import render_alert_details
    from dashboard.components.analytics_view import render_analytics
    from dashboard.components.demo_mode import render_demo_mode
    from dashboard.components.governance_view import render_governance
except Exception:
    # On Streamlit Cloud, ROOT_DIR is on path so 'dashboard' package is importable via ROOT_DIR
    # Add dashboard back just for component imports (not as a sys module shadowing app/)
    sys.path.insert(0, str(DASHBOARD_DIR))
    from api_client import DashboardApiClient
    from components.overview import render_overview
    from components.alerts_view import render_alerts_view
    from components.alert_details import render_alert_details
    from components.analytics_view import render_analytics
    from components.demo_mode import render_demo_mode
    from components.governance_view import render_governance
    sys.path = [p for p in sys.path if Path(p).resolve() != DASHBOARD_DIR]

# Initialize API Client
if "api_client" not in st.session_state:
    client = DashboardApiClient()
    # Auto-preload demonstration telemetry on initial visit so the dashboard is live
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

if st.sidebar.button("🔄 Force Refresh Data", width='stretch'):
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
