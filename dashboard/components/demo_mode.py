"""
Interactive Demo Replay Mode Component.
Allows SOC operators to trigger real-time PCAP replays and observe live ingestion.
"""
import streamlit as st
from typing import Dict, Any

def render_demo_mode(api_client):
    st.subheader("Interactive PCAP Streaming Replay Simulator")
    st.write(
        "Simulate live passive unidirectional network ingestion by streaming real synthetic PCAP traffic "
        "through the full Zeek/Suricata -> Feature Extraction -> Hybrid AI -> Alert Engine pipeline."
    )

    scenarios = {
        "Distributed SYN Flood (DDoS)": ("syn_flood.pcap", "500 packets of spoofed SYN packets targeting victim server 10.0.0.1:80"),
        "Vertical Port Scanning Probe": ("port_scan.pcap", "100 single-SYN connection attempts probing ports 1-100 on target 192.168.1.1"),
        "DNS Tunnelling & DGA Queries": ("dga_dns_tunnel.pcap", "High-entropy algorithmic TXT record requests to recursive resolver 8.8.8.8"),
        "C2 Cobalt Strike Beaconing":   ("c2_beaconing.pcap", "Periodic 1.0s interval TCP PSH-ACK heartbeats to external C2 server"),
        "Data Exfiltration Channel":    ("data_exfiltration.pcap", "High-volume asymmetric outbound data upload (57x upload ratio)"),
        "Normal Benign Web Browsing":   ("benign_traffic.pcap", "Clean multi-session DNS and HTTPS TLS web browsing")
    }

    col1, col2 = st.columns([2, 3])

    with col1:
        selected_scenario_name = st.selectbox("Select Threat Simulation Scenario", list(scenarios.keys()))
        pcap_file, description = scenarios[selected_scenario_name]
        st.caption(f"**Description**: {description}")
        st.caption(f"**Target Sample**: `{pcap_file}`")

        if st.button("🚀 Launch Streaming Replay", type="primary", use_container_width=True):
            with st.spinner(f"Replaying {pcap_file} through passive AI pipeline ..."):
                res = api_client.trigger_replay(pcap_file)
                st.session_state["last_replay_result"] = res
                st.session_state["last_replayed_pcap"] = pcap_file
                if res.get("status") == "COMPLETED":
                    st.success(f"✅ Replay completed! Live alerts generated into dashboard.")
                else:
                    st.warning(f"Status: {res.get('status')} — {res.get('message')}")
                st.rerun()

    with col2:
        st.markdown("#### Live Replay Execution Telemetry")
        last_res = st.session_state.get("last_replay_result")
        if last_res:
            report = last_res.get("report")
            if report:
                st.markdown(f"**PCAP Replayed**: `{report.get('pcap_name')}`")
                
                m1, m2, m3 = st.columns(3)
                m1.metric("Events Processed", f"{report.get('total_events_processed')} events")
                m2.metric("Flows Tracked", f"{report.get('total_flows_tracked')} flows")
                m3.metric("Throughput", f"{report.get('events_per_second')} evt/s")

                st.markdown("**Measured Latency Benchmarks (Hardware Timers):**")
                lat = report.get("end_to_end_latency", {})
                st.markdown(f"- **End-to-End Latency ($p50$)**: `{lat.get('p50_ms')} ms`")
                st.markdown(f"- **End-to-End Latency ($p99$)**: `{lat.get('p99_ms')} ms`")
                st.markdown(f"- **Total Replay Duration**: `{report.get('duration_seconds')} s`")
            else:
                st.write(last_res.get("message", "Processing in background."))
        else:
            st.info("Select a scenario and click 'Launch Streaming Replay' to view real-time performance telemetry.")
