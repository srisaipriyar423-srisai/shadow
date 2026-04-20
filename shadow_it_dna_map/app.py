from __future__ import annotations

import os
import json
from datetime import datetime, timedelta

import streamlit as st

from core.generator import generate_synthetic_dns_logs, synthetic_csv_text
from core.matcher import load_catalog, match_tools
from core.parser import parse_dns_log_content
from core.scorer import calculate_exposure_score
from utils.helpers import (
    build_user_session_payload,
    ensure_session_clock,
    get_live_duration,
    latest_session,
    load_sessions,
    save_sessions,
    init_storage,
    next_session_id,
    record_page_visit,
    ring_html,
)
from utils.theme import apply_theme, THEME

# Ensure data directory and default files exist
os.makedirs("data", exist_ok=True)

for fname, default in [
    ("data/sessions.json", {"sessions": []}),
    ("data/alerts.json", {"alerts": []}),
    ("data/settings.json", {"risk_threshold": "MEDIUM", "auto_alert": True, "session_limit": 20}),
]:
    if not os.path.exists(fname):
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)

init_storage()

st.set_page_config(page_title="Shadow IT DNA Map", page_icon="🔍", layout="wide")
apply_theme(st)

ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Home")


with st.sidebar:
    st.markdown(f"<h2 style='color:{THEME['color']}'>🔍 Shadow IT DNA Map</h2>", unsafe_allow_html=True)
    st.markdown(
        f"<p style='color:{THEME['muted']}; margin-top:-8px;'>02 — IT Management</p>",
        unsafe_allow_html=True,
    )
    st.markdown("<hr>", unsafe_allow_html=True)

    st.page_link("app.py", label="Home")
    st.page_link("pages/01_dashboard.py", label="Live Exposure Dashboard")
    st.page_link("pages/02_upload.py", label="DNS Log Upload & Parsing")
    st.page_link("pages/03_tools.py", label="Shadow Tool Browser")
    st.page_link("pages/04_alerts.py", label="Alerts Manager")
    st.page_link("pages/05_settings.py", label="Settings & Reference")
    try:
        st.page_link("pages/06_report.py", label="📄 Master Report")
    except Exception:
        if st.button("📄 Master Report", use_container_width=True):
            st.switch_page("pages/06_report.py")

    st.markdown("---")
    latest = latest_session()
    if latest:
        score = latest.get("exposure_score", 0)
        st.markdown(ring_html(score), unsafe_allow_html=True)
        st.markdown(f"Exposure Score: {int(score)}/100")
        st.caption(f"Last analysed: {latest.get('uploaded_at', '-')}")
    else:
        st.info("No analysis session yet.")

    st.markdown("---")
    st.markdown("### Session Timer")
    duration_str, duration_secs = get_live_duration(st.session_state)
    st.metric("Session Duration", duration_str)
    st.caption(f"Started: {st.session_state['app_start_time'].strftime('%H:%M:%S')}")
    if st.button("End Session", use_container_width=True):
        st.session_state["app_end_time"] = datetime.now()
        st.session_state["session_ended"] = True
        st.success(f"Session ended at {st.session_state['app_end_time'].strftime('%H:%M:%S')}")


st.title("Shadow IT DNA Map")
sessions = load_sessions()

if not sessions:
    st.markdown(
        "Analyse internal DNS logs to discover unauthorised SaaS usage, score exposure, and trigger risk alerts."
    )

    st.markdown("### Quick Start")
    st.write("1. Generate demo DNS data or upload your own DNS file")
    st.write("2. Parse and match detected domains against the SaaS catalog")
    st.write("3. Review exposure score, tools, and alerts")

    c1, c2 = st.columns([1, 1])

    with c1:
        if st.button("Generate Demo Data", type="primary", use_container_width=True):
            with st.spinner("Generating and analysing demo DNS log..."):
                catalog = load_catalog().get("tools", [])
                df_demo = generate_synthetic_dns_logs(
                    catalog_tools=catalog,
                    n_lines=10000,
                    risky_employees=5,
                    start_date=datetime.now() - timedelta(days=7),
                    end_date=datetime.now(),
                )
                parsed_df, _ = parse_dns_log_content(synthetic_csv_text(df_demo))
                detections, unknown_domains, duration_payload = match_tools(parsed_df)
                prev = latest_session()
                score_data = calculate_exposure_score(detections, prev)
                analysis_end = datetime.now()
                user_session = build_user_session_payload(st.session_state, analysis_end)

                session = {
                    "id": next_session_id(),
                    "name": f"Demo DNS Log — {datetime.now().strftime('%d %b %Y')}",
                    "uploaded_at": datetime.now().isoformat(timespec="seconds"),
                    "log_lines": int(len(parsed_df)),
                    "unique_domains": int(parsed_df["domain"].nunique()) if not parsed_df.empty else 0,
                    "shadow_tools_found": len(detections),
                    "exposure_score": score_data["score"],
                    "analysis_start_time": user_session["analysis_started_at"],
                    "analysis_end_time": user_session["analysis_ended_at"],
                    "analysis_duration_seconds": user_session["analysis_duration_sec"],
                    "analysis_duration_formatted": user_session["analysis_duration_fmt"],
                    "user_session": user_session,
                    "tool_detections": detections,
                    "ip_tool_durations": duration_payload.get("ip_tool_durations", []),
                    "tool_hourly_usage": duration_payload.get("tool_hourly_usage", []),
                    "ip_hourly_usage": duration_payload.get("ip_hourly_usage", []),
                    "unknown_domains": unknown_domains[:200],
                }
                sessions = load_sessions()
                sessions.append(session)
                save_sessions(sessions)
                st.session_state["latest_df"] = parsed_df
                st.success("Demo session generated and saved.")
                st.switch_page("pages/01_dashboard.py")

    with c2:
        if st.button("Upload DNS Log", use_container_width=True):
            st.switch_page("pages/02_upload.py")
else:
    latest = latest_session()
    st.success("A previous session exists. Continue from the dashboard.")
    c1, c2 = st.columns([1, 1])
    with c1:
        if latest:
            st.markdown(ring_html(latest.get("exposure_score", 0)), unsafe_allow_html=True)
            st.caption(f"Session: {latest.get('name', '-')}")
    with c2:
        if st.button("Open Dashboard", type="primary", use_container_width=True):
            st.switch_page("pages/01_dashboard.py")
        if st.button("Upload New DNS Log", use_container_width=True):
            st.switch_page("pages/02_upload.py")
