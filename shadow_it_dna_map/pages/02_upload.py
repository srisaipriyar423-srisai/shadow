from __future__ import annotations

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
    next_session_id,
    record_page_visit,
    ring_html,
    save_sessions,
)
from utils.theme import apply_theme

st.set_page_config(page_title="DNS Log Upload & Parser", page_icon="📥", layout="wide")
apply_theme(st)
ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Upload")
st.title("DNS Log Upload & Parser")


def safe_switch_page(path: str) -> None:
    try:
        st.switch_page(path)
    except Exception:
        st.error("Navigation failed. Use the sidebar to open the target page.")

UPLOAD_TEMPLATE = """timestamp,source_ip,query_domain,query_type,response_code
2026-03-29 10:15:32,10.0.5.21,notion.so,A,NOERROR
2026-03-29 10:15:34,10.0.5.21,drive.google.com,A,NOERROR
2026-03-29 10:16:01,10.0.8.44,slack.com,A,NOERROR
"""

st.markdown("Step 1 — Upload")
with st.form("dns_upload_form", clear_on_submit=False):
    uploaded = st.file_uploader(
        "Upload DNS log",
        type=["csv", "txt", "log"],
        help="Limit 200MB per file • CSV, TXT, LOG",
    )
    upload_clicked = st.form_submit_button("Upload Selected File", type="primary", use_container_width=True)

st.markdown("### Upload details")
st.caption("Accepted: CSV, TXT, LOG up to 200MB.")
st.markdown("**Standard CSV columns:** `timestamp, source_ip, query_domain, query_type, response_code`")
st.caption("If your file uses Standard CSV, keep the exact header names above.")
st.download_button(
    "Download upload template (.csv)",
    data=UPLOAD_TEMPLATE,
    file_name="dns_upload_template.csv",
    mime="text/csv",
)
st.code(UPLOAD_TEMPLATE, language="csv")

with st.expander("Or generate demo data", expanded=True):
    st.caption("Use this when you do not have a real DNS export yet.")
    st.markdown("**Demo format (Standard CSV):** `timestamp, source_ip, query_domain, query_type, response_code`")

    col1, col2 = st.columns([1, 1])
    with col1:
        n_lines = st.number_input("Number of log entries", 1000, 100000, 10000, step=1000)
        risky = st.number_input("Risky employees", 1, 20, 5)
    with col2:
        end_date = st.date_input("End date", datetime.now().date())
        start_date = st.date_input("Start date", (datetime.now() - timedelta(days=7)).date())

    if start_date > end_date:
        st.error("Start date must be before end date.")
        st.stop()

    if st.button("Generate Demo Data", type="primary"):
        with st.spinner("Generating synthetic DNS data..."):
            catalog = load_catalog().get("tools", [])
            df = generate_synthetic_dns_logs(
                catalog_tools=catalog,
                n_lines=int(n_lines),
                risky_employees=int(risky),
                start_date=datetime.combine(start_date, datetime.min.time()),
                end_date=datetime.combine(end_date, datetime.max.time()),
            )
            text = synthetic_csv_text(df)
            parsed_df, meta = parse_dns_log_content(text)
            st.session_state["upload_text"] = text
            st.session_state["upload_name"] = "demo_dns_log.csv"
            st.session_state["upload_source"] = "demo"
            st.session_state["parsed_df"] = parsed_df
            st.session_state["parse_meta"] = meta
            st.success("Demo data generated and parsed preview is ready.")

    if st.session_state.get("upload_source") == "demo" and "upload_text" in st.session_state:
        preview_lines = "\n".join(st.session_state["upload_text"].splitlines()[:4])
        st.markdown("**Demo upload details**")
        st.caption(
            "Download the generated demo file and drag it into Upload DNS log above, "
            "or continue directly with the parsed preview below."
        )
        st.download_button(
            "Download demo DNS log (.csv)",
            data=st.session_state["upload_text"],
            file_name=st.session_state.get("upload_name", "demo_dns_log.csv"),
            mime="text/csv",
        )
        st.code(preview_lines, language="csv")

if upload_clicked and uploaded is None:
    st.warning("Please choose a file first, then click Upload Selected File.")

if upload_clicked and uploaded is not None:
    size_mb = uploaded.size / (1024 * 1024)
    content = uploaded.getvalue().decode("utf-8", errors="ignore")
    lines = content.count("\n") + 1
    st.info(f"File: {uploaded.name} | Size: {size_mb:.2f} MB | Lines: {lines:,}")
    if size_mb > 200:
        st.error("File exceeds 200MB upload limit. Please upload a smaller file.")
        st.stop()

    parsed_df, meta = parse_dns_log_content(content)
    st.session_state["upload_text"] = content
    st.session_state["upload_name"] = uploaded.name
    st.session_state["upload_source"] = "upload"
    st.session_state["parsed_df"] = parsed_df
    st.session_state["parse_meta"] = meta

if "parse_meta" in st.session_state:
    meta = st.session_state["parse_meta"]
    parsed_df = st.session_state.get("parsed_df")

    st.markdown("Step 2 — Format Detection")
    if not meta.get("format"):
        st.error(
            "File format unrecognised. Supported examples: Standard CSV, Bind/dnsmasq TXT, Pi-hole CSV."
        )
        st.stop()

    st.success(f"Detected: {meta['format']} format ✓")
    st.caption(
        f"Parsed preview: {meta.get('parsed', 0):,} lines, {meta.get('skipped', 0):,} skipped, {meta.get('unique_domains', 0):,} unique domains"
    )
    st.dataframe(parsed_df.head(5), use_container_width=True)

    st.markdown("Step 3 — Parsing and Analysis")
    if st.button("Parse Full Log", type="primary"):
        progress = st.progress(0)
        status = st.empty()
        for p in [10, 25, 45, 65, 85, 100]:
            status.info(
                f"Lines parsed: {meta.get('parsed', 0):,} | Domains: {meta.get('unique_domains', 0):,} | Progress: {p}%"
            )
            progress.progress(p)

        detections, unknown, duration_payload = match_tools(parsed_df)
        score_data = calculate_exposure_score(detections, latest_session())

        st.markdown("### Summary")
        s1, s2 = st.columns([1, 1])
        with s1:
            st.write(f"Total queries parsed: {len(parsed_df):,}")
            st.write(f"Unique domains: {parsed_df['domain'].nunique() if not parsed_df.empty else 0:,}")
            st.write(f"Shadow tools detected: {len(detections)}")
        with s2:
            st.markdown(ring_html(score_data["score"]), unsafe_allow_html=True)

        if not detections:
            st.success("Clean scan: no known shadow tools were detected.")

        st.session_state["analysis_result"] = {
            "detections": detections,
            "unknown": unknown,
            "duration_payload": duration_payload,
            "score_data": score_data,
            "parsed_count": len(parsed_df),
            "unique_domains": int(parsed_df["domain"].nunique()) if not parsed_df.empty else 0,
            "df": parsed_df,
        }

if "analysis_result" in st.session_state:
    if st.button("Save & View Dashboard", type="primary"):
        res = st.session_state["analysis_result"]
        analysis_end = datetime.now()
        duration_text, duration_secs = get_live_duration(st.session_state)
        user_session = build_user_session_payload(st.session_state, analysis_end)
        session = {
            "id": next_session_id(),
            "name": f"DNS Log — {datetime.now().strftime('%d %b %Y')}",
            "uploaded_at": datetime.now().isoformat(timespec="seconds"),
            "log_lines": int(res["parsed_count"]),
            "unique_domains": int(res["unique_domains"]),
            "shadow_tools_found": len(res["detections"]),
            "exposure_score": res["score_data"]["score"],
            "analysis_start_time": user_session["analysis_started_at"],
            "analysis_end_time": analysis_end.isoformat(timespec="seconds"),
            "analysis_duration_seconds": duration_secs,
            "analysis_duration_formatted": duration_text,
            "user_session": user_session,
            "tool_detections": res["detections"],
            "ip_tool_durations": res.get("duration_payload", {}).get("ip_tool_durations", []),
            "tool_hourly_usage": res.get("duration_payload", {}).get("tool_hourly_usage", []),
            "ip_hourly_usage": res.get("duration_payload", {}).get("ip_hourly_usage", []),
            "unknown_domains": res["unknown"][:200],
        }
        sessions = load_sessions()
        sessions.append(session)
        save_sessions(sessions)
        st.session_state["latest_df"] = res["df"]
        st.success("Session saved successfully.")
        safe_switch_page("pages/01_dashboard.py")
