from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from utils.helpers import (
    detections_to_df,
    ensure_session_clock,
    latest_session,
    load_sessions,
    record_page_visit,
    ring_html,
)
from utils.theme import apply_theme

st.set_page_config(page_title="Live Exposure Dashboard", page_icon="📊", layout="wide")
apply_theme(st)
ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Dashboard")


def safe_switch_page(path: str) -> None:
    try:
        st.switch_page(path)
    except Exception:
        st.error("Navigation failed. Use the sidebar to open the target page.")

PLOTLY_LAYOUT = dict(
    paper_bgcolor="#0C0A04",
    plot_bgcolor="#13100A",
    font=dict(color="#E8D48A"),
    xaxis=dict(gridcolor="#2A2200", color="#E8D48A"),
    yaxis=dict(gridcolor="#2A2200", color="#E8D48A"),
    legend=dict(bgcolor="#13100A", bordercolor="#2A2200"),
)

st.title("Live Exposure Dashboard")

action_col1, action_col2, action_col3 = st.columns([1, 1, 2])
with action_col1:
    if st.button("Upload New DNS Log", type="primary", use_container_width=True):
        safe_switch_page("pages/02_upload.py")
with action_col2:
    if st.button("Open Master Report", use_container_width=True):
        safe_switch_page("pages/06_report.py")

session = latest_session()
if not session:
    st.warning("No session found. Upload or generate data first.")
    if st.button("Go to Upload Page"):
        safe_switch_page("pages/02_upload.py")
    st.stop()


detections = session.get("tool_detections", [])
score = float(session.get("exposure_score", 0))
risky_queries = int(sum(d.get("query_count", 0) for d in detections))
gdpr_tools = int(sum(1 for d in detections if d.get("gdpr_concern")))

r1c1, r1c2 = st.columns([1, 1])
r2c1, r2c2 = st.columns([1, 1])

with r1c1:
    st.markdown("Exposure Score")
    st.markdown(ring_html(score), unsafe_allow_html=True)
    st.caption("Overall weighted Shadow IT risk based on severity, volume, and GDPR concerns.")

with r1c2:
    st.metric("Shadow Tools Found", f"{len(detections)} tools", help="Count of matched SaaS tools in latest DNS session.")

with r2c1:
    st.metric("Risky Queries", f"{risky_queries:,} queries", help="Total DNS queries matching known shadow tools.")

with r2c2:
    st.metric("GDPR Concerns", f"{gdpr_tools} tools", help="Matched tools marked with GDPR concern in the catalog.")

left, right = st.columns([1, 1])

df_det = pd.DataFrame(detections)

with left:
    st.subheader("Top Shadow Tools by Query Count")
    if not df_det.empty:
        top = df_det.sort_values("query_count", ascending=False).head(10)
        color_map = {"HIGH": "#F44336", "MEDIUM": "#FF9800", "LOW": "#4CAF50"}
        fig = px.bar(
            top,
            x="query_count",
            y="tool_name",
            orientation="h",
            color="risk_level",
            color_discrete_map=color_map,
        )
        fig.update_layout(**PLOTLY_LAYOUT)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No detections in this session.")

with right:
    st.subheader("Query Distribution by Category")
    if not df_det.empty:
        by_cat = df_det.groupby("category", as_index=False)["query_count"].sum()
        fig = px.pie(
            by_cat,
            values="query_count",
            names="category",
            hole=0.45,
            color_discrete_sequence=["#FFD700", "#FFB300", "#FF9800", "#FF6B00", "#E8D48A"],
        )
        fig.update_layout(**PLOTLY_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No category distribution available.")

sessions = sorted(load_sessions(), key=lambda s: s.get("uploaded_at", ""))
if len(sessions) > 1:
    st.subheader("Exposure Score Timeline")
    trend_df = pd.DataFrame(
        [{"uploaded_at": s.get("uploaded_at"), "score": s.get("exposure_score", 0)} for s in sessions]
    )
    fig_line = go.Figure(
        data=go.Scatter(
            x=trend_df["uploaded_at"],
            y=trend_df["score"],
            mode="lines+markers",
            line=dict(color="#FFD700", width=3),
        )
    )
    fig_line.update_layout(**PLOTLY_LAYOUT)
    st.plotly_chart(fig_line, use_container_width=True)

st.subheader("Detected Shadow Tools")

if df_det.empty:
    st.success("Clean scan: no known shadow tools were detected.")
else:
    f1, f2, f3 = st.columns([1, 1, 1])
    with f1:
        risk_f = st.selectbox("Risk", ["ALL", "HIGH", "MEDIUM", "LOW"])
    with f2:
        cats = ["ALL"] + sorted(df_det["category"].dropna().unique().tolist())
        cat_f = st.selectbox("Category", cats)
    with f3:
        search = st.text_input("Search Tool")

    filtered = df_det.copy()
    if risk_f != "ALL":
        filtered = filtered[filtered["risk_level"] == risk_f]
    if cat_f != "ALL":
        filtered = filtered[filtered["category"] == cat_f]
    if search.strip():
        filtered = filtered[filtered["tool_name"].str.contains(search, case=False, na=False)]

    table_df = detections_to_df(filtered.to_dict("records"))
    st.dataframe(table_df, use_container_width=True)
