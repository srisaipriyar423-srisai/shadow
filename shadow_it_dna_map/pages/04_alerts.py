from __future__ import annotations

from datetime import date, datetime

import pandas as pd
import streamlit as st

from utils.helpers import ensure_session_clock, load_alerts, record_page_visit, save_alerts
from utils.theme import apply_theme

st.set_page_config(page_title="Alerts Manager", page_icon="🚨", layout="wide")
apply_theme(st)
ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Alerts")
st.title("Alerts Manager")

alerts = load_alerts()

open_count = sum(1 for a in alerts if a.get("status") == "open")
ack_count = sum(1 for a in alerts if a.get("status") == "acknowledged")
resolved_count = sum(1 for a in alerts if a.get("status") == "resolved")

s1, s2, s3 = st.columns([1, 1, 1])
s1.metric("Open alerts", open_count)
s2.metric("Acknowledged", ack_count)
s3.metric("Resolved", resolved_count)

f1, f2, f3 = st.columns([1, 1, 1])
with f1:
    status_f = st.selectbox("Status", ["ALL", "open", "acknowledged", "resolved"])
with f2:
    sev_f = st.selectbox("Severity", ["ALL", "HIGH", "MEDIUM", "LOW"])
with f3:
    default_from = date.today().replace(day=1)
    date_range = st.date_input("Date range", value=(default_from, date.today()))

filtered = []
for a in alerts:
    created = a.get("created_at", "")[:10]
    try:
        created_d = datetime.fromisoformat(created).date()
    except ValueError:
        created_d = date.today()

    include = True
    if status_f != "ALL" and a.get("status") != status_f:
        include = False
    if sev_f != "ALL" and a.get("severity") != sev_f:
        include = False
    if isinstance(date_range, tuple) and len(date_range) == 2:
        if not (date_range[0] <= created_d <= date_range[1]):
            include = False
    if include:
        filtered.append(a)

if not filtered:
    st.info("No alerts match the selected filters.")

for i, a in enumerate(filtered):
    sev = a.get("severity", "LOW")
    st.markdown(
        f"""
        <div class='dna-card'>
            <div class='card-title'>{a.get('tool_name')} • {sev} </div>
            <div class='card-sub'>Session: {a.get('session_id')} • Created: {a.get('created_at')}</div>
            <p>{a.get('message')}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns([1, 2, 1])
    with c1:
        new_status = st.selectbox(
            "Status",
            ["open", "acknowledged", "resolved"],
            index=["open", "acknowledged", "resolved"].index(a.get("status", "open")),
            key=f"status_{a.get('id')}",
        )
    with c2:
        note = st.text_input("Add note", value=a.get("notes", ""), key=f"note_{a.get('id')}")
    with c3:
        if st.button("Resolve", key=f"resolve_{a.get('id')}"):
            a["status"] = "resolved"
            st.success("Alert resolved.")

    a["status"] = new_status
    a["notes"] = note

save_alerts(alerts)

if alerts:
    export_df = pd.DataFrame(alerts)
    st.download_button(
        "Download Alerts as CSV",
        data=export_df.to_csv(index=False).encode("utf-8"),
        file_name="shadow_it_alerts.csv",
        mime="text/csv",
    )
