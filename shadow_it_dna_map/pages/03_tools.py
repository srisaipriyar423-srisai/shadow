from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from core.matcher import load_catalog
from utils.helpers import (
    CATALOG_PATH,
    ensure_session_clock,
    latest_session,
    load_alerts,
    record_page_visit,
    risk_badge_html,
    save_alerts,
    safe_json_save,
)
from utils.theme import apply_theme

st.set_page_config(page_title="Shadow Tool Browser", page_icon="🧰", layout="wide")
apply_theme(st)
ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Tools")
st.title("Shadow Tool Browser")

session = latest_session()
catalog = load_catalog().get("tools", [])

tab1, tab2 = st.tabs(["Detected Tools", "Full SaaS Catalog"])

with tab1:
    detections = session.get("tool_detections", []) if session else []
    if not detections:
        st.info("No detected tools in latest session. Upload or generate data first.")
    else:
        df = pd.DataFrame(detections)
        f1, f2, f3 = st.columns([1, 1, 1])
        with f1:
            risk_f = st.selectbox("Risk Level", ["ALL", "HIGH", "MEDIUM", "LOW"])
        with f2:
            categories = ["ALL"] + sorted(df["category"].dropna().unique().tolist())
            cat_f = st.selectbox("Category", categories)
        with f3:
            search = st.text_input("Search")

        if risk_f != "ALL":
            df = df[df["risk_level"] == risk_f]
        if cat_f != "ALL":
            df = df[df["category"] == cat_f]
        if search.strip():
            df = df[df["tool_name"].str.contains(search, case=False, na=False)]

        for _, row in df.iterrows():
            gdpr_text = "⚠️ Yes — personal data may be transmitted" if row.get("gdpr_concern") else "No"
            reasons = ", ".join(row.get("risk_reasons", []))
            badge = risk_badge_html(row.get("risk_level", "LOW"))
            st.markdown(
                f"""
                <div class='dna-card'>
                    <div class='card-title'>📦 {row.get('tool_name')} &nbsp; {badge}</div>
                    <div class='card-sub'>{row.get('category')} • {row.get('query_count')} queries • {row.get('unique_ips')} devices</div>
                    <p>Risk reasons: {reasons}</p>
                    <p>GDPR: {gdpr_text}</p>
                    <p>Alternative: {row.get('approved_alternative')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            c1, c2 = st.columns([1, 1])
            with c1:
                if st.button(f"Create Alert for {row.get('tool_id')}", key=f"alert_{row.get('tool_id')}"):
                    alerts = load_alerts()
                    alert = {
                        "id": f"alert_{len(alerts) + 1:03d}",
                        "session_id": session.get("id") if session else None,
                        "tool_id": row.get("tool_id"),
                        "tool_name": row.get("tool_name"),
                        "severity": row.get("risk_level"),
                        "message": f"{row.get('tool_name')} detected with {row.get('query_count')} queries from {row.get('unique_ips')} unique devices. Potential exposure risk.",
                        "created_at": datetime.now().isoformat(timespec="seconds"),
                        "status": "open",
                        "assigned_to": None,
                        "notes": "",
                    }
                    alerts.append(alert)
                    save_alerts(alerts)
                    st.success("Alert created.")
            with c2:
                st.button("Dismiss", key=f"dismiss_{row.get('tool_id')}")

with tab2:
    st.subheader("Catalog")
    cat_df = pd.DataFrame(catalog)
    if not cat_df.empty:
        search_all = st.text_input("Search catalog")
        shown = cat_df.copy()
        if search_all.strip():
            shown = shown[shown["name"].str.contains(search_all, case=False, na=False)]
        st.dataframe(shown, use_container_width=True)

    st.markdown("### Add Custom Tool")
    with st.form("add_tool"):
        name = st.text_input("Name")
        domain = st.text_input("Domain")
        category = st.text_input("Category")
        risk = st.selectbox("Risk Level", ["LOW", "MEDIUM", "HIGH"])
        reasons = st.text_area("Risk Reasons (comma separated)")
        gdpr = st.toggle("GDPR concern")
        alternative = st.text_input("Approved Alternative")
        submitted = st.form_submit_button("Add Tool")

        if submitted:
            if not name or not domain:
                st.error("Name and domain are required.")
            else:
                tool_id = name.lower().replace(" ", "_")
                catalog.append(
                    {
                        "id": tool_id,
                        "name": name,
                        "category": category or "Other",
                        "domains": [domain.strip().lower()],
                        "risk_level": risk,
                        "risk_reasons": [r.strip() for r in reasons.split(",") if r.strip()],
                        "approved_alternative": alternative or "N/A",
                        "gdpr_concern": gdpr,
                        "data_types": [],
                    }
                )
                if safe_json_save(CATALOG_PATH, {"tools": catalog}):
                    st.success("Custom tool added to catalog.")
                else:
                    st.error("Failed to save catalog.")
