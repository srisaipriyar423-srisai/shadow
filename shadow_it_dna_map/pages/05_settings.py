from __future__ import annotations

import pandas as pd
import streamlit as st

from utils.helpers import (
    CATALOG_DEFAULT_PATH,
    CATALOG_PATH,
    ensure_session_clock,
    load_sessions,
    load_settings,
    record_page_visit,
    safe_json_load,
    safe_json_save,
    save_sessions,
    save_settings,
)
from utils.theme import apply_theme

st.set_page_config(page_title="Settings & Reference", page_icon="⚙️", layout="wide")
apply_theme(st)
ensure_session_clock(st.session_state)
record_page_visit(st.session_state, "Settings")
st.title("Settings & Reference")

st.subheader("App Settings")
settings = load_settings()

risk_threshold = st.select_slider(
    "Default risk threshold for auto-alerting",
    options=["LOW", "MEDIUM", "HIGH"],
    value=settings.get("risk_threshold", "MEDIUM"),
)
auto_alert = st.toggle("Auto-generate alerts on upload", value=bool(settings.get("auto_alert", True)))
session_limit = st.number_input("Session retention limit", 1, 500, int(settings.get("session_limit", 20)))

if st.button("Save Settings", type="primary"):
    ok = save_settings(
        {
            "risk_threshold": risk_threshold,
            "auto_alert": auto_alert,
            "session_limit": int(session_limit),
        }
    )
    if ok:
        st.success("Settings saved.")
    else:
        st.error("Failed to save settings.")

st.markdown("---")
st.subheader("Sessions History")
sessions = load_sessions()
if not sessions:
    st.info("No sessions saved yet.")
else:
    s_df = pd.DataFrame(sessions)
    st.dataframe(
        s_df[["id", "name", "uploaded_at", "log_lines", "unique_domains", "shadow_tools_found", "exposure_score"]],
        use_container_width=True,
    )
    ids = [s.get("id") for s in sessions]
    delete_id = st.selectbox("Delete a session", ["NONE"] + ids)
    if st.button("Delete Selected Session") and delete_id != "NONE":
        sessions = [s for s in sessions if s.get("id") != delete_id]
        save_sessions(sessions)
        st.success("Session deleted.")
        st.rerun()

    if st.button("Clear All Sessions"):
        save_sessions([])
        st.success("All sessions cleared.")
        st.rerun()

st.markdown("---")
st.subheader("Data Reference")
catalog = safe_json_load(CATALOG_PATH, {"tools": []}).get("tools", [])

if catalog:
    cdf = pd.DataFrame(catalog)
    st.write(f"Total tools: {len(cdf)}")
    by_cat = cdf.groupby("category", as_index=False).size().rename(columns={"size": "count"})
    st.dataframe(by_cat, use_container_width=True)

    if st.button("Reset Catalog to Default"):
        default_catalog = safe_json_load(CATALOG_DEFAULT_PATH, {"tools": []})
        if safe_json_save(CATALOG_PATH, default_catalog):
            st.success("Catalog reset to default.")
        else:
            st.error("Failed to reset catalog.")

    st.download_button(
        "Export Catalog as CSV",
        data=cdf.to_csv(index=False).encode("utf-8"),
        file_name="saas_catalog.csv",
        mime="text/csv",
    )
else:
    st.warning("Catalog appears empty.")
