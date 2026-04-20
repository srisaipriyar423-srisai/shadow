from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

DATA_DIR = Path("data")
CATALOG_PATH = DATA_DIR / "saas_catalog.json"
CATALOG_DEFAULT_PATH = DATA_DIR / "saas_catalog_default.json"
RISK_RULES_PATH = DATA_DIR / "risk_rules.json"
SESSIONS_PATH = DATA_DIR / "sessions.json"
ALERTS_PATH = DATA_DIR / "alerts.json"
SETTINGS_PATH = DATA_DIR / "settings.json"


def ensure_file(path: Path, default: dict[str, Any]) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)


def init_storage() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    ensure_file(SESSIONS_PATH, {"sessions": []})
    ensure_file(ALERTS_PATH, {"alerts": []})
    ensure_file(
        SETTINGS_PATH,
        {"risk_threshold": "MEDIUM", "auto_alert": True, "session_limit": 20},
    )


def safe_json_load(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        if not path.exists():
            ensure_file(path, default)
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def safe_json_save(path: Path, data: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except OSError:
        return False


def load_sessions() -> list[dict[str, Any]]:
    return safe_json_load(SESSIONS_PATH, {"sessions": []}).get("sessions", [])


def save_sessions(sessions: list[dict[str, Any]]) -> bool:
    return safe_json_save(SESSIONS_PATH, {"sessions": sessions})


def load_alerts() -> list[dict[str, Any]]:
    return safe_json_load(ALERTS_PATH, {"alerts": []}).get("alerts", [])


def save_alerts(alerts: list[dict[str, Any]]) -> bool:
    return safe_json_save(ALERTS_PATH, {"alerts": alerts})


def load_settings() -> dict[str, Any]:
    return safe_json_load(
        SETTINGS_PATH,
        {"risk_threshold": "MEDIUM", "auto_alert": True, "session_limit": 20},
    )


def save_settings(settings: dict[str, Any]) -> bool:
    return safe_json_save(SETTINGS_PATH, settings)


def latest_session() -> dict[str, Any] | None:
    sessions = load_sessions()
    if not sessions:
        return None
    return sorted(sessions, key=lambda s: s.get("uploaded_at", ""))[-1]


def next_session_id() -> str:
    return f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def next_alert_id(alerts: list[dict[str, Any]]) -> str:
    return f"alert_{len(alerts) + 1:03d}"


def risk_badge_html(level: str) -> str:
    level_u = (level or "LOW").upper()
    css = "risk-low"
    if level_u == "HIGH":
        css = "risk-high"
    elif level_u == "MEDIUM":
        css = "risk-medium"
    return f"<span class='risk-badge {css}'>{level_u} RISK</span>"


def score_class(score: float) -> str:
    if score >= 66:
        return "score-high"
    if score >= 31:
        return "score-medium"
    return "score-low"


def ring_html(score: float) -> str:
    return f"<div class='score-ring {score_class(score)}'>{int(score)}</div>"


def detections_to_df(detections: list[dict[str, Any]]) -> pd.DataFrame:
    if not detections:
        return pd.DataFrame(
            columns=[
                "Tool Name",
                "Category",
                "Risk",
                "Queries",
                "Unique IPs",
                "GDPR",
                "Alternative",
            ]
        )

    rows = []
    for d in detections:
        rows.append(
            {
                "Tool Name": d.get("tool_name"),
                "Category": d.get("category"),
                "Risk": d.get("risk_level"),
                "Queries": d.get("query_count"),
                "Unique IPs": d.get("unique_ips"),
                "GDPR": "⚠️" if d.get("gdpr_concern") else "",
                "Alternative": d.get("approved_alternative"),
            }
        )
    return pd.DataFrame(rows)


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def format_duration(seconds: int) -> str:
    """Convert seconds to HHh MMm SSs format."""
    safe_seconds = max(0, int(seconds or 0))
    h = safe_seconds // 3600
    m = (safe_seconds % 3600) // 60
    s = safe_seconds % 60
    return f"{h:02d}h {m:02d}m {s:02d}s"


def duration_between(start_iso: str, end_iso: str) -> tuple[int, str]:
    """Return duration in seconds and formatted text between two ISO timestamps."""
    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)
    secs = int((end - start).total_seconds())
    return secs, format_duration(secs)


def _dt_or_now(value: Any, now: datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return now
    return now


def ensure_session_clock(session_state: Any) -> None:
    now = datetime.now()
    if "app_start_time" not in session_state:
        session_state["app_start_time"] = now
        session_state["analysis_start_time"] = now
    session_state["last_activity_time"] = now
    if "page_visit_log" not in session_state:
        session_state["page_visit_log"] = []


def get_live_duration(session_state: Any) -> tuple[str, int]:
    now = datetime.now()
    start = _dt_or_now(session_state.get("app_start_time"), now)
    total_seconds = int((now - start).total_seconds())
    return format_duration(total_seconds), total_seconds


def record_page_visit(session_state: Any, page_name: str) -> None:
    ensure_session_clock(session_state)
    now = datetime.now()
    entered_key = f"entered_{page_name}"
    if entered_key not in session_state:
        session_state[entered_key] = now
    session_state["page_visit_log"].append({"page": page_name, "visited_at": now.isoformat(timespec="seconds")})


def build_user_session_payload(
    session_state: Any,
    analysis_end_time: datetime,
) -> dict[str, Any]:
    ensure_session_clock(session_state)

    app_opened = _dt_or_now(session_state.get("app_start_time"), analysis_end_time)
    analysis_started = _dt_or_now(session_state.get("analysis_start_time"), app_opened)
    app_closed_raw = session_state.get("app_end_time")
    app_closed = _dt_or_now(app_closed_raw, analysis_end_time) if app_closed_raw else None

    analysis_sec = int((analysis_end_time - analysis_started).total_seconds())
    total_sec = int(((app_closed or analysis_end_time) - app_opened).total_seconds())

    page_log = session_state.get("page_visit_log", [])
    pages = [str(item.get("page", "")).strip() for item in page_log if isinstance(item, dict)]
    pages = [p for p in pages if p]
    unique_pages = list(dict.fromkeys(pages))

    return {
        "app_opened_at": app_opened.isoformat(timespec="seconds"),
        "analysis_started_at": analysis_started.isoformat(timespec="seconds"),
        "analysis_ended_at": analysis_end_time.isoformat(timespec="seconds"),
        "app_closed_at": app_closed.isoformat(timespec="seconds") if app_closed else None,
        "total_app_duration_sec": total_sec,
        "total_app_duration_fmt": format_duration(total_sec),
        "analysis_duration_sec": analysis_sec,
        "analysis_duration_fmt": format_duration(analysis_sec),
        "pages_visited": unique_pages,
        "page_visit_log": page_log,
    }
