from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd
import streamlit as st

from utils.helpers import CATALOG_PATH, safe_json_load


@st.cache_data(show_spinner=False)
def load_catalog() -> dict[str, Any]:
    return safe_json_load(CATALOG_PATH, {"tools": []})


def _matches(query_domain: str, catalog_domain: str) -> bool:
    query_domain = (query_domain or "").lower().strip(".")
    catalog_domain = (catalog_domain or "").lower().strip(".")
    return query_domain == catalog_domain or query_domain.endswith(f".{catalog_domain}")


def _format_hms(seconds: int) -> str:
    safe_seconds = max(0, int(seconds or 0))
    hours = safe_seconds // 3600
    minutes = (safe_seconds % 3600) // 60
    secs = safe_seconds % 60
    return f"{hours:02d}h {minutes:02d}m {secs:02d}s"


def _format_active_minutes(minutes: int) -> str:
    safe_minutes = max(0, int(minutes or 0))
    h = safe_minutes // 60
    m = safe_minutes % 60
    return f"{h}h {m:02d}m"


def _duration_payload(tool_queries: pd.DataFrame) -> dict[str, Any] | None:
    if tool_queries.empty:
        return None

    first_seen = tool_queries["timestamp"].min()
    last_seen = tool_queries["timestamp"].max()
    duration_sec = int((last_seen - first_seen).total_seconds())
    minute_bucket = tool_queries["timestamp"].dt.floor("min")
    active_minutes = int(minute_bucket.nunique())
    total_queries = int(len(tool_queries))
    peak_usage_hour = int(tool_queries["timestamp"].dt.hour.mode().iloc[0]) if total_queries else 0

    return {
        "first_query_at": first_seen.isoformat(),
        "last_query_at": last_seen.isoformat(),
        "total_span_seconds": duration_sec,
        "total_span_fmt": _format_hms(duration_sec),
        "active_minutes": active_minutes,
        "active_minutes_fmt": _format_active_minutes(active_minutes),
        "total_queries": total_queries,
        "queries_per_minute": round(total_queries / max(active_minutes, 1), 2),
        "peak_usage_hour": peak_usage_hour,
    }


def match_tools(df: pd.DataFrame) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if df.empty:
        return [], [], {"ip_tool_durations": [], "tool_hourly_usage": [], "ip_hourly_usage": []}

    catalog = load_catalog().get("tools", [])
    detections: dict[str, dict[str, Any]] = {}
    domain_to_tools: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for tool in catalog:
        for d in tool.get("domains", []):
            domain_to_tools[d.lower()].append(tool)

    unknown_counter = defaultdict(int)

    for domain, group in df.groupby("domain"):
        matched_tools = []
        for c_domain, tools in domain_to_tools.items():
            if _matches(domain, c_domain):
                matched_tools.extend(tools)

        if not matched_tools:
            unknown_counter[domain] += len(group)
            continue

        for tool in matched_tools:
            tid = tool.get("id")
            if tid not in detections:
                detections[tid] = {
                    "tool_id": tid,
                    "tool_name": tool.get("name"),
                    "domain": None,
                    "category": tool.get("category"),
                    "risk_level": tool.get("risk_level"),
                    "risk_reasons": tool.get("risk_reasons", []),
                    "query_count": 0,
                    "unique_ips": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "domains_matched": set(),
                    "gdpr_concern": tool.get("gdpr_concern", False),
                    "approved_alternative": tool.get("approved_alternative", "N/A"),
                }

            d = detections[tid]
            d["query_count"] += len(group)
            d["unique_ips"] = len(
                set(df[df["domain"].isin([domain] + list(d["domains_matched"]))]["source_ip"])
            )
            d["domains_matched"].add(domain)
            g_min = group["timestamp"].min()
            g_max = group["timestamp"].max()
            d["first_seen"] = g_min if d["first_seen"] is None else min(d["first_seen"], g_min)
            d["last_seen"] = g_max if d["last_seen"] is None else max(d["last_seen"], g_max)

    output = []
    ip_tool_durations: list[dict[str, Any]] = []
    tool_hourly_usage: list[dict[str, Any]] = []
    ip_hourly_usage_counter: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

    for item in detections.values():
        domains_matched = sorted(list(item["domains_matched"]))
        item["domains_matched"] = domains_matched
        item["domain"] = domains_matched[0] if domains_matched else None
        tool_df = df[df["domain"].isin(domains_matched)].copy()
        duration = _duration_payload(tool_df)
        item["duration"] = duration

        if not tool_df.empty:
            tool_df["hour"] = tool_df["timestamp"].dt.hour
            hourly = tool_df.groupby("hour", as_index=False).size().rename(columns={"size": "query_count"})
            tool_hourly_usage.append(
                {
                    "tool_name": item.get("tool_name"),
                    "tool_id": item.get("tool_id"),
                    "hourly_queries": {str(int(r["hour"])): int(r["query_count"]) for _, r in hourly.iterrows()},
                }
            )

            for ip, ip_group in tool_df.groupby("source_ip"):
                ip_duration = _duration_payload(ip_group)
                if not ip_duration:
                    continue
                ip_tool_durations.append(
                    {
                        "ip": str(ip),
                        "tool": item.get("tool_name"),
                        "tool_id": item.get("tool_id"),
                        "category": item.get("category"),
                        "risk": item.get("risk_level"),
                        "first_query_at": ip_duration["first_query_at"],
                        "last_query_at": ip_duration["last_query_at"],
                        "total_span_seconds": ip_duration["total_span_seconds"],
                        "total_span_fmt": ip_duration["total_span_fmt"],
                        "active_minutes": ip_duration["active_minutes"],
                        "query_count": int(len(ip_group)),
                    }
                )
            for ip, ip_group in tool_df.groupby("source_ip"):
                for hour, cnt in ip_group["timestamp"].dt.hour.value_counts().items():
                    ip_hourly_usage_counter[str(ip)][int(hour)] += int(cnt)

        item["first_seen"] = item["first_seen"].isoformat() if item["first_seen"] is not None else None
        item["last_seen"] = item["last_seen"].isoformat() if item["last_seen"] is not None else None
        output.append(item)

    output = sorted(output, key=lambda x: x.get("query_count", 0), reverse=True)
    unknown_domains = [
        {"domain": d, "query_count": c}
        for d, c in sorted(unknown_counter.items(), key=lambda x: x[1], reverse=True)
    ]

    ip_hourly_usage = []
    for ip, h_map in ip_hourly_usage_counter.items():
        row = {str(h): int(h_map.get(h, 0)) for h in range(24)}
        row["ip"] = ip
        ip_hourly_usage.append(row)

    duration_payload = {
        "ip_tool_durations": sorted(ip_tool_durations, key=lambda x: x.get("total_span_seconds", 0), reverse=True),
        "tool_hourly_usage": tool_hourly_usage,
        "ip_hourly_usage": ip_hourly_usage,
    }
    return output, unknown_domains, duration_payload
