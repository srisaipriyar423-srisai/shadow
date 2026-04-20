from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any

import pandas as pd
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)

CSV_HEADER = ["timestamp", "source_ip", "query_domain", "query_type", "response_code"]


FORMAT_A = "Standard CSV"
FORMAT_B = "Bind/dnsmasq TXT"
FORMAT_C = "Pi-hole CSV"


def _normalize_domain(full_query: str) -> tuple[str, str]:
    full_query = (full_query or "").strip().lower().rstrip(".")
    if not full_query:
        return "", ""
    ext = _EXTRACT(full_query)
    if not ext.domain or not ext.suffix:
        return full_query, ""
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain
    return domain, subdomain


def detect_format(lines: list[str]) -> str | None:
    sample = "\n".join(lines[:10]).lower()
    if "timestamp,source_ip,query_domain" in sample:
        return FORMAT_A
    if re.search(r"dnsmasq\[\d+\]:\s+query\[[a-z]+\]\s+\S+\s+from\s+\d+\.\d+\.\d+\.\d+", sample):
        return FORMAT_B
    if re.search(r"^\d{10},[^,]+,\d+\.\d+\.\d+\.\d+,", lines[0] if lines else ""):
        return FORMAT_C
    return None


def parse_dns_log_content(content: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    detected = detect_format(lines)
    records: list[dict[str, Any]] = []
    skipped = 0

    if detected == FORMAT_A:
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            try:
                ts = pd.to_datetime(row.get("timestamp"), errors="coerce")
                ip = (row.get("source_ip") or "").strip()
                fqdn = (row.get("query_domain") or "").strip().lower()
                if pd.isna(ts) or not ip or not fqdn:
                    skipped += 1
                    continue
                domain, subdomain = _normalize_domain(fqdn)
                records.append(
                    {
                        "timestamp": ts,
                        "source_ip": ip,
                        "domain": domain,
                        "subdomain": subdomain,
                        "full_query": fqdn,
                    }
                )
            except Exception:
                skipped += 1

    elif detected == FORMAT_B:
        year = datetime.now().year
        pattern = re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*query\[[A-Z]+\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        for line in lines:
            m = pattern.search(line)
            if not m:
                skipped += 1
                continue
            try:
                ts = pd.to_datetime(
                    f"{m.group('month')} {m.group('day')} {year} {m.group('time')}",
                    format="%b %d %Y %H:%M:%S",
                    errors="coerce",
                )
                fqdn = m.group("domain").strip().lower()
                domain, subdomain = _normalize_domain(fqdn)
                if pd.isna(ts) or not domain:
                    skipped += 1
                    continue
                records.append(
                    {
                        "timestamp": ts,
                        "source_ip": m.group("ip"),
                        "domain": domain,
                        "subdomain": subdomain,
                        "full_query": fqdn,
                    }
                )
            except Exception:
                skipped += 1

    elif detected == FORMAT_C:
        for line in lines:
            parts = line.split(",")
            if len(parts) < 3:
                skipped += 1
                continue
            try:
                ts = pd.to_datetime(int(parts[0]), unit="s", errors="coerce")
                fqdn = parts[1].strip().lower()
                ip = parts[2].strip()
                domain, subdomain = _normalize_domain(fqdn)
                if pd.isna(ts) or not ip or not domain:
                    skipped += 1
                    continue
                records.append(
                    {
                        "timestamp": ts,
                        "source_ip": ip,
                        "domain": domain,
                        "subdomain": subdomain,
                        "full_query": fqdn,
                    }
                )
            except Exception:
                skipped += 1

    else:
        return (
            pd.DataFrame(columns=["timestamp", "source_ip", "domain", "subdomain", "full_query"]),
            {"format": None, "skipped": len(lines), "total_lines": len(lines)},
        )

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)

    return (
        df,
        {
            "format": detected,
            "skipped": skipped,
            "total_lines": len(lines),
            "parsed": len(records),
            "unique_domains": int(df["domain"].nunique()) if not df.empty else 0,
        },
    )


def domain_frequency(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["domain", "query_count"])
    return (
        df.groupby("domain", as_index=False)
        .size()
        .rename(columns={"size": "query_count"})
        .sort_values("query_count", ascending=False)
    )
