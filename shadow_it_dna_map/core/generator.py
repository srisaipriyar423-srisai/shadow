from __future__ import annotations

import random
from datetime import datetime, timedelta

import pandas as pd
from faker import Faker

NORMAL_DOMAINS = [
    "google.com",
    "microsoft.com",
    "windows.com",
    "office.com",
    "windowsupdate.com",
    "live.com",
    "outlook.com",
    "bing.com",
    "azure.com",
    "cloudflare.com",
    "amazonaws.com",
    "akamai.com",
    "fastly.net",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "github.com",
]


fake = Faker()


def generate_tool_usage_pattern(
    tool: dict,
    num_queries: int,
    base_date: datetime,
    persona: str,
) -> list[datetime]:
    """Generate realistic query timestamps per persona for a tool on a specific day."""
    timestamps: list[datetime] = []

    if persona == "office_worker":
        start_hour, end_hour = 9, 18
    elif persona == "night_owl":
        start_hour, end_hour = 20, 26
    elif persona == "burst_user":
        burst_start = random.randint(8, 16)
        start_hour, end_hour = burst_start, burst_start + 2
    else:
        start_hour, end_hour = 0, 24

    for _ in range(max(1, num_queries)):
        hour = random.randint(start_hour, end_hour - 1) % 24
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        timestamps.append(base_date.replace(hour=hour, minute=minute, second=second))

    return sorted(timestamps)


def _random_time(start: datetime, end: datetime) -> datetime:
    delta_seconds = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, max(1, delta_seconds)))


def generate_synthetic_dns_logs(
    catalog_tools: list[dict],
    n_lines: int = 10000,
    risky_employees: int = 5,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> pd.DataFrame:
    start_date = start_date or (datetime.now() - timedelta(days=7))
    end_date = end_date or datetime.now()

    records = []
    risky_ips = [fake.ipv4_private() for _ in range(max(1, risky_employees))]
    personas = ["office_worker", "night_owl", "all_day", "burst_user"]
    risky_persona = {ip: random.choice(personas) for ip in risky_ips}
    shadow_tools = random.sample(catalog_tools, k=min(len(catalog_tools), random.randint(5, 8)))

    day_count = max(1, (end_date.date() - start_date.date()).days + 1)
    day_list = [start_date + timedelta(days=i) for i in range(day_count)]

    # Pre-generate realistic shadow usage blocks to create meaningful duration spans.
    shadow_target = int(n_lines * 0.25)
    shadow_records: list[dict[str, str]] = []
    if shadow_tools:
        per_tool = max(1, shadow_target // len(shadow_tools))
        for tool in shadow_tools:
            for _ in range(per_tool):
                base_day = random.choice(day_list)
                ip = random.choice(risky_ips)
                persona = risky_persona.get(ip, "office_worker")
                ts = generate_tool_usage_pattern(tool, 1, base_day, persona)[0]
                shadow_records.append(
                    {
                        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                        "source_ip": ip,
                        "query_domain": random.choice(tool.get("domains", ["example.com"])),
                        "query_type": "A",
                        "response_code": "NOERROR",
                    }
                )

    for _ in range(max(0, n_lines - len(shadow_records))):
        ts = _random_time(start_date, end_date)
        roll = random.random()

        if roll <= 0.60:
            domain = random.choice(NORMAL_DOMAINS)
            ip = fake.ipv4_private()
        elif roll <= 0.85 and shadow_tools:
            tool = random.choice(shadow_tools)
            domain = random.choice(tool.get("domains", ["example.com"]))
            ip = random.choice(risky_ips)
            ts = generate_tool_usage_pattern(tool, 1, ts, risky_persona.get(ip, "office_worker"))[0]
        else:
            # Unknown domains are intentionally generated to simulate undiscovered SaaS usage.
            domain = f"{fake.word()}{random.randint(1,999)}.{random.choice(['io', 'app', 'cloud', 'tech'])}"
            ip = fake.ipv4_private()

        records.append(
            {
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ip,
                "query_domain": domain,
                "query_type": "A",
                "response_code": "NOERROR",
            }
        )

    records.extend(shadow_records)

    if records:
        random.shuffle(records)

    return pd.DataFrame(records)


def synthetic_csv_text(df: pd.DataFrame) -> str:
    return df.to_csv(index=False)
