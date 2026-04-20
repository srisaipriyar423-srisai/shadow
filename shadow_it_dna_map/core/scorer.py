from __future__ import annotations

from typing import Any

from utils.helpers import RISK_RULES_PATH, safe_json_load


def _frequency_multiplier(query_count: int, rules: dict[str, Any]) -> float:
    multipliers = rules.get("frequency_multipliers", {})
    for band in multipliers.values():
        if band.get("min", 0) <= query_count <= band.get("max", 0):
            return float(band.get("multiplier", 1.0))
    return 1.0


def _duration_risk_bonus(duration_seconds: int) -> float:
    """Add risk points based on sustained usage duration of a shadow tool."""
    hours = float(duration_seconds or 0) / 3600.0
    if hours >= 8:
        return 25.0
    if hours >= 4:
        return 15.0
    if hours >= 1:
        return 8.0
    if hours >= 0.25:
        return 3.0
    return 0.0


def calculate_exposure_score(
    detections: list[dict[str, Any]],
    previous_session: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = safe_json_load(RISK_RULES_PATH, {})
    weights = rules.get("risk_weights", {"HIGH": 10, "MEDIUM": 5, "LOW": 1})
    gdpr_penalty = float(rules.get("gdpr_penalty", 3))
    max_score = float(rules.get("max_score", 100))

    raw_score = 0.0
    breakdown = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    contributors = []

    for d in detections:
        risk = str(d.get("risk_level", "LOW")).upper()
        query_count = int(d.get("query_count", 0))
        mult = _frequency_multiplier(query_count, rules)
        base = float(weights.get(risk, 1))
        gdpr_factor = gdpr_penalty if d.get("gdpr_concern") else 1.0
        duration_seconds = int(((d.get("duration") or {}).get("total_span_seconds", 0)) or 0)
        duration_bonus = _duration_risk_bonus(duration_seconds)
        contribution = (base * mult * gdpr_factor) + duration_bonus
        raw_score += contribution
        breakdown[risk] = breakdown.get(risk, 0) + 1
        contributors.append(
            {
                "tool_name": d.get("tool_name"),
                "score": contribution,
                "risk": risk,
                "duration_bonus": duration_bonus,
            }
        )

    normalisation_factor = max(
        1.0,
        len(detections) * (float(weights.get("HIGH", 10)) * 2.0 * gdpr_penalty + 25.0),
    )
    score = min(max_score, round((raw_score / normalisation_factor) * 100, 2))

    band_name = "low"
    for key, band in rules.get("score_bands", {}).items():
        if band.get("min", 0) <= score <= band.get("max", 100):
            band_name = key
            break

    trend = None
    if previous_session is not None:
        prev = float(previous_session.get("exposure_score", 0))
        trend = {
            "previous": prev,
            "delta": round(score - prev, 2),
            "direction": "up" if score > prev else "down" if score < prev else "flat",
        }

    top3 = sorted(contributors, key=lambda x: x["score"], reverse=True)[:3]

    return {
        "score": score,
        "raw_score": round(raw_score, 2),
        "band": band_name,
        "breakdown": breakdown,
        "top_contributors": top3,
        "trend": trend,
    }
