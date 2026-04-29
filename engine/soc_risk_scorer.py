"""
Spec-aligned Risk Scoring on Alerts.

The legacy `engine.risk_engine` is a stateful per-host profile with
decay, kill-chain bonuses, etc. — keep using it for the rich dashboard.
This module is the *minimal* spec implementation:

    Low      = +5
    Medium   = +15
    High     = +30
    Critical = +50

It adds severity scores per alert, optionally clamped to 0..100, and
returns a `(risk_score, risk_level)` tuple. Pure function, no state,
trivially testable.

Risk level thresholds (CrowdStrike-ish):

    0-29     LOW
    30-59    MEDIUM
    60-79    HIGH
    80-100   CRITICAL
"""

from __future__ import annotations

from typing import Iterable

from storage.repository import Alert

# Per-spec increments.
SEV_INCREMENTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

# Thresholds → human level.
LEVEL_BANDS = (
    ("LOW",       0,  29),
    ("MEDIUM",    30, 59),
    ("HIGH",      60, 79),
    ("CRITICAL",  80, 100),
)


def severity_increment(severity: str) -> int:
    if not severity:
        return 0
    return SEV_INCREMENTS.get(severity.lower().strip(), 0)


def level_for(score: int) -> str:
    s = max(0, min(100, int(score)))
    for level, lo, hi in LEVEL_BANDS:
        if lo <= s <= hi:
            return level
    return "LOW"


def score_alerts(
    alerts: Iterable[Alert | dict],
    *,
    base_score: int = 0,
    cap: int = 100,
) -> tuple[int, str]:
    """
    Sum severity increments and clamp to `cap`. Returns (score, level).

    Accepts either Alert objects or plain dicts (severity field used).
    """
    score = max(0, int(base_score))
    for a in alerts:
        sev = a.severity if isinstance(a, Alert) else (a.get("severity") if isinstance(a, dict) else "")
        score += severity_increment(sev or "")
    score = min(int(cap), score)
    return score, level_for(score)


def aggregate_per_host(alerts: Iterable[Alert]) -> dict[str, dict]:
    """
    Group alerts by host and return per-host risk:
        { host_id: { "risk_score": int, "risk_level": str, "alert_count": int } }
    """
    by_host: dict[str, list[Alert]] = {}
    for a in alerts:
        if not a.host_id:
            continue
        by_host.setdefault(a.host_id, []).append(a)
    out: dict[str, dict] = {}
    for host, host_alerts in by_host.items():
        score, level = score_alerts(host_alerts)
        out[host] = {
            "risk_score": score,
            "risk_level": level,
            "alert_count": len(host_alerts),
        }
    return out
