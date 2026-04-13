"""Severity and risk helpers for the XDR pipeline."""

SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 35,
    "critical": 60,
}


def normalize_severity(value: str | None, default: str = "low") -> str:
    if not value:
        return default
    normalized = str(value).strip().lower()
    return normalized if normalized in SEVERITY_ORDER else default


def max_severity(*values: str) -> str:
    candidates = [normalize_severity(v) for v in values if v]
    if not candidates:
        return "low"
    return max(candidates, key=lambda item: SEVERITY_ORDER[item])


def severity_weight(value: str | None) -> int:
    return SEVERITY_WEIGHTS[normalize_severity(value)]


def clamp_risk(score: int) -> int:
    return max(0, min(100, int(score)))


def risk_level(score: int) -> str:
    score = clamp_risk(score)
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
