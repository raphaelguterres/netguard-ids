"""
NetGuard — Severity Classifier
Classifica severidade de eventos e alertas de forma determinística.
Extensível via regras de mapeamento sem alterar lógica central.
"""

from typing import Optional


# ── Mapeamento por event_type ────────────────────────────────────
EVENT_TYPE_SEVERITY: dict[str, str] = {
    # Critical
    "ransomware_detected":       "CRITICAL",
    "malware_c2":                "CRITICAL",
    "credential_dump":           "CRITICAL",
    "shadow_copy_deletion":      "CRITICAL",
    "lateral_movement":          "CRITICAL",

    # High
    "web_sqli":                  "HIGH",
    "web_xss":                   "HIGH",
    "web_rce":                   "HIGH",
    "process_high_cpu":          "HIGH",
    "port_opened":               "HIGH",
    "network_spike":             "HIGH",
    "network_scan":              "HIGH",
    "process_external_conn":     "HIGH",
    "brute_force":               "HIGH",
    "privilege_escalation":      "HIGH",
    "defense_evasion":           "HIGH",

    # Medium
    "process_unknown":           "MEDIUM",
    "process_anomaly":           "MEDIUM",
    "port_new_listen":           "MEDIUM",
    "behavior_deviation":        "MEDIUM",
    "web_suspicious_ua":         "MEDIUM",
    "connection_outbound":       "MEDIUM",
    "process_started":           "MEDIUM",

    # Low
    "ip_new_external":           "LOW",
    "behavior_baseline":         "LOW",
    "port_scan_probe":           "LOW",
    "system_alert":              "LOW",
}

# ── Mapeamento por palavras-chave no rule_name ────────────────────
RULE_NAME_KEYWORDS: list[tuple[str, str]] = [
    # Critical
    ("ransomware",          "CRITICAL"),
    ("cobalt strike",       "CRITICAL"),
    ("mimikatz",            "CRITICAL"),
    ("lsass",               "CRITICAL"),
    # High
    ("sql injection",       "HIGH"),
    ("sqli",                "HIGH"),
    ("xss",                 "HIGH"),
    ("brute force",         "HIGH"),
    ("cpu alta",            "HIGH"),
    ("high cpu",            "HIGH"),
    ("port scan",           "HIGH"),
    ("spike",               "HIGH"),
    ("rce",                 "HIGH"),
    ("injection",           "HIGH"),
    # Medium
    ("desconhecido",        "MEDIUM"),
    ("unknown",             "MEDIUM"),
    ("anomaly",             "MEDIUM"),
    ("anomalia",            "MEDIUM"),
    ("suspeito",            "MEDIUM"),
    ("suspicious",         "MEDIUM"),
    ("deviation",           "MEDIUM"),
    ("desvio",              "MEDIUM"),
    ("listen",              "MEDIUM"),
    # Low
    ("novo ip",             "LOW"),
    ("new ip",              "LOW"),
    ("new external",        "LOW"),
    ("baseline",            "LOW"),
]

# ── Mapeamento por conteúdo do details ───────────────────────────
DETAILS_SEVERITY_HINTS: list[tuple[str, float, str]] = [
    # (campo, threshold, severity se >= threshold)
    ("cpu_usage",    90.0, "CRITICAL"),
    ("cpu_usage",    80.0, "HIGH"),
    ("cpu_usage",    60.0, "MEDIUM"),
    ("conn_count",   100,  "CRITICAL"),
    ("conn_count",   50,   "HIGH"),
    ("unique_ips",   30,   "CRITICAL"),
    ("unique_ips",   20,   "HIGH"),
]

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def classify_severity(
    event_type: str = "",
    rule_name:  str = "",
    details:    dict | None = None,
    current:    str = "",
) -> str:
    """
    Classifica a severidade de um evento/alerta.
    Retorna a severidade mais alta encontrada entre:
    - severidade atual (se já definida e válida)
    - mapeamento por event_type
    - mapeamento por palavras-chave no rule_name
    - hints extraídos dos details

    Fallback: LOW
    """
    candidates: list[str] = []

    # 1. Usa severidade atual se válida
    if current and current.upper() in SEV_ORDER:
        candidates.append(current.upper())

    # 2. Mapeamento por event_type
    et = event_type.lower().strip()
    if et in EVENT_TYPE_SEVERITY:
        candidates.append(EVENT_TYPE_SEVERITY[et])

    # 3. Mapeamento por rule_name keywords
    rn = rule_name.lower().strip()
    for keyword, sev in RULE_NAME_KEYWORDS:
        if keyword in rn:
            candidates.append(sev)
            break  # usa o primeiro match

    # 4. Hints dos details
    if details and isinstance(details, dict):
        for field, threshold, sev in DETAILS_SEVERITY_HINTS:
            val = details.get(field)
            if val is not None:
                try:
                    if float(val) >= threshold:
                        candidates.append(sev)
                        break
                except (TypeError, ValueError):
                    pass

    if not candidates:
        return "LOW"

    # Retorna a mais alta
    return max(candidates, key=lambda s: SEV_ORDER.get(s, 0))


def severity_score(severity: str) -> int:
    """Converte severidade em score numérico para comparação."""
    return SEV_ORDER.get(severity.upper(), 0)


def is_high_priority(severity: str) -> bool:
    """Retorna True para HIGH e CRITICAL."""
    return severity_score(severity) >= SEV_ORDER["HIGH"]
