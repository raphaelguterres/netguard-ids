"""
NetGuard — Exemplo de uso do Event Engine
Demonstra:
  1. Como escrever regras compatíveis
  2. Como registrar no engine
  3. Como processar eventos
  4. Como consumir os resultados

Cole este arquivo em: examples/engine_usage.py
(ou leia como referência)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.event_engine   import EventEngine, normalize_event, validate_event, enrich_event
from engine.rule_executor  import make_alert, Alert, RuleRegistry  # noqa: F401
from engine.severity_classifier import classify_severity
from engine.baseline_engine     import BaselineEngine, BaselineType  # noqa: F401
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# PARTE 1 — COMO ESCREVER UMA REGRA COMPATÍVEL
# ═══════════════════════════════════════════════════════════════════
#
# Uma regra é uma função com assinatura:
#   def rule_name(event: dict) -> Optional[Alert | list[Alert]]
#
# Retorna:
#   - None           → sem alerta (evento normal)
#   - Alert          → um alerta gerado
#   - list[Alert]    → múltiplos alertas
#
# Use make_alert() para criar alertas padronizados.


def rule_unknown_process(event: dict) -> Optional[Alert]:
    """R1 — Processo desconhecido (nunca visto no baseline)."""
    if event.get("event_type") != "process_unknown":
        return None
    details = event.get("details", {})
    proc    = details.get("process_name") or details.get("process", "")
    if not proc:
        return None
    return make_alert(
        rule_name   = "Processo Desconhecido",
        event_type  = "process_unknown",
        severity    = "MEDIUM",
        description = f"Processo '{proc}' nunca visto no baseline do host",
        details     = details,
        rule_id     = "R1",
        tactic      = "execution",
        technique   = "T1204",
        tags        = ["process", "baseline"],
    )


def rule_high_cpu(event: dict) -> Optional[Alert]:
    """R2 — Processo com CPU muito alta por período contínuo."""
    if event.get("event_type") not in ("process_high_cpu", "process_anomaly"):
        return None
    details = event.get("details", {})
    cpu     = float(details.get("cpu_usage") or details.get("cpu") or 0)
    proc    = details.get("process_name") or details.get("process", "unknown")

    if cpu <= 80:
        return None

    severity = "CRITICAL" if cpu >= 95 else "HIGH"
    return make_alert(
        rule_name   = "CPU Alta — Processo Suspeito",
        event_type  = "process_high_cpu",
        severity    = severity,
        description = f"Processo '{proc}' usando {cpu}% de CPU",
        details     = {**details, "cpu_threshold": 80},
        rule_id     = "R2",
        tactic      = "execution",
        technique   = "T1496",
        tags        = ["process", "performance"],
    )


def rule_port_unusual(event: dict) -> Optional[Alert]:
    """R3 — Processo abrindo porta fora do baseline."""
    if event.get("event_type") not in ("port_opened", "port_new_listen"):
        return None
    details = event.get("details", {})
    port    = details.get("port")
    proc    = details.get("process", "unknown")
    is_new  = details.get("is_new_port", True)  # flag do enrich step

    if not port or not is_new:
        return None

    return make_alert(
        rule_name   = "Processo Abrindo Porta Incomum",
        event_type  = "port_opened",
        severity    = "HIGH",
        description = f"Processo '{proc}' abriu porta incomum {port}",
        details     = details,
        rule_id     = "R3",
        tactic      = "persistence",
        technique   = "T1205",
        tags        = ["network", "port"],
    )


def rule_network_spike(event: dict) -> Optional[Alert]:
    """R4 — Muitas conexões em curto período."""
    if event.get("event_type") != "network_spike":
        return None
    details = event.get("details", {})
    count   = int(details.get("conn_count") or details.get("count") or 0)
    if count < 50:
        return None
    return make_alert(
        rule_name   = "Spike de Conexões",
        event_type  = "network_spike",
        severity    = "HIGH",
        description = f"{count} conexões em curto período — possível scan ou beaconing",
        details     = details,
        rule_id     = "R4",
        tactic      = "reconnaissance",
        technique   = "T1046",
        tags        = ["network", "spike"],
    )


def rule_multi_ip(event: dict) -> Optional[Alert]:
    """R5 — Processo conectando em muitos IPs diferentes."""
    if event.get("event_type") != "network_scan":
        return None
    details    = event.get("details", {})
    unique_ips = int(details.get("unique_ips") or 0)
    proc       = details.get("process", "unknown")
    if unique_ips < 20:
        return None
    return make_alert(
        rule_name   = "Múltiplos IPs — Comportamento de Bot/Worm",
        event_type  = "network_scan",
        severity    = "HIGH",
        description = f"Processo '{proc}' contatou {unique_ips} IPs únicos em pouco tempo",
        details     = details,
        rule_id     = "R5",
        tactic      = "discovery",
        technique   = "T1046",
        tags        = ["network", "scan", "worm"],
    )


def rule_proc_external(event: dict) -> Optional[Alert]:
    """R6 — Processo fora do baseline fazendo conexão externa."""
    if event.get("event_type") != "process_external_conn":
        return None
    details = event.get("details", {})
    proc    = details.get("process", "unknown")
    return make_alert(
        rule_name   = "Processo Desconhecido com Conexão Externa",
        event_type  = "process_external_conn",
        severity    = "MEDIUM",
        description = f"Processo '{proc}' fora do baseline iniciou tráfego externo",
        details     = details,
        rule_id     = "R6",
        tactic      = "command_and_control",
        technique   = "T1071",
        tags        = ["process", "network"],
    )


def rule_new_listen_port(event: dict) -> Optional[Alert]:
    """R7 — Nova porta em LISTEN."""
    if event.get("event_type") != "port_new_listen":
        return None
    details = event.get("details", {})
    return make_alert(
        rule_name   = "Nova Porta em LISTEN",
        event_type  = "port_new_listen",
        severity    = "MEDIUM",
        description = f"Porta {details.get('port')} ({details.get('proto','tcp')}) em LISTEN pela primeira vez",
        details     = details,
        rule_id     = "R7",
        tactic      = "persistence",
        technique   = "T1205",
        tags        = ["network", "listen"],
    )


def rule_new_external_ip(event: dict) -> Optional[Alert]:
    """R8 — Novo IP externo nunca visto."""
    if event.get("event_type") != "ip_new_external":
        return None
    details = event.get("details", {})
    ip      = details.get("ip", "")
    is_new  = details.get("is_new_ip", True)
    if not is_new:
        return None
    return make_alert(
        rule_name   = "Novo IP Externo",
        event_type  = "ip_new_external",
        severity    = "LOW",
        description = f"Conexão para IP externo {ip} nunca visto antes",
        details     = details,
        rule_id     = "R8",
        tactic      = "reconnaissance",
        technique   = "T1590",
        tags        = ["network", "ip", "baseline"],
    )


def rule_sqli(event: dict) -> Optional[Alert]:
    """R10 — SQL Injection detectado no payload."""
    if event.get("event_type") not in ("web_sqli", "web_attack_detected"):
        return None
    details = event.get("details", {})
    return make_alert(
        rule_name   = "SQL Injection Detectado",
        event_type  = "web_sqli",
        severity    = "HIGH",
        description = f"Padrão SQLi detectado: {details.get('match', '')[:60]}",
        details     = details,
        rule_id     = "R10",
        tactic      = "initial_access",
        technique   = "T1190",
        tags        = ["web", "sqli", "injection"],
    )


def rule_xss(event: dict) -> Optional[Alert]:
    """R11 — XSS detectado no payload."""
    if event.get("event_type") not in ("web_xss", "web_attack_detected"):
        return None
    details = event.get("details", {})
    if details.get("attack_type") not in (None, "xss") and "xss" not in str(details.get("match","")).lower():
        return None
    return make_alert(
        rule_name   = "XSS Detectado",
        event_type  = "web_xss",
        severity    = "HIGH",
        description = f"Padrão XSS detectado: {details.get('match','')[:60]}",
        details     = details,
        rule_id     = "R11",
        tactic      = "initial_access",
        technique   = "T1190",
        tags        = ["web", "xss"],
    )


def rule_suspicious_ua(event: dict) -> Optional[Alert]:
    """R12 — User-Agent suspeito."""
    if event.get("event_type") != "web_suspicious_ua":
        return None
    details = event.get("details", {})
    return make_alert(
        rule_name   = "User-Agent Suspeito",
        event_type  = "web_suspicious_ua",
        severity    = "MEDIUM",
        description = f"UA suspeito detectado: {details.get('matched', '')}",
        details     = details,
        rule_id     = "R12",
        tactic      = "reconnaissance",
        technique   = "T1595",
        tags        = ["web", "scanner", "ua"],
    )


# ═══════════════════════════════════════════════════════════════════
# PARTE 2 — COMO MONTAR E USAR O ENGINE
# ═══════════════════════════════════════════════════════════════════

def build_engine(alert_callback=None) -> EventEngine:
    """
    Factory para criar e configurar o EventEngine com todas as regras.
    Pronto para integrar no app.py.
    """
    engine = EventEngine(
        host_id        = "netguard-host",
        alert_callback = alert_callback,
    )

    # Registra todas as regras com IDs e tags
    (engine.registry
        .register(rule_unknown_process,  tags=["process"])
        .register(rule_high_cpu,         tags=["process", "performance"])
        .register(rule_port_unusual,     tags=["network"])
        .register(rule_network_spike,    tags=["network"])
        .register(rule_multi_ip,         tags=["network"])
        .register(rule_proc_external,    tags=["process", "network"])
        .register(rule_new_listen_port,  tags=["network"])
        .register(rule_new_external_ip,  tags=["network"])
        .register(rule_sqli,             tags=["web"])
        .register(rule_xss,              tags=["web"])
        .register(rule_suspicious_ua,    tags=["web"])
    )

    return engine


# ═══════════════════════════════════════════════════════════════════
# PARTE 3 — DEMO COMPLETA
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json  # noqa: F401

    print("=" * 60)
    print("NetGuard Event Engine — Demo")
    print("=" * 60)

    # Callback para alertas HIGH/CRITICAL
    def on_alert(alert: dict):
        print(f"\n🚨 ALERTA [{alert['severity']}] {alert['rule_name']}")
        print(f"   {alert['description']}")

    # Monta engine com todas as regras
    engine = build_engine(alert_callback=on_alert)
    print(f"\nEngine pronto | {engine.registry.active_count} regras ativas\n")

    # ── Eventos de teste ─────────────────────────────────────────
    test_events = [
        # Evento 1: processo desconhecido
        {
            "event_type": "process_unknown",
            "source":     "agent.process",
            "details":    {"process_name": "ransomware.exe", "pid": 1337},
        },
        # Evento 2: CPU alta
        {
            "event_type": "process_anomaly",
            "source":     "process",  # será normalizado
            "severity":   "high",     # será normalizado para HIGH
            "details":    {"process_name": "miner.exe", "cpu_usage": 97, "pid": 666},
        },
        # Evento 3: SQL Injection
        {
            "event_type": "web_sqli",
            "source":     "agent.web",
            "host_id":    "webserver-01",
            "details":    {
                "match":     "1=1",
                "source_ip": "185.220.101.45",
                "payload":   "GET /api?id=1' UNION SELECT username,password FROM users--",
            },
        },
        # Evento 4: evento inválido (sem event_type)
        {
            "source":  "agent.process",
            "details": {"process": "ok.exe"},
        },
        # Evento 5: novo IP externo
        {
            "event_type": "ip_new_external",
            "source":     "agent.network",
            "details":    {"ip": "91.108.56.22", "process": "brave.exe"},
        },
        # Evento 6: User-agent suspeito
        {
            "event_type": "web_suspicious_ua",
            "source":     "agent.web",
            "details":    {
                "user_agent": "sqlmap/1.7 (https://sqlmap.org)",
                "matched":    "sqlmap",
                "source_ip":  "45.152.84.57",
            },
        },
    ]

    print("-" * 60)
    for i, raw in enumerate(test_events, 1):
        print(f"\nEvento {i}: {raw.get('event_type', '(sem tipo)')}")
        result = engine.process(raw)

        if not result.valid:
            print(f"  ⚠ Validação: {result.errors}")

        if result.alerts:
            for a in result.alerts:
                print(f"  ✓ [{a['severity']:8}] {a['rule_name']}")
                print(f"    MITRE: {a['mitre']['tactic']} / {a['mitre']['technique']}")
        else:
            print("  — Sem alertas")

    print("\n" + "=" * 60)
    stats = engine.stats()
    print("Stats do Engine:")
    for k, v in stats.items():
        print(f"  {k:20}: {v}")

    # ── Uso individual das funções do pipeline ────────────────────
    print("\n" + "=" * 60)
    print("Funções do pipeline individualmente:")

    raw = {"event_type": "PROCESS_ANOMALY", "source": "process",
           "details": {"process_name": "test.exe", "cpu_usage": 85}}

    norm = normalize_event(raw)
    print(f"\n1. normalize_event:")
    print(f"   event_type: {norm['event_type']}  (normalizado)")
    print(f"   severity:   {norm['severity']}      (será classificado)")
    print(f"   host_id:    {norm['host_id']}")

    valid, errs = validate_event(norm)
    print(f"\n2. validate_event: valid={valid} errors={errs}")

    enriched = enrich_event(norm)
    print(f"\n3. enrich_event:")
    print(f"   severity: {enriched['severity']}  (classificado)")
    print(f"   tags:     {enriched['tags']}")

    sev = classify_severity(event_type="web_sqli", rule_name="SQL Injection")
    print(f"\n4. classify_severity('web_sqli'): {sev}")

    print("\nDone!")
