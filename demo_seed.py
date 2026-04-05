"""
NetGuard IDS — Seed de dados de demonstração
Popula um tenant de demo com 30 dias de eventos realistas.

Uso:
    python demo_seed.py                  # cria/recria tenant demo
    python demo_seed.py --clear          # limpa apenas o tenant demo

O tenant demo usa token fixo: ng_DEMO00000000000000000000000000
"""

from __future__ import annotations

import os
import uuid
import random
import argparse
from datetime import datetime, timezone, timedelta

# ── Config ────────────────────────────────────────────────────────
DEMO_TENANT_ID = "demo-tenant-netguard"
DEMO_TOKEN     = "ng_DEMO00000000000000000000000000"
DEMO_NAME      = "Empresa Demo — NetGuard IDS"
DEMO_PLAN      = "pro"

# ── Dados realistas ───────────────────────────────────────────────
THREAT_SCENARIOS = [
    # (event_type, threat_name, severity, message_template)
    ("web_sqli",       "SQL Injection",             "HIGH",
     "SQLi detectado em {path} — payload: {payload}"),
    ("web_xss",        "Cross-Site Scripting (XSS)", "MEDIUM",
     "XSS tentativa em {path} — parâmetro: {param}"),
    ("brute_force",    "Brute Force SSH",            "HIGH",
     "Múltiplas tentativas de login SSH de {ip} — {count} em 60s"),
    ("brute_force",    "Brute Force HTTP",           "MEDIUM",
     "Força bruta em /login de {ip} — {count} tentativas"),
    ("port_scan",      "Port Scan",                  "MEDIUM",
     "Varredura de portas detectada de {ip} — {count} portas em 10s"),
    ("recon",          "Network Reconnaissance",     "LOW",
     "Reconhecimento de rede de {ip} — ICMP sweep"),
    ("malware",        "Malware Communication",      "CRITICAL",
     "Comunicação com C2 conhecido: {ip}:{port} — hash: {hash}"),
    ("data_exfil",     "Possível Exfiltração",       "CRITICAL",
     "Volume anormal de dados saindo para {ip} — {size}MB em 5min"),
    ("lateral_move",   "Movimento Lateral",          "HIGH",
     "Acesso incomum entre hosts internos: {src} → {dst}"),
    ("privesc",        "Escalada de Privilégio",     "CRITICAL",
     "Tentativa de sudo/runas em {host} por usuário {user}"),
    ("ransomware",     "Atividade de Ransomware",    "CRITICAL",
     "Criação massiva de arquivos criptografados em {host}"),
    ("dns_tunneling",  "DNS Tunneling",              "HIGH",
     "Consultas DNS suspeitas de {host} → {domain} (volume: {count}/min)"),
    ("web_scanner",    "Web Scanner Detectado",      "LOW",
     "Scanner automatizado de {ip} — User-Agent: {ua}"),
    ("failed_login",   "Login Inválido",             "LOW",
     "Credenciais inválidas para usuário {user} de {ip}"),
    ("geo_anomaly",    "Acesso de Localização Incomum", "MEDIUM",
     "Login de país incomum: {country} para conta {user}"),
    ("policy_viola",   "Violação de Política",       "LOW",
     "Acesso a recurso bloqueado: {resource} por {user}"),
    ("open_redirect",  "Open Redirect",              "MEDIUM",
     "Tentativa de redirecionamento malicioso em {path}"),
    ("rce_attempt",    "Remote Code Execution",      "CRITICAL",
     "Tentativa de RCE via {path} — payload: {payload}"),
    ("path_traversal", "Path Traversal",             "HIGH",
     "Tentativa de leitura de {path} via directory traversal"),
    ("dos_attempt",    "DoS/DDoS Attempt",           "HIGH",
     "Volume anormal de requisições de {ip} — {count} req/s"),
]

ATTACKING_IPS = [
    "185.220.101.47", "45.142.212.100", "194.165.16.11",
    "91.240.118.172", "198.235.24.156", "103.75.190.12",
    "62.210.115.87",  "5.188.206.14",   "185.156.73.54",
    "141.98.81.227",  "79.137.206.57",  "45.227.254.8",
    "176.111.174.26", "104.248.47.122", "167.99.200.45",
]

INTERNAL_HOSTS = [
    "srv-web-01", "srv-db-01", "srv-mail-01",
    "wks-admin",  "wks-finance", "wks-dev-01",
    "firewall-01","lb-prod-01",
]

WEB_PATHS = [
    "/admin/login", "/wp-login.php", "/api/users",
    "/phpmyadmin",  "/login",        "/checkout",
    "/.env",        "/config.php",   "/api/v1/auth",
]

PAYLOADS = [
    "' OR 1=1 --", "UNION SELECT * FROM users",
    "<script>alert(1)</script>", "../../../etc/passwd",
    "; ls -la", "$(whoami)", "%00bypass",
]

USERS = ["admin", "root", "administrator", "sa", "user1", "backup"]
COUNTRIES = ["Rússia", "China", "Coreia do Norte", "Irã", "Brasil", "EUA"]
DOMAINS = ["c2.evil.ru", "exfil.xyz", "beacon.malware.io", "update.fake-cdn.com"]
USER_AGENTS = [
    "sqlmap/1.7", "Nikto/2.1.6", "Nmap Scripting Engine",
    "masscan/1.3", "python-requests/2.28",
]


def _rand_ts(days_ago_max: int = 30, days_ago_min: int = 0) -> str:
    """Gera timestamp aleatório nos últimos N dias."""
    now    = datetime.now(timezone.utc)
    delta  = timedelta(
        days=random.uniform(days_ago_min, days_ago_max),
        hours=random.uniform(0, 23),
        minutes=random.uniform(0, 59),
    )
    return (now - delta).isoformat()


def _build_event(scenario: tuple, tenant_id: str) -> dict:
    etype, tname, sev, msg_tpl = scenario
    ip   = random.choice(ATTACKING_IPS)
    host = random.choice(INTERNAL_HOSTS)
    msg  = msg_tpl.format(
        path    = random.choice(WEB_PATHS),
        payload = random.choice(PAYLOADS),
        param   = random.choice(["q", "id", "search", "username"]),
        ip      = ip,
        count   = random.randint(10, 500),
        port    = random.choice([4444, 8080, 1337, 443, 9001]),
        hash    = uuid.uuid4().hex[:16],
        size    = round(random.uniform(0.5, 500), 1),
        src     = random.choice(INTERNAL_HOSTS),
        dst     = random.choice(INTERNAL_HOSTS),
        host    = host,
        user    = random.choice(USERS),
        domain  = random.choice(DOMAINS),
        country = random.choice(COUNTRIES),
        resource= random.choice(["/admin", "/backup", "/secret", "/config"]),
        ua      = random.choice(USER_AGENTS),
    )
    return {
        "event_id":    str(uuid.uuid4()),
        "tenant_id":   tenant_id,
        "timestamp":   _rand_ts(),
        "event_type":  etype,
        "threat_name": tname,
        "severity":    sev,
        "source_ip":   ip,
        "host_id":     host,
        "message":     msg,
        "rule_id":     f"NG-{random.randint(1000, 9999)}",
        "acknowledged": False,
        "details":     {"auto_generated": True, "demo": True},
    }


def _weight_scenario(scenario: tuple) -> float:
    """Eventos críticos são mais raros — mais realista."""
    sev = scenario[2]
    return {"CRITICAL": 0.05, "HIGH": 0.20, "MEDIUM": 0.40, "LOW": 0.35}.get(sev, 0.20)


def seed_demo(repo, n_events: int = 350, verbose: bool = True) -> dict:
    """
    Cria o tenant de demo e insere N eventos realistas.
    Retorna dict com tenant_id e token.
    """
    # Cria ou garante que o tenant existe
    try:
        existing = repo.get_tenant_by_token(DEMO_TOKEN)
        if not existing:
            repo.create_tenant(
                tenant_id = DEMO_TENANT_ID,
                name      = DEMO_NAME,
                token     = DEMO_TOKEN,
                plan      = DEMO_PLAN,
                max_hosts = 50,
            )
            if verbose:
                print(f"[demo] Tenant criado: {DEMO_TENANT_ID}")
        else:
            if verbose:
                print(f"[demo] Tenant já existe: {DEMO_TENANT_ID}")
    except Exception as e:
        if verbose:
            print(f"[demo] Aviso ao criar tenant: {e}")

    # Pesos para distribuição realista
    scenarios = THREAT_SCENARIOS
    weights   = [_weight_scenario(s) for s in scenarios]

    # Gera eventos com distribuição realista
    # Usa _save_raw diretamente — o schema real não tem colunas threat_name/source_ip/message
    events_saved = 0
    for _ in range(n_events):
        scenario = random.choices(scenarios, weights=weights, k=1)[0]
        event    = _build_event(scenario, DEMO_TENANT_ID)
        try:
            _save_raw(repo, event)
            events_saved += 1
        except Exception as e:
            if verbose:
                print(f"[demo] Erro ao salvar evento: {e}")

    if verbose:
        print(f"[demo] {events_saved} eventos inseridos para tenant {DEMO_TENANT_ID}")

    return {
        "tenant_id": DEMO_TENANT_ID,
        "token":     DEMO_TOKEN,
        "events":    events_saved,
    }


def _save_raw(repo, ev: dict) -> None:
    """
    Insere evento diretamente via SQL — mapeado para o schema real de events.

    Mapeamento de campos do seed → colunas do schema:
        source_ip   → source     (IP de origem)
        threat_name → rule_name  (nome legível da ameaça)
        message     → raw        (mensagem formatada)
        details     → details    (JSON com metadados extras)
    """
    import json
    ph = repo._placeholder()
    details_json = json.dumps({
        "threat_name": ev.get("threat_name", ""),
        "message":     ev.get("message", ""),
        "demo":        True,
        **ev.get("details", {}),
    })
    sql_sqlite = (
        f"INSERT OR IGNORE INTO events"
        f" (event_id, tenant_id, timestamp, host_id, event_type, severity,"
        f"  source, rule_id, rule_name, raw, details, acknowledged)"
        f" VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})"
    )
    sql_pg = (
        f"INSERT INTO events"
        f" (event_id, tenant_id, timestamp, host_id, event_type, severity,"
        f"  source, rule_id, rule_name, raw, details, acknowledged)"
        f" VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})"
        f" ON CONFLICT (event_id) DO NOTHING"
    )
    params = (
        ev["event_id"],
        ev["tenant_id"],
        ev["timestamp"],
        ev.get("host_id", "unknown"),
        ev["event_type"],
        ev["severity"],
        ev.get("source_ip", ev.get("source", "-")),  # attacking IP → source
        ev.get("rule_id", ""),
        ev.get("threat_name", ""),                   # threat name → rule_name
        ev.get("message", ""),                       # human message → raw
        details_json,
        0,                                           # acknowledged = False
    )
    sql = sql_sqlite if ph == "?" else sql_pg
    repo._exec_sql(sql, params)


def clear_demo(repo, verbose: bool = True) -> None:
    """Remove todos os eventos do tenant demo."""
    ph  = repo._placeholder()
    sql = f"DELETE FROM events WHERE tenant_id = {ph}"
    repo._exec_sql(sql, (DEMO_TENANT_ID,))
    if verbose:
        print(f"[demo] Eventos do tenant {DEMO_TENANT_ID} removidos.")


# ── CLI ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetGuard Demo Seed")
    parser.add_argument("--clear", action="store_true",
                        help="Remove eventos do tenant demo antes de inserir")
    parser.add_argument("--only-clear", action="store_true",
                        help="Apenas remove, não insere novos eventos")
    parser.add_argument("--events", type=int, default=350,
                        help="Número de eventos a gerar (default: 350)")
    args = parser.parse_args()

    os.environ.setdefault("IDS_AUTH", "false")
    os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")

    from storage.event_repository import EventRepository
    repo = EventRepository()

    if args.clear or args.only_clear:
        clear_demo(repo)

    if not args.only_clear:
        result = seed_demo(repo, n_events=args.events)
        print(f"\nDemo pronto:")
        print(f"  Token:     {result['token']}")
        print(f"  Tenant ID: {result['tenant_id']}")
        print(f"  Eventos:   {result['events']}")
        print(f"\n  Acesse: http://localhost:5000/demo")
