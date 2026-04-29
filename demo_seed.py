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


def seed_demo(repo, n_events: int = 350, verbose: bool = True,
              tenant_override: str = None) -> dict:
    """
    Cria o tenant de demo e insere N eventos realistas.
    tenant_override: usa tenant_id alternativo (para trials isolados).
    Retorna dict com tenant_id e token.
    """
    _TENANT_ID = tenant_override or DEMO_TENANT_ID

    # Cria ou garante que o tenant existe (apenas para o tenant padrão de demo)
    if not tenant_override:
        try:
            existing = repo.get_tenant_by_token(DEMO_TOKEN)
            if not existing:
                existing_by_id = repo.get_tenant_by_id(DEMO_TENANT_ID)
                if existing_by_id:
                    from security import hash_token

                    repaired = repo.update_tenant_token(
                        DEMO_TENANT_ID,
                        DEMO_TOKEN,
                        hash_token(DEMO_TOKEN),
                    )
                    if repaired:
                        existing = repo.get_tenant_by_token(DEMO_TOKEN)
                        if verbose:
                            print(f"[demo] Token demo revalidado: {_TENANT_ID}")
            if not existing:
                repo.create_tenant(
                    tenant_id = DEMO_TENANT_ID,
                    name      = DEMO_NAME,
                    token     = DEMO_TOKEN,
                    plan      = DEMO_PLAN,
                    max_hosts = 50,
                    role      = "admin",
                )
                if verbose:
                    print(f"[demo] Tenant criado: {_TENANT_ID}")
            else:
                # Garante que tenant existente tenha role=admin
                try:
                    repo.update_tenant_role(DEMO_TENANT_ID, "admin")
                except Exception:
                    pass
                if verbose:
                    print(f"[demo] Tenant já existe: {_TENANT_ID}")
        except Exception as e:
            if verbose:
                print(f"[demo] Aviso ao criar tenant: {e}")

    # Pesos para distribuição realista
    scenarios = THREAT_SCENARIOS
    weights   = [_weight_scenario(s) for s in scenarios]

    # Gera eventos com distribuição realista
    events_saved = 0
    built_events = []
    for _ in range(n_events):
        scenario = random.choices(scenarios, weights=weights, k=1)[0]
        event    = _build_event(scenario, _TENANT_ID)
        built_events.append(event)
        try:
            _save_raw(repo, event)
            events_saved += 1
        except Exception as e:
            if verbose:
                print(f"[demo] Erro ao salvar evento (repo): {e}")

    # Popula também o DetectionStore (ids_detections.db) — banco lido pelo dashboard
    ids_saved = _seed_detection_store(built_events, verbose=verbose)

    if verbose:
        print(f"[demo] {events_saved} eventos no EventRepo | {ids_saved} no DetectionStore")

    _seed_new_modules(verbose=verbose)

    return {
        "tenant_id": _TENANT_ID,
        "token":     DEMO_TOKEN,
        "events":    events_saved,
    }


def _seed_detection_store(events: list, verbose: bool = False) -> int:
    """
    Insere eventos de demo diretamente no DetectionStore (ids_detections.db).
    Este é o banco lido por /api/detections e /api/statistics no dashboard.
    """
    import sqlite3 as _sq
    import os as _os

    db_path = _os.environ.get("IDS_DB_PATH", "ids_detections.db")
    SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    schema = """
    CREATE TABLE IF NOT EXISTS detections (
        detection_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
        threat_name TEXT NOT NULL, severity TEXT NOT NULL,
        description TEXT, source_ip TEXT, log_entry TEXT,
        method TEXT, mitre_tactic TEXT, mitre_technique TEXT,
        status TEXT DEFAULT 'active', analyst_note TEXT DEFAULT '',
        confidence REAL DEFAULT 1.0, count INTEGER DEFAULT 1,
        updated_at TEXT
    );
    """
    try:
        conn = _sq.connect(db_path)
        conn.executescript(schema)
        conn.commit()
        saved = 0
        for ev in events:
            sev = SEV_MAP.get(ev.get("severity", "LOW"), "low")
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO detections "
                    "(detection_id,timestamp,threat_name,severity,description,"
                    " source_ip,log_entry,method,mitre_tactic,mitre_technique,"
                    " status,confidence,count,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ev["event_id"],
                        ev["timestamp"],
                        ev.get("threat_name", "Unknown"),
                        sev,
                        ev.get("message", ""),
                        ev.get("source_ip", ""),
                        ev.get("message", ""),
                        ev.get("event_type", "ids"),
                        "",   # mitre_tactic
                        "",   # mitre_technique
                        "active",
                        round(random.uniform(0.65, 0.99), 2),
                        1,
                        ev["timestamp"],
                    )
                )
                saved += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
        return saved
    except Exception as exc:
        if verbose:
            print(f"[demo] Aviso DetectionStore: {exc}")
        return 0


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


def _seed_new_modules(verbose: bool = False) -> None:
    """Popula IOC Manager e Custom Rules com dados de demonstração."""
    import pathlib
    db_path = str(pathlib.Path(__file__).parent / "netguard_soc.db")

    # ── IOC Manager demo ──────────────────────────────────────────
    try:
        from ioc_manager import get_ioc_manager
        mgr = get_ioc_manager(db_path, DEMO_TENANT_ID)
        demo_iocs = [
            ("185.220.101.47",    "ip",     "TOR Exit Node — Feodo Tracker"),
            ("91.108.4.0/22",     "ip",     "Telegram Infrastructure (known C2 abuse)"),
            ("evil-c2-server.ru", "domain", "Known C2 Domain — abuse.ch"),
            ("update-flash-cdn.net","domain","Phishing domain — OpenPhish"),
            ("44d88612fea8a8f36de82e1278abb02f","hash","EICAR Test Hash (MD5)"),
            ("275a021bbfb6489e54d471899f7db9d1693986da69f5304ab75c5","hash","Emotet dropper SHA256"),
        ]
        existing = {i["value"] for i in mgr.list_iocs()}
        for value, itype, desc in demo_iocs:
            if value not in existing:
                mgr.add_ioc({"value": value, "ioc_type": itype, "description": desc, "tags": ["demo"]})
        if verbose:
            print(f"[demo] {len(demo_iocs)} IOCs inseridos")
    except Exception as e:
        if verbose:
            print(f"[demo] IOC seed falhou: {e}")

    # ── Custom Rules demo ──────────────────────────────────────────
    try:
        from custom_rules import get_custom_rule_engine
        engine = get_custom_rule_engine(db_path, DEMO_TENANT_ID)
        demo_rules = [
            {
                "name": "Acesso Fora do Horário Comercial",
                "description": "Detecta logins entre 00h-06h (provável acesso não autorizado)",
                "severity": "HIGH",
                "logic": "AND",
                "conditions": [
                    {"field": "hour", "operator": "between", "value": [0, 6]},
                    {"field": "event_type", "operator": "contains", "value": "login"},
                ],
                "enabled": True,
            },
            {
                "name": "Brute Force SSH Detectado",
                "description": "Mais de 10 tentativas de login SSH seguidas",
                "severity": "CRITICAL",
                "logic": "AND",
                "conditions": [
                    {"field": "source", "operator": "eq",  "value": "22"},
                    {"field": "details.attempts", "operator": "gte", "value": 10},
                ],
                "enabled": True,
            },
            {
                "name": "PowerShell Suspeito",
                "description": "Execução de PowerShell com parâmetros de bypass",
                "severity": "HIGH",
                "logic": "OR",
                "conditions": [
                    {"field": "raw", "operator": "contains", "value": "-ExecutionPolicy Bypass"},
                    {"field": "raw", "operator": "contains", "value": "-EncodedCommand"},
                    {"field": "raw", "operator": "contains", "value": "DownloadString"},
                ],
                "enabled": True,
            },
        ]
        existing_names = {r["name"] for r in engine.list_rules()}
        for rule in demo_rules:
            if rule["name"] not in existing_names:
                engine.create_rule(rule)
        if verbose:
            print(f"[demo] {len(demo_rules)} regras customizadas inseridas")
    except Exception as e:
        if verbose:
            print(f"[demo] Custom Rules seed falhou: {e}")


# ── T17 — Multi-tenant Operator Inbox seed ────────────────────────
#
# Este bloco existe pra preencher o /admin/inbox com hosts ranqueados de
# múltiplos clientes na hora — útil pra demos/portfolio. O inbox lê
# repo.list_tenants() → list_hosts(tenant) → events últimas 24h por host.
# Sem hosts em managed_hosts (T16: bucket "admin" é exatamente isso),
# o inbox fica vazio mesmo com 350 eventos no events table.
MT_TENANT_PREFIX = "demo-mt-"
MT_TOKEN_PREFIX  = "ng_DEMOMT"

# Cenários "high signal" pra cada tenant ter pelo menos 1 evento crítico
# tangível na timeline do host (não só MEDIUM/LOW que ficam no fundo).
MT_CRITICAL_SCENARIOS = [
    ("ransomware",  "Atividade de Ransomware",   "CRITICAL",
     "Criação massiva de arquivos criptografados em {host}"),
    ("data_exfil",  "Possível Exfiltração",      "CRITICAL",
     "Volume anormal de dados saindo para {ip} — {size}MB em 5min"),
    ("malware",     "Malware Communication",     "CRITICAL",
     "Comunicação com C2 conhecido: {ip}:{port} — hash: {hash}"),
    ("privesc",     "Escalada de Privilégio",    "CRITICAL",
     "Tentativa de sudo/runas em {host} por usuário {user}"),
    ("rce_attempt", "Remote Code Execution",     "CRITICAL",
     "Tentativa de RCE via {path} — payload: {payload}"),
]

# Pool maior de host_ids pra evitar colisão visual no inbox (cada
# tenant tem set distinto, fica óbvio que são clientes diferentes).
MT_HOST_POOL = [
    "srv-web", "srv-db", "srv-app", "srv-api", "srv-mail",
    "wks-eng", "wks-finance", "wks-ops", "wks-sales",
    "fw-edge", "fw-core", "lb-prod", "vpn-gw",
    "k8s-node", "ad-dc", "fileserver",
]

MT_PLATFORMS = ["linux", "windows", "macos"]


def _rand_recent_ts(hours_max: int = 20) -> str:
    """
    Timestamp dentro das últimas hours_max horas (default 20h).
    O inbox filtra `since = now - 24h`, então qualquer coisa mais
    velha que isso some do ranking de risco.
    """
    now   = datetime.now(timezone.utc)
    delta = timedelta(
        hours   = random.uniform(0, hours_max),
        minutes = random.uniform(0, 59),
    )
    return (now - delta).isoformat()


def _build_recent_critical_event(tenant_id: str, host_id: str) -> dict:
    """
    Constrói um evento CRITICAL recente (<24h) ligado a um host
    específico — necessário pro `_host_inbox_ranking` enxergar o host
    com risco > 0 e empurrar pra Inbox.
    """
    scenario = random.choice(MT_CRITICAL_SCENARIOS)
    etype, tname, sev, msg_tpl = scenario
    ip   = random.choice(ATTACKING_IPS)
    msg  = msg_tpl.format(
        path    = random.choice(WEB_PATHS),
        payload = random.choice(PAYLOADS),
        ip      = ip,
        host    = host_id,
        size    = round(random.uniform(50, 2500), 1),
        port    = random.choice([4444, 8080, 1337, 443, 9001]),
        hash    = uuid.uuid4().hex[:16],
        user    = random.choice(USERS),
    )
    return {
        "event_id":    str(uuid.uuid4()),
        "tenant_id":   tenant_id,
        "timestamp":   _rand_recent_ts(),
        "event_type":  etype,
        "threat_name": tname,
        "severity":    sev,
        "source_ip":   ip,
        "host_id":     host_id,
        "message":     msg,
        "rule_id":     f"NG-{random.randint(1000, 9999)}",
        "acknowledged": False,
        "details":     {"auto_generated": True, "demo": True, "demo_mt": True},
    }


def seed_multi_tenant_inbox(
    repo,
    n_tenants: int = 20,
    hosts_per_tenant: int = 3,
    verbose: bool = True,
) -> dict:
    """
    Cria N tenants demo, registra 2-3 hosts por tenant em managed_hosts
    e insere 1-2 eventos críticos recentes (<24h) por tenant amarrados
    a um dos hosts. Resultado: /api/admin/inbox retorna ~N hosts
    ranqueados na primeira request, sem precisar registrar agentes na
    mão.

    Idempotente: re-rodar não duplica tenants/hosts; eventos novos são
    inseridos a cada execução (event_id é UUID).
    """
    from storage.host_repository import HostRepository
    from security import hash_token

    n_tenants = max(1, min(n_tenants, 200))
    hosts_per_tenant = max(1, min(hosts_per_tenant, 10))

    db_path = getattr(repo, "db_path", None)
    tenants_created = 0
    hosts_created   = 0
    events_saved    = 0

    company_suffix = [
        "Banco", "Logistica", "Saude", "Varejo", "Telecom",
        "Energia", "Industria", "Educacao", "Seguros", "Mineradora",
        "Agro", "Tech", "Construcao", "Mídia", "Servicos",
        "Pharma", "Hotelaria", "Aviacao", "Financeira", "Cooperativa",
    ]

    for idx in range(1, n_tenants + 1):
        tid   = f"{MT_TENANT_PREFIX}{idx:02d}"
        token = f"{MT_TOKEN_PREFIX}{idx:02d}{'0' * 22}"  # ng_DEMOMT01000... (32 chars)
        tname = f"Cliente {company_suffix[(idx - 1) % len(company_suffix)]} {idx:02d}"

        # ── 1. Tenant ───────────────────────────────────────────────
        try:
            existing = repo.get_tenant_by_id(tid)
            if not existing:
                repo.create_tenant(
                    tenant_id = tid,
                    name      = tname,
                    token     = token,
                    plan      = "pro",
                    max_hosts = 50,
                    role      = "analyst",
                )
                tenants_created += 1
        except Exception as exc:
            if verbose:
                print(f"[demo-mt] Aviso ao criar tenant {tid}: {exc}")
            continue

        # ── 2. Hosts em managed_hosts ───────────────────────────────
        host_registry = HostRepository(db_path=db_path, tenant_id=tid)
        # Sample sem repetição mas amostra do pool grande (suficiente pra hosts_per_tenant<=10)
        host_names = random.sample(MT_HOST_POOL, k=min(hosts_per_tenant, len(MT_HOST_POOL)))
        host_ids: list[str] = []
        for host_name in host_names:
            host_id = f"{host_name}-{idx:02d}"
            host_ids.append(host_id)
            try:
                fake_key      = f"nga_DEMO{uuid.uuid4().hex[:24]}"
                host_registry.register_host(
                    host_id          = host_id,
                    display_name     = host_id,
                    platform         = random.choice(MT_PLATFORMS),
                    agent_version    = "1.0.0-demo",
                    enrollment_method= "demo_seed",
                    api_key_hash     = hash_token(fake_key),
                    api_key_prefix   = fake_key[:16],
                    metadata         = {"demo_mt": True, "tenant_idx": idx},
                    tags             = ["demo", "demo-mt"],
                    tenant_id        = tid,
                )
                hosts_created += 1
            except Exception as exc:
                if verbose:
                    print(f"[demo-mt] Aviso ao registrar host {host_id}: {exc}")

        # ── 3. Eventos críticos recentes (<24h) ─────────────────────
        # 1-2 críticos por tenant amarrados a um host real do tenant.
        # Sem isso o _host_inbox_ranking devolve risk_score=0 e o host
        # nunca aparece no inbox.
        if not host_ids:
            continue
        n_critical = random.choice([1, 2])
        for _ in range(n_critical):
            target_host = random.choice(host_ids)
            ev = _build_recent_critical_event(tid, target_host)
            try:
                _save_raw(repo, ev)
                events_saved += 1
            except Exception as exc:
                if verbose:
                    print(f"[demo-mt] Aviso ao salvar evento crítico {tid}/{target_host}: {exc}")

    if verbose:
        print(
            f"[demo-mt] {tenants_created} novos tenants | "
            f"{hosts_created} hosts em managed_hosts | "
            f"{events_saved} eventos críticos recentes"
        )

    return {
        "tenants_created": tenants_created,
        "hosts_created":   hosts_created,
        "events_saved":    events_saved,
        "n_tenants":       n_tenants,
    }


def clear_multi_tenant_inbox(repo, verbose: bool = True) -> dict:
    """
    Remove todos os tenants/hosts/eventos criados por
    `seed_multi_tenant_inbox` (prefix demo-mt-). Útil pra resetar a
    demo entre apresentações.
    """
    ph = repo._placeholder()
    pattern = f"{MT_TENANT_PREFIX}%"

    # Eventos
    try:
        repo._exec_sql(
            f"DELETE FROM events WHERE tenant_id LIKE {ph}",
            (pattern,),
        )
    except Exception as exc:
        if verbose:
            print(f"[demo-mt] Aviso ao limpar eventos: {exc}")

    # Hosts
    try:
        repo._exec_sql(
            f"DELETE FROM managed_hosts WHERE tenant_id LIKE {ph}",
            (pattern,),
        )
    except Exception as exc:
        if verbose:
            print(f"[demo-mt] Aviso ao limpar managed_hosts: {exc}")

    # Tenants
    try:
        repo._exec_sql(
            f"DELETE FROM tenants WHERE tenant_id LIKE {ph}",
            (pattern,),
        )
    except Exception as exc:
        if verbose:
            print(f"[demo-mt] Aviso ao limpar tenants: {exc}")

    if verbose:
        print(f"[demo-mt] Tenants/hosts/eventos com prefix '{MT_TENANT_PREFIX}' removidos.")
    return {"ok": True}


def clear_demo(repo, verbose: bool = True) -> None:
    """Remove todos os eventos do tenant demo (EventRepo + DetectionStore)."""
    import sqlite3 as _sq, os as _os
    ph  = repo._placeholder()
    sql = f"DELETE FROM events WHERE tenant_id = {ph}"
    repo._exec_sql(sql, (DEMO_TENANT_ID,))
    # Limpa também o DetectionStore
    db_path = _os.environ.get("IDS_DB_PATH", "ids_detections.db")
    try:
        conn = _sq.connect(db_path)
        conn.execute("DELETE FROM detections")
        conn.commit()
        conn.close()
    except Exception:
        pass
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
    parser.add_argument("--multi-tenant", type=int, default=0,
                        metavar="N",
                        help="Cria N tenants demo + 2-3 hosts/tenant + "
                             "evento crítico recente (popula /admin/inbox)")
    parser.add_argument("--hosts-per-tenant", type=int, default=3,
                        help="Hosts por tenant no modo --multi-tenant (default: 3)")
    parser.add_argument("--clear-mt", action="store_true",
                        help="Remove tenants/hosts/eventos do seed multi-tenant")
    args = parser.parse_args()

    os.environ.setdefault("IDS_AUTH", "false")
    os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")

    from storage.event_repository import EventRepository
    repo = EventRepository()

    if args.clear or args.only_clear:
        clear_demo(repo)

    if args.clear_mt:
        clear_multi_tenant_inbox(repo)

    if not args.only_clear:
        result = seed_demo(repo, n_events=args.events)
        print(f"\nDemo pronto:")
        print(f"  Token:     {result['token']}")
        print(f"  Tenant ID: {result['tenant_id']}")
        print(f"  Eventos:   {result['events']}")
        print(f"\n  Acesse: http://localhost:5000/demo")

        if args.multi_tenant > 0:
            mt = seed_multi_tenant_inbox(
                repo,
                n_tenants        = args.multi_tenant,
                hosts_per_tenant = args.hosts_per_tenant,
            )
            print(f"\nSeed multi-tenant:")
            print(f"  Tenants pedidos:   {mt['n_tenants']}")
            print(f"  Tenants criados:   {mt['tenants_created']}")
            print(f"  Hosts registrados: {mt['hosts_created']}")
            print(f"  Eventos críticos:  {mt['events_saved']}")
            print(f"\n  Inbox: http://localhost:5000/admin/inbox")
