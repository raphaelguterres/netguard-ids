"""
NetGuard IDS — Seed direto no banco SQLite
==========================================
Script autossuficiente. Usa APENAS a stdlib do Python.
Não depende do app, do EventRepository, nem de nenhum import externo.

Uso (no terminal da pasta do projeto):
    python seed_direto.py

O script:
  1. Encontra o banco netguard_events.db automaticamente
  2. Mostra as colunas reais da tabela events
  3. Cria o tenant demo se não existir
  4. Apaga eventos antigos do tenant demo
  5. Insere 350 eventos realistas no mês de MARÇO/ABRIL 2026
  6. Confirma quantos foram gravados
"""

import sqlite3
import json
import uuid
import random
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ── Configuração ──────────────────────────────────────────────────
DEMO_TENANT_ID = "demo-tenant-netguard"
DEMO_TOKEN     = "ng_DEMO00000000000000000000000000"
DEMO_NAME      = "Empresa Demo — NetGuard IDS"
N_EVENTOS      = 350

# Encontra o banco relativo ao script
DB_PATH = Path(__file__).parent / "netguard_events.db"

# ── Dados de ameaças ──────────────────────────────────────────────
CENARIOS = [
    ("web_sqli",       "SQL Injection",                "HIGH"),
    ("web_xss",        "Cross-Site Scripting (XSS)",   "MEDIUM"),
    ("brute_force",    "Brute Force SSH",               "HIGH"),
    ("brute_force",    "Brute Force HTTP",              "MEDIUM"),
    ("port_scan",      "Port Scan",                     "MEDIUM"),
    ("recon",          "Network Reconnaissance",        "LOW"),
    ("malware",        "Malware Communication",         "CRITICAL"),
    ("data_exfil",     "Possível Exfiltração",          "CRITICAL"),
    ("lateral_move",   "Movimento Lateral",             "HIGH"),
    ("privesc",        "Escalada de Privilégio",        "CRITICAL"),
    ("ransomware",     "Atividade de Ransomware",       "CRITICAL"),
    ("dns_tunneling",  "DNS Tunneling",                 "HIGH"),
    ("web_scanner",    "Web Scanner Detectado",         "LOW"),
    ("failed_login",   "Login Inválido",                "LOW"),
    ("geo_anomaly",    "Acesso de Localização Incomum", "MEDIUM"),
    ("policy_viola",   "Violação de Política",          "LOW"),
    ("open_redirect",  "Open Redirect",                 "MEDIUM"),
    ("rce_attempt",    "Remote Code Execution",         "CRITICAL"),
    ("path_traversal", "Path Traversal",                "HIGH"),
    ("dos_attempt",    "DoS/DDoS Attempt",              "HIGH"),
]

IPS_ATACANTES = [
    "185.220.101.47", "45.142.212.100", "194.165.16.11",
    "91.240.118.172", "198.235.24.156", "103.75.190.12",
    "62.210.115.87",  "5.188.206.14",   "185.156.73.54",
    "141.98.81.227",  "79.137.206.57",  "45.227.254.8",
]

HOSTS = [
    "srv-web-01", "srv-db-01", "srv-mail-01",
    "wks-admin",  "wks-finance", "firewall-01",
]

PESOS = {"CRITICAL": 0.05, "HIGH": 0.20, "MEDIUM": 0.40, "LOW": 0.35}


def ts_aleatorio() -> str:
    """Timestamp aleatório nos últimos 35 dias (cobre março e abril)."""
    now   = datetime.now(timezone.utc)
    delta = timedelta(
        days    = random.uniform(0, 35),
        hours   = random.uniform(0, 23),
        minutes = random.uniform(0, 59),
    )
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    print(f"\n{'='*55}")
    print("  NetGuard IDS — Seed Direto")
    print(f"{'='*55}")
    print(f"  Banco: {DB_PATH}")

    if not DB_PATH.exists():
        print(f"\n  ERRO: Banco não encontrado em {DB_PATH}")
        print("  Certifique-se de rodar o script na pasta do projeto.")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row

    # ── Mostra colunas reais ──────────────────────────────────────
    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
    print(f"\n  Colunas da tabela events:")
    print(f"  {', '.join(cols)}")

    # ── Garante tenant demo ───────────────────────────────────────
    existing = conn.execute(
        "SELECT tenant_id FROM tenants WHERE token = ?", (DEMO_TOKEN,)
    ).fetchone()

    if not existing:
        conn.execute("""
            INSERT OR IGNORE INTO tenants
                (tenant_id, name, token, plan, max_hosts)
            VALUES (?, ?, ?, 'pro', 50)
        """, (DEMO_TENANT_ID, DEMO_NAME, DEMO_TOKEN))
        conn.commit()
        print(f"\n  Tenant criado: {DEMO_TENANT_ID}")
    else:
        print(f"\n  Tenant já existe: {DEMO_TENANT_ID}")

    # ── Remove eventos antigos do demo ────────────────────────────
    antes = conn.execute(
        "SELECT COUNT(*) FROM events WHERE tenant_id = ?", (DEMO_TENANT_ID,)
    ).fetchone()[0]
    conn.execute("DELETE FROM events WHERE tenant_id = ?", (DEMO_TENANT_ID,))
    conn.commit()
    print(f"  Eventos removidos (antes): {antes}")

    # ── Insere eventos novos ──────────────────────────────────────
    pesos   = [PESOS.get(c[2], 0.20) for c in CENARIOS]
    salvos  = 0
    erros   = 0

    # Detecta quais colunas existem (compatibilidade com schemas antigos)
    tem_rule_name  = "rule_name" in cols
    tem_source     = "source" in cols
    tem_raw        = "raw" in cols

    for _ in range(N_EVENTOS):
        etype, threat, sev = random.choices(CENARIOS, weights=pesos, k=1)[0]
        ip   = random.choice(IPS_ATACANTES)
        host = random.choice(HOSTS)
        ts   = ts_aleatorio()
        eid  = str(uuid.uuid4())
        msg  = f"[{threat}] de {ip} em {host}"
        det  = json.dumps({"threat_name": threat, "message": msg, "demo": True})

        try:
            conn.execute("""
                INSERT OR IGNORE INTO events
                    (event_id, tenant_id, timestamp, host_id, event_type,
                     severity, source, rule_id, rule_name, raw, details, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (eid, DEMO_TENANT_ID, ts, host, etype,
                  sev, ip, f"NG-{random.randint(1000,9999)}",
                  threat, msg, det))
            salvos += 1
        except sqlite3.OperationalError as e:
            # Fallback para schemas sem rule_name/source/raw
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO events
                        (event_id, tenant_id, timestamp, host_id, event_type,
                         severity, details, acknowledged)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """, (eid, DEMO_TENANT_ID, ts, host, etype, sev, det))
                salvos += 1
            except Exception as e2:
                erros += 1
                if erros <= 3:
                    print(f"  [ERRO] {e2}")

    conn.commit()

    # ── Verifica ──────────────────────────────────────────────────
    total = conn.execute(
        "SELECT COUNT(*) FROM events WHERE tenant_id = ?", (DEMO_TENANT_ID,)
    ).fetchone()[0]

    por_sev = {r[0]: r[1] for r in conn.execute(
        "SELECT severity, COUNT(*) FROM events WHERE tenant_id = ? GROUP BY severity",
        (DEMO_TENANT_ID,)
    ).fetchall()}

    print(f"\n  {'─'*45}")
    print(f"  Eventos inseridos : {salvos}")
    print(f"  Erros             : {erros}")
    print(f"  Total no banco    : {total}")
    print(f"  Por severidade    : {por_sev}")

    conn.close()

    if total > 0:
        print(f"\n  ✓ SUCESSO! Banco populado com {total} eventos.")
        print(f"\n  Próximos passos:")
        print(f"  1. Reinicie o Flask: python app.py")
        print(f"  2. Abra: http://localhost:5000/demo")
        print(f"  3. Abra: http://localhost:5000/api/report/monthly/preview")
    else:
        print("\n  ✗ FALHA — nenhum evento foi gravado.")
        print("  Verifique se o banco não está travado por outro processo.")

    print(f"\n{'='*55}\n")


if __name__ == "__main__":
    main()
