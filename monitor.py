"""
monitor.py — Monitor de Rede Real
Lê eventos reais do Windows e manda pro IDS.
Monitora: Event Log, conexoes de rede, processos suspeitos.

Como usar:
  Terminal 1: python app.py
  Terminal 2: python monitor.py
"""

import re
import time
import subprocess
import requests
import sys
from datetime import datetime

API     = "http://localhost:5000/api/analyze"
HEALTH  = "http://localhost:5000/api/health"

# ─────────────────────────────────────────────
#  Sua rede local — ajuste se necessário
# ─────────────────────────────────────────────
REDE_LOCAL = "192.168.15."   # prefixo da sua rede

# IPs da sua própria rede que são confiáveis
# (o IDS já tem whitelist, mas aqui evitamos
#  nem enviar pra análise — reduz ruído)
IPS_CONFIAVEIS = {
    "192.168.15.1",   # gateway
    "192.168.15.2",   # sua máquina
    "127.0.0.1",
    "::1",
}

# Portas clássicas de reverse shell / C2
PORTAS_SUSPEITAS = {
    4444, 4445, 4446, 1234, 31337,
    9999, 6666, 6667, 8888, 2222,
}

# Processos de hacking conhecidos
PROCESSOS_SUSPEITOS = [
    "nc.exe", "ncat.exe", "nmap.exe", "netcat.exe",
    "mimikatz.exe", "meterpreter", "cobaltstrike",
    "psexec.exe", "wce.exe", "fgdump.exe", "pwdump",
    "gsecdump", "procdump.exe", "lazagne.exe",
    "sharpdump", "rubeus.exe", "bloodhound.exe",
]

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def extrair_ip(texto: str) -> str:
    m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', texto)
    return m.group(1) if m else None

def ip_confiavel(ip: str) -> bool:
    return ip in IPS_CONFIAVEIS

def enviar(log: str, ip: str = None, field: str = "syslog", origem: str = ""):
    """Envia log pra API do IDS e imprime se detectar algo."""
    if ip and ip_confiavel(ip):
        return   # não envia IPs confiáveis

    try:
        r = requests.post(API, json={
            "log": log,
            "source_ip": ip,
            "field": field,
        }, timeout=3)

        data = r.json()
        if data.get("threats_found", 0) > 0:
            for d in data["detections"]:
                sev   = d["severity"].upper()
                nome  = d["threat_name"]
                conf  = round(d.get("confidence", 1) * 100)
                print(f"\n  {'!'*50}")
                print(f"  ALERTA REAL [{sev}] {nome}")
                print(f"  IP: {ip or 'desconhecido'} | Confiança: {conf}%")
                print(f"  Origem: {origem}")
                print(f"  Log: {log[:120]}")
                print(f"  {'!'*50}\n")

    except requests.exceptions.ConnectionError:
        print("  [!] IDS offline — reinicie o app.py")
    except Exception as e:
        print(f"  [erro] {e}")


# ─────────────────────────────────────────────
#  1. Event Log de Segurança do Windows
# ─────────────────────────────────────────────

# Guarda o ID do último evento processado pra não repetir
_ultimo_event_id = [0]

def monitorar_event_log():
    """
    Lê eventos de segurança novos do Windows.
    IDs monitorados:
      4625 — Falha de logon (brute force)
      4648 — Logon com credenciais explícitas
      4720 — Nova conta de usuário criada
      4732 — Usuário adicionado ao grupo Admins
      4740 — Conta bloqueada
      4756 — Membro adicionado a grupo privilegiado
      7045 — Novo serviço instalado (persistence)
    """
    cmd = [
        "powershell", "-Command",
        """
        $ids = @(4625,4648,4720,4732,4740,4756,7045)
        Get-WinEvent -FilterHashtable @{
            LogName='Security';
            Id=$ids;
            StartTime=(Get-Date).AddSeconds(-35)
        } -ErrorAction SilentlyContinue |
        ForEach-Object {
            $_.RecordId.ToString() + '||' +
            $_.Id.ToString() + '||' +
            $_.TimeCreated.ToString('HH:mm:ss') + '||' +
            $_.Message.Substring(0,[Math]::Min(400,$_.Message.Length)).Replace("`n",' ')
        }
        """
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        linhas = [l.strip() for l in result.stdout.strip().split('\n') if '||' in l]

        novos = 0
        for linha in linhas:
            partes = linha.split('||')
            if len(partes) < 4:
                continue

            record_id = int(partes[0]) if partes[0].isdigit() else 0
            event_id  = partes[1]
            horario   = partes[2]
            mensagem  = partes[3]

            # Ignora eventos já processados
            if record_id <= _ultimo_event_id[0]:
                continue
            _ultimo_event_id[0] = max(_ultimo_event_id[0], record_id)

            ip = extrair_ip(mensagem)

            # Mapeia cada Event ID
            if event_id == '4625':
                enviar(f"Failed logon attempt: {mensagem}", ip, "syslog",
                       f"Windows Event 4625 ({horario})")
            elif event_id == '4648':
                enviar(f"Explicit credential logon: {mensagem}", ip, "syslog",
                       f"Windows Event 4648 ({horario})")
            elif event_id == '4720':
                enviar(f"New user account created: {mensagem}", ip, "syslog",
                       f"Windows Event 4720 ({horario})")
            elif event_id == '4732':
                enviar(f"User added to Administrators group: {mensagem}", ip, "command",
                       f"Windows Event 4732 ({horario})")
            elif event_id == '4740':
                enviar(f"Account locked out: {mensagem}", ip, "syslog",
                       f"Windows Event 4740 ({horario})")
            elif event_id == '4756':
                enviar(f"Member added to privileged group: {mensagem}", ip, "command",
                       f"Windows Event 4756 ({horario})")
            elif event_id == '7045':
                enviar(f"New service installed: {mensagem}", ip, "command",
                       f"Windows Event 7045 ({horario})")

            novos += 1

        if novos > 0:
            print(f"  Event Log: {novos} eventos novos analisados")
        else:
            print(f"  Event Log: sem eventos novos nos ultimos 35s")

    except subprocess.TimeoutExpired:
        print("  Event Log: timeout (sem eventos recentes)")
    except Exception as e:
        print(f"  Event Log: erro — {e}")


# ─────────────────────────────────────────────
#  2. Conexões de rede ativas
# ─────────────────────────────────────────────

_conexoes_vistas = set()   # evita alertar a mesma conexão duas vezes

def monitorar_conexoes():
    """Analisa conexões TCP ativas procurando padrões suspeitos."""
    try:
        result = subprocess.run(
            ["netstat", "-n", "-o"],
            capture_output=True, text=True, timeout=10
        )

        suspeitas = 0
        total     = 0

        for linha in result.stdout.strip().split('\n'):
            if 'ESTABLISHED' not in linha:
                continue

            partes = linha.split()
            if len(partes) < 5:
                continue

            endereco_remoto = partes[2]
            if ':' not in endereco_remoto:
                continue

            # Extrai IP e porta remotos
            ultimo_dois_pontos = endereco_remoto.rfind(':')
            ip_remoto   = endereco_remoto[:ultimo_dois_pontos].strip('[]')
            porta_str   = endereco_remoto[ultimo_dois_pontos+1:]
            pid         = partes[4] if len(partes) > 4 else "?"

            try:
                porta_remota = int(porta_str)
            except ValueError:
                continue

            total += 1
            chave = f"{ip_remoto}:{porta_remota}"

            # Ignora loopback e IPs confiáveis
            if ip_confiavel(ip_remoto) or ip_remoto.startswith("127."):
                continue

            # Verifica porta suspeita
            if porta_remota in PORTAS_SUSPEITAS and chave not in _conexoes_vistas:
                _conexoes_vistas.add(chave)
                log = (f"SUSPICIOUS CONNECTION ESTABLISHED "
                       f"DST={ip_remoto} DPT={porta_remota} PID={pid}")
                enviar(log, ip_remoto, "firewall",
                       f"netstat: porta suspeita {porta_remota}")
                suspeitas += 1

            # IP externo (fora da rede local) em porta baixa
            elif (not ip_remoto.startswith(REDE_LOCAL)
                  and porta_remota < 1024
                  and chave not in _conexoes_vistas):
                _conexoes_vistas.add(chave)
                log = (f"EXTERNAL CONNECTION "
                       f"DST={ip_remoto} DPT={porta_remota} PID={pid}")
                enviar(log, ip_remoto, "firewall",
                       f"netstat: conexao externa porta {porta_remota}")
                suspeitas += 1

        print(f"  Rede: {total} conexoes ativas | {suspeitas} suspeitas")

    except Exception as e:
        print(f"  Rede: erro — {e}")


# ─────────────────────────────────────────────
#  3. Processos em execução
# ─────────────────────────────────────────────

_processos_alertados = set()   # não repete alertas do mesmo processo

def monitorar_processos():
    """Verifica processos em execução buscando ferramentas de hacking."""
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10
        )

        encontrados = []
        for linha in result.stdout.strip().split('\n'):
            partes = linha.strip().split(',')
            if not partes:
                continue
            nome = partes[0].strip('"').lower()
            pid  = partes[1].strip('"') if len(partes) > 1 else "?"

            for suspeito in PROCESSOS_SUSPEITOS:
                if suspeito.lower() in nome and nome not in _processos_alertados:
                    _processos_alertados.add(nome)
                    log = f"Suspicious process running: {nome} PID={pid}"
                    enviar(log, "127.0.0.1", "command",
                           f"tasklist: {nome} (pid {pid})")
                    encontrados.append(nome)

        if encontrados:
            print(f"  Processos: SUSPEITOS ENCONTRADOS: {encontrados}")
        else:
            print(f"  Processos: nenhum suspeito")

    except Exception as e:
        print(f"  Processos: erro — {e}")


# ─────────────────────────────────────────────
#  Loop principal
# ─────────────────────────────────────────────

def aguardar_api(tentativas: int = 15):
    print("  Aguardando IDS API...")
    for i in range(tentativas):
        try:
            r = requests.get(HEALTH, timeout=2)
            if r.status_code == 200:
                data = r.json()
                print(f"  IDS conectado | modo: {data.get('modo','?')} | "
                      f"assinaturas: {data.get('signatures_loaded','?')}")
                return True
        except Exception:
            pass
        time.sleep(1)
        print(f"    tentativa {i+1}/{tentativas}...")
    return False


def main():
    print("""
  ╔══════════════════════════════════════════════╗
  ║  IDS Monitor — Rede Real 192.168.15.x       ║
  ║  Sem simulador. Apenas eventos reais.        ║
  ╚══════════════════════════════════════════════╝
    """)

    if not aguardar_api():
        print("  IDS offline. Inicie o app.py primeiro.")
        sys.exit(1)

    intervalo = 30
    ciclo     = 0

    print(f"\n  Monitorando a cada {intervalo}s — Ctrl+C para parar\n")

    while True:
        ciclo += 1
        agora = datetime.now().strftime('%H:%M:%S')
        print(f"--- Ciclo #{ciclo} — {agora} ---")

        monitorar_event_log()
        monitorar_conexoes()
        monitorar_processos()

        print(f"  Proxima varredura em {intervalo}s...\n")
        time.sleep(intervalo)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Monitor encerrado.")
