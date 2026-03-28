"""
NetGuard — Agente Distribuído
Roda em qualquer máquina da rede e envia dados para o NetGuard central.

Uso:
  python agent.py --hub http://192.168.15.2:5000 --token SEU_TOKEN

O agente coleta:
  - Processos ativos (nome, PID, CPU, memória, exe)
  - Conexões de rede ativas
  - Portas em LISTEN
  - Métricas de sistema (CPU, RAM)

E envia para o hub central a cada 30 segundos.
O hub processa com o SOC Engine, Correlation Engine e Risk Score.
"""

import os
import sys
import time
import json
import socket
import logging
import argparse
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Importações opcionais
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False
    print("[WARN] psutil não instalado. Instale: pip install psutil")

# ── Configuração de logging ───────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = '{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt = "%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("netguard.agent")

BANNER = """
  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
  Agente Distribuído v1.0  |  Push de dados para o hub central
"""


class NetGuardAgent:
    """
    Agente leve que coleta dados do host e envia ao NetGuard central.
    Funciona em Windows, Linux e macOS.
    """

    def __init__(self, hub_url: str, token: str = "",
                 interval: int = 30, host_id: str = ""):
        self.hub_url  = hub_url.rstrip("/")
        self.token    = token
        self.interval = interval
        self.host_id  = host_id or self._get_host_id()
        self._running = False
        self._cycle   = 0
        self._errors  = 0
        self._sent    = 0

        logger.info("Agente iniciado | host=%s | hub=%s | interval=%ds",
                    self.host_id, self.hub_url, self.interval)

    def _get_host_id(self) -> str:
        """Retorna identificador único do host."""
        try:
            import subprocess
            hn = subprocess.check_output("hostname", shell=True, text=True).strip()
            return hn or socket.gethostname()
        except Exception:
            return socket.gethostname()

    def collect(self) -> dict:
        """Coleta snapshot completo do sistema."""
        snapshot = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "host_id":    self.host_id,
            "agent_v":    "1.0",
            "processes":  [],
            "connections":[],
            "ports":      [],
            "system":     {},
        }

        if not PSUTIL_OK:
            return snapshot

        # Processos
        try:
            for p in psutil.process_iter(
                ["pid","name","cpu_percent","memory_percent","exe","status"]
            ):
                try:
                    snapshot["processes"].append({
                        "pid":  p.info["pid"],
                        "name": p.info["name"] or "",
                        "cpu":  round(p.info["cpu_percent"] or 0, 1),
                        "mem":  round(p.info["memory_percent"] or 0, 2),
                        "exe":  (p.info["exe"] or "")[:120],
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug("Process collection error: %s", e)

        # Conexões de rede
        try:
            private = ("192.168.","10.","172.","127.","::1","0.0.0.0")
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.ip:
                    is_ext = not any(conn.raddr.ip.startswith(p) for p in private)
                    proc   = ""
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                    snapshot["connections"].append({
                        "dst_ip":   conn.raddr.ip,
                        "dst_port": conn.raddr.port,
                        "process":  proc,
                        "external": is_ext,
                        "status":   conn.status or "",
                    })
        except Exception as e:
            logger.debug("Connection collection error: %s", e)

        # Portas em LISTEN
        try:
            seen = set()
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    port  = conn.laddr.port
                    proto = "tcp"
                    key   = f"{proto}/{port}"
                    if key not in seen:
                        seen.add(key)
                        proc = ""
                        try:
                            if conn.pid:
                                proc = psutil.Process(conn.pid).name()
                        except Exception:
                            pass
                        snapshot["ports"].append({
                            "port":    port,
                            "proto":   proto,
                            "process": proc,
                        })
        except Exception as e:
            logger.debug("Port collection error: %s", e)

        # Métricas de sistema
        try:
            snapshot["system"] = {
                "cpu_percent":  psutil.cpu_percent(interval=0.1),
                "mem_percent":  psutil.virtual_memory().percent,
                "mem_used_mb":  psutil.virtual_memory().used // 1024 // 1024,
                "disk_percent": psutil.disk_usage("/").percent,
                "boot_time":    psutil.boot_time(),
            }
        except Exception as e:
            logger.debug("System metrics error: %s", e)

        return snapshot

    def send(self, snapshot: dict) -> bool:
        """Envia snapshot para o hub central."""
        url  = f"{self.hub_url}/api/agent/push"
        data = json.dumps(snapshot).encode("utf-8")
        headers = {
            "Content-Type":  "application/json",
            "User-Agent":    f"NetGuard-Agent/1.0 ({self.host_id})",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            req  = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                self._sent += 1
                return True
        except urllib.error.HTTPError as e:
            logger.warning("Hub HTTP error: %s %s", e.code, e.reason)
        except urllib.error.URLError as e:
            logger.warning("Hub unreachable: %s", e.reason)
        except Exception as e:
            logger.error("Send error: %s", e)

        self._errors += 1
        return False

    def run_once(self):
        """Coleta e envia um snapshot."""
        self._cycle += 1
        snapshot = self.collect()
        ok       = self.send(snapshot)
        logger.info(
            "Ciclo #%d | procs=%d conns=%d ports=%d | send=%s | erros=%d",
            self._cycle,
            len(snapshot["processes"]),
            len(snapshot["connections"]),
            len(snapshot["ports"]),
            "OK" if ok else "FAIL",
            self._errors,
        )
        return ok

    def run(self):
        """Loop principal — roda indefinidamente."""
        self._running = True
        logger.info("Loop iniciado | intervalo=%ds", self.interval)

        while self._running:
            try:
                self.run_once()
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error("Erro no ciclo: %s", e)

            # Aguarda próximo ciclo
            for _ in range(self.interval):
                if not self._running:
                    break
                time.sleep(1)

        logger.info("Agente encerrado | ciclos=%d enviados=%d erros=%d",
                    self._cycle, self._sent, self._errors)

    def stop(self):
        self._running = False


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="NetGuard Distributed Agent — push data to central hub"
    )
    parser.add_argument(
        "--hub", "-H",
        default=os.environ.get("NETGUARD_HUB", "http://127.0.0.1:5000"),
        help="URL do NetGuard hub (ex: http://192.168.15.2:5000)"
    )
    parser.add_argument(
        "--token", "-t",
        default=os.environ.get("NETGUARD_TOKEN", ""),
        help="Token de autenticação (se IDS_AUTH=true no hub)"
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=int(os.environ.get("NETGUARD_INTERVAL", "30")),
        help="Intervalo entre envios em segundos (default: 30)"
    )
    parser.add_argument(
        "--host-id",
        default=os.environ.get("NETGUARD_HOST_ID", ""),
        help="Identificador do host (default: hostname)"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Envia um snapshot e sai (útil para teste)"
    )

    args = parser.parse_args()

    print(f"  Hub:      {args.hub}")
    print(f"  Token:    {'configurado' if args.token else 'nenhum'}")
    print(f"  Intervalo: {args.interval}s")
    print()

    agent = NetGuardAgent(
        hub_url  = args.hub,
        token    = args.token,
        interval = args.interval,
        host_id  = args.host_id,
    )

    if args.once:
        ok = agent.run_once()
        sys.exit(0 if ok else 1)

    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()
        print("\n  Agente encerrado.")


if __name__ == "__main__":
    main()
