"""
Host identity — gera e persiste o host_id de forma estável entre reboots.

Decisões de design:

- UUID v4 (não derivar de MAC/hostname): MAC pode mudar (NIC trocada,
  VPN, dock). Hostname pode duplicar (clones de VM). UUID v4 é
  estável e único por instalação.

- Persistência em ProgramData (Windows) ou /var/lib (Linux): sobrevive
  a reboot, atualização do agente e logoff de usuário. Não cabe em
  AppData (escopo do user) porque o agente roda como SYSTEM/service.

- Fallback "in-memory" só pra dev: se nem ProgramData nem ~/.netguard
  forem graváveis, gera UUID em memória e segue. O server vai tratar
  cada execução como host novo, mas pelo menos o agente roda.

- Não usa hostname como host_id por questões de privacidade
  (hostname vazado em log público é PII baixa, mas vazado).
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import subprocess
import sys
import uuid
from pathlib import Path

logger = logging.getLogger("netguard.agent.host_identity")

_HOST_ID_FILE = "host_id"
_DEFAULT_DIRS_WINDOWS = [
    # ProgramData é o lugar canônico pra estado de serviço Windows.
    r"C:\ProgramData\NetGuard",
]
_DEFAULT_DIRS_POSIX = [
    "/var/lib/netguard",
    str(Path.home() / ".netguard"),
]


def _candidate_dirs() -> list[Path]:
    """
    Diretórios candidatos pra gravar host_id, em ordem de preferência.
    NETGUARD_AGENT_HOME (env) sobrescreve tudo — útil pra docker/CI.
    """
    override = os.environ.get("NETGUARD_AGENT_HOME")
    if override:
        return [Path(override)]
    if sys.platform.startswith("win"):
        return [Path(d) for d in _DEFAULT_DIRS_WINDOWS]
    return [Path(d) for d in _DEFAULT_DIRS_POSIX]


def _normalize_mac(value: str) -> str:
    mac = str(value or "").strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6 or not all(len(part) == 2 for part in parts):
        return ""
    try:
        bytes_ = [int(part, 16) for part in parts]
    except ValueError:
        return ""
    if all(byte == 0 for byte in bytes_):
        return ""
    return ":".join(f"{byte:02x}" for byte in bytes_)


def _primary_local_ip() -> str:
    """
    Resolve o IP local que o SO usaria para sair da rede.
    UDP connect nao envia pacote; apenas consulta a tabela de rotas.
    """
    for target in ("8.8.8.8", "1.1.1.1"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((target, 80))
            local_ip = sock.getsockname()[0]
            if local_ip and not local_ip.startswith("127."):
                return local_ip
        except OSError:
            pass
        finally:
            sock.close()

    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip if local_ip != "127.0.0.1" else ""
    except OSError:
        return ""


def _network_interfaces() -> list[dict]:
    try:
        import psutil
    except ImportError:
        return []

    rows: list[dict] = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        ipv4: list[str] = []
        mac_address = ""
        for addr in addrs:
            address = str(getattr(addr, "address", "") or "")
            if getattr(addr, "family", None) == socket.AF_INET:
                if address and not address.startswith("127."):
                    ipv4.append(address)
                continue
            normalized = _normalize_mac(address)
            if normalized:
                mac_address = normalized
        if not ipv4 and not mac_address:
            continue
        stat = stats.get(name)
        rows.append({
            "name": str(name),
            "ipv4": ipv4[:4],
            "mac_address": mac_address,
            "is_up": bool(getattr(stat, "isup", False)) if stat else False,
            "speed_mbps": int(getattr(stat, "speed", 0) or 0) if stat else 0,
        })
    return rows


def _mac_for_local_ip(local_ip: str, interfaces: list[dict]) -> str:
    for iface in interfaces:
        if local_ip and local_ip in (iface.get("ipv4") or []):
            return str(iface.get("mac_address") or "")
    for iface in interfaces:
        mac = str(iface.get("mac_address") or "")
        if mac:
            return mac

    node = uuid.getnode()
    first_octet = (node >> 40) & 0xFF
    if first_octet & 0x01:
        return ""  # uuid gerou valor aleatorio, nao hardware MAC.
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def _run_text_command(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _default_gateway() -> str:
    if sys.platform.startswith("win"):
        output = _run_text_command(["route", "print", "-4", "0.0.0.0"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
        return ""

    if sys.platform == "darwin":
        output = _run_text_command(["route", "-n", "get", "default"])
        for line in output.splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "gateway":
                return value.strip()
        return ""

    output = _run_text_command(["ip", "route", "show", "default"])
    parts = output.split()
    if "via" in parts:
        idx = parts.index("via")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _neighbor_mac(ip_address: str) -> str:
    ip_address = str(ip_address or "").strip()
    if not ip_address:
        return ""

    if sys.platform.startswith("win"):
        output = _run_text_command(["arp", "-a", ip_address])
        for line in output.splitlines():
            if ip_address in line:
                for part in line.split():
                    mac = _normalize_mac(part)
                    if mac:
                        return mac
        return ""

    output = _run_text_command(["ip", "neigh", "show", ip_address])
    parts = output.split()
    if "lladdr" in parts:
        idx = parts.index("lladdr")
        if idx + 1 < len(parts):
            return _normalize_mac(parts[idx + 1])

    output = _run_text_command(["arp", "-n", ip_address])
    for part in output.split():
        mac = _normalize_mac(part)
        if mac:
            return mac
    return ""


def _try_read(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
        # Sanity: parsea como UUID. Se vier corrompido, descarta e regenera.
        uuid.UUID(text)
        return text
    except (OSError, ValueError):
        return None


def _try_write(path: Path, value: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="utf-8")
        # Em POSIX, restringe leitura a root pra não vazar pra usuários
        # comuns (em Windows o ACL default já é razoável).
        if not sys.platform.startswith("win"):
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return True
    except OSError as exc:
        logger.debug("host_id write falhou em %s: %s", path, exc)
        return False


def get_host_id() -> str:
    """
    Retorna o host_id persistente. Cria na primeira execução.
    Idempotente: chamadas subsequentes devolvem o mesmo valor.
    """
    for d in _candidate_dirs():
        path = d / _HOST_ID_FILE
        existing = _try_read(path)
        if existing:
            return existing

    # Não achou. Gera e tenta persistir no primeiro candidato gravável.
    new_id = str(uuid.uuid4())
    for d in _candidate_dirs():
        path = d / _HOST_ID_FILE
        if _try_write(path, new_id):
            logger.info("host_id novo gerado e gravado em %s", path)
            return new_id

    # Último recurso: in-memory. Server vai ver cada run como host novo.
    logger.warning(
        "host_id em memória — nenhum diretório gravável. "
        "Server vai tratar cada execução como host novo."
    )
    return new_id


def get_host_facts() -> dict:
    """
    Coleta hostname, OS, user, IP — usado no envelope do POST inicial
    pro server preencher display_name e platform corretamente.
    """
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"

    try:
        # IP "primário" — não é 100% confiável (interfaces múltiplas),
        # mas server usa só pra display, não como identificador.
        local_ip = _primary_local_ip()
    except OSError:
        local_ip = ""
    interfaces = _network_interfaces()
    default_gateway = _default_gateway()

    user = (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or ""
    )

    return {
        "hostname": hostname,
        "platform": platform.system().lower() or "unknown",
        "platform_version": platform.release() or "",
        "user": user,
        "local_ip": local_ip,
        "mac_address": _mac_for_local_ip(local_ip, interfaces),
        "default_gateway": default_gateway,
        "default_gateway_mac": _neighbor_mac(default_gateway),
        "network_interfaces": interfaces,
        "machine": platform.machine() or "",
    }


if __name__ == "__main__":
    # Smoke test manual: python -m agent.host_identity
    logging.basicConfig(level=logging.INFO)
    hid = get_host_id()
    facts = get_host_facts()
    print(f"host_id: {hid}")
    for k, v in facts.items():
        print(f"  {k}: {v}")
