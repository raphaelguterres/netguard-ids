import os  # noqa: F401
import platform
import socket
import subprocess
import time
from typing import Any, Dict, List

import psutil

OS = platform.system()
IS_WINDOWS = OS.lower().startswith("win")
IS_LINUX = OS.lower().startswith("linux")
IS_MAC = OS.lower().startswith("darwin")


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "netguard-host"


def get_processes(limit: int | None = None) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []

    for proc in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "status"]
    ):
        try:
            items.append(
                {
                    "pid": proc.info.get("pid"),
                    "name": proc.info.get("name") or "",
                    "user": proc.info.get("username") or "",
                    "cpu": proc.info.get("cpu_percent") or 0,
                    "memory": proc.info.get("memory_percent") or 0,
                    "status": proc.info.get("status") or "",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if limit:
        return items[:limit]
    return items


def get_pid_name_map() -> Dict[str, str]:
    mapping: Dict[str, str] = {}

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or ""
            if pid is not None:
                mapping[str(pid)] = name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return mapping


def get_listen_ports() -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                ports.append(
                    {
                        "ip": getattr(conn.laddr, "ip", ""),
                        "port": getattr(conn.laddr, "port", 0),
                        "pid": conn.pid,
                        "status": conn.status,
                    }
                )
    except Exception:
        pass

    return ports


def get_connections() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []

    try:
        pid_map = get_pid_name_map()

        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue

            remote_ip = getattr(conn.raddr, "ip", "")
            remote_port = getattr(conn.raddr, "port", 0)
            local_port = getattr(conn.laddr, "port", 0) if conn.laddr else 0
            pid = conn.pid
            process_name = pid_map.get(str(pid), f"pid:{pid}") if pid else "system"

            items.append(
                {
                    "ip": remote_ip,
                    "port": remote_port,
                    "local_port": local_port,
                    "pid": pid,
                    "process": process_name.lower(),
                    "status": conn.status,
                }
            )
    except Exception:
        pass

    return items


def get_security_events(seconds_back: int = 35) -> List[Dict[str, Any]]:
    """
    Shim compatível.
    No Windows sem integração nativa com Event Log, retorna lista vazia.
    """
    return []


def get_arp_table() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    try:
        cmd = ["arp", "-a"] if IS_WINDOWS else ["arp", "-an"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if IS_WINDOWS:
                if len(parts) >= 3 and "." in parts[0]:
                    rows.append(
                        {
                            "ip": parts[0],
                            "mac": parts[1],
                            "type": parts[2] if len(parts) > 2 else "",
                        }
                    )
            else:
                if len(parts) >= 4:
                    ip = parts[1].strip("()")
                    mac = parts[3]
                    rows.append({"ip": ip, "mac": mac, "type": ""})
    except Exception:
        pass

    return rows


def ping(host: str, timeout_ms: int = 500) -> float:
    """
    Retorna latência em ms; -1 em caso de falha.
    """
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        else:
            timeout_s = max(1, int(timeout_ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]

        started = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        elapsed_ms = (time.perf_counter() - started) * 1000

        if result.returncode == 0:
            return round(elapsed_ms, 2)
        return -1
    except Exception:
        return -1