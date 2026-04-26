"""Snapshot collection helpers for the NetGuard agent."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone

try:
    import psutil

    PSUTIL_OK = True
except ImportError:  # pragma: no cover - environment dependent
    psutil = None
    PSUTIL_OK = False


def collect_snapshot(*, host_id: str, platform_name: str) -> dict:
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": host_id,
        "hostname": socket.gethostname(),
        "platform": platform_name,
        "agent_v": "2.0",
        "processes": [],
        "connections": [],
        "ports": [],
        "system": {},
    }
    if not PSUTIL_OK:
        return snapshot

    try:
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "exe", "status"],
        ):
            try:
                snapshot["processes"].append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"] or "",
                        "cpu": round(proc.info["cpu_percent"] or 0, 1),
                        "mem": round(proc.info["memory_percent"] or 0, 2),
                        "exe": (proc.info["exe"] or "")[:256],
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    private_prefixes = ("192.168.", "10.", "172.", "127.", "::1", "0.0.0.0")
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr or not conn.raddr.ip:
                continue
            process_name = ""
            try:
                if conn.pid:
                    process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = ""
            snapshot["connections"].append(
                {
                    "dst_ip": conn.raddr.ip,
                    "dst_port": conn.raddr.port,
                    "process": process_name,
                    "external": not any(
                        conn.raddr.ip.startswith(prefix)
                        for prefix in private_prefixes
                    ),
                    "status": conn.status or "",
                }
            )
    except Exception:
        pass

    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "LISTEN" or not conn.laddr:
                continue
            port = conn.laddr.port
            key = f"tcp/{port}"
            if key in seen:
                continue
            seen.add(key)
            process_name = ""
            try:
                if conn.pid:
                    process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = ""
            snapshot["ports"].append(
                {
                    "port": port,
                    "proto": "tcp",
                    "process": process_name,
                }
            )
    except Exception:
        pass

    try:
        snapshot["system"] = {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "mem_percent": psutil.virtual_memory().percent,
            "mem_used_mb": psutil.virtual_memory().used // 1024 // 1024,
            "disk_percent": psutil.disk_usage("/").percent,
            "boot_time": psutil.boot_time(),
        }
    except Exception:
        snapshot["system"] = {}

    return snapshot


def current_platform() -> str:
    return platform.system().lower()


def summarize_snapshot(snapshot: dict) -> dict:
    return {
        "process_count": len(snapshot.get("processes") or []),
        "connection_count": len(snapshot.get("connections") or []),
        "listen_port_count": len(snapshot.get("ports") or []),
        "system": snapshot.get("system") or {},
    }
