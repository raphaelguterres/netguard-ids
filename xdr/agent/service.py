"""Snapshot-to-event adapter service for the lightweight NetGuard agent."""

from __future__ import annotations

import logging
from typing import Any

from .buffer import LocalEventBuffer
from .client import XDRIngestionClient
from ..schema import utc_now_iso

logger = logging.getLogger("netguard.xdr.agent")

_SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "bash",
    "sh",
    "python",
    "python.exe",
}
_HIGH_RISK_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5985, 5986}


def snapshot_to_events(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    host_id = str(snapshot.get("host_id") or "unknown-host")
    platform = str(snapshot.get("platform") or "").lower()
    timestamp = str(snapshot.get("timestamp") or utc_now_iso())
    events: list[dict[str, Any]] = []

    suspicious_processes = sorted(
        list(snapshot.get("processes") or []),
        key=lambda item: float(item.get("cpu") or 0),
        reverse=True,
    )
    for process in suspicious_processes[:25]:
        name = str(process.get("name") or "").lower()
        cpu = float(process.get("cpu") or 0)
        command_line = str(process.get("exe") or process.get("cmdline") or "")
        if name not in _SUSPICIOUS_PROCESS_NAMES and cpu < 70:
            continue
        severity = "high" if name in _SUSPICIOUS_PROCESS_NAMES else "medium"
        events.append(
            {
                "host_id": host_id,
                "event_type": "process_execution",
                "severity": severity,
                "timestamp": timestamp,
                "process_name": process.get("name") or "",
                "command_line": command_line,
                "source": "agent",
                "platform": platform,
                "pid": process.get("pid"),
                "details": {
                    "cpu": process.get("cpu"),
                    "mem": process.get("mem"),
                    "exe": process.get("exe"),
                    "collection_mode": "snapshot",
                },
            }
        )

    for conn in list(snapshot.get("connections") or [])[:60]:
        destination_ip = str(conn.get("dst_ip") or "")
        destination_port = int(conn.get("dst_port") or 0)
        if not destination_ip:
            continue
        severity = "medium" if destination_port in _HIGH_RISK_PORTS else "low"
        events.append(
            {
                "host_id": host_id,
                "event_type": "network_connection",
                "severity": severity,
                "timestamp": timestamp,
                "process_name": conn.get("process") or "",
                "network_direction": "outbound",
                "network_dst_ip": destination_ip,
                "network_dst_port": destination_port,
                "source": "agent",
                "platform": platform,
                "details": {
                    "external": bool(conn.get("external")),
                    "status": conn.get("status") or "",
                    "collection_mode": "snapshot",
                },
            }
        )

    system = snapshot.get("system") or {}
    cpu_percent = float(system.get("cpu_percent") or 0)
    mem_percent = float(system.get("mem_percent") or 0)
    if cpu_percent >= 90 or mem_percent >= 95:
        events.append(
            {
                "host_id": host_id,
                "event_type": "behavioral_anomaly",
                "severity": "medium",
                "timestamp": timestamp,
                "source": "agent",
                "platform": platform,
                "details": {
                    "cpu_percent": cpu_percent,
                    "mem_percent": mem_percent,
                    "disk_percent": system.get("disk_percent"),
                    "collection_mode": "snapshot",
                },
            }
        )
    return events


class SnapshotAgentService:
    def __init__(self, client: XDRIngestionClient, buffer: LocalEventBuffer):
        self.client = client
        self.buffer = buffer

    def snapshot_to_events(self, snapshot: dict) -> list[dict]:
        return snapshot_to_events(snapshot)

    def ship_snapshot(self, snapshot: dict) -> dict:
        host_id = str(snapshot.get("host_id") or "unknown-host")
        platform = str(snapshot.get("platform") or "").lower()
        summary = {
            "process_count": len(snapshot.get("processes") or []),
            "connection_count": len(snapshot.get("connections") or []),
            "listen_port_count": len(snapshot.get("ports") or []),
            "system": snapshot.get("system") or {},
        }

        if not getattr(self.client, "agent_key", "") and getattr(self.client, "bootstrap_token", ""):
            try:
                self.client.register_host(
                    host_id=host_id,
                    display_name=host_id,
                    platform=platform,
                    agent_version=str(snapshot.get("agent_v") or ""),
                    metadata={"auto_enrolled": True},
                )
            except Exception as exc:
                logger.debug("Agent enrollment deferred | host=%s | detail=%s", host_id, exc)

        try:
            self.client.heartbeat(
                host_id=host_id,
                display_name=host_id,
                platform=platform,
                agent_version=str(snapshot.get("agent_v") or ""),
                snapshot_summary=summary,
            )
        except Exception as exc:
            logger.debug("Agent heartbeat failed | host=%s | detail=%s", host_id, exc)

        pending = self.buffer.load()
        events = self.snapshot_to_events(snapshot)
        outbound = (pending + events)[-500:]
        if not outbound:
            return {"ok": True, "queued": 0, "response": {"processed": 0}}
        try:
            payload = self.client.post_events(
                host_id=host_id,
                events=outbound,
                snapshot_summary=summary,
            )
            self.buffer.clear()
            return {"ok": True, "queued": 0, "response": payload}
        except Exception as exc:
            self.buffer.replace(outbound)
            return {
                "ok": False,
                "queued": len(outbound),
                "response": {"error": str(exc)},
            }
