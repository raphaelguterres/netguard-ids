"""Snapshot-to-event adapter service for the lightweight NetGuard agent."""

from __future__ import annotations

from .buffer import LocalEventBuffer
from .client import XDRIngestionClient
from ..schema import utc_now_iso


class SnapshotAgentService:
    def __init__(self, client: XDRIngestionClient, buffer: LocalEventBuffer):
        self.client = client
        self.buffer = buffer

    def snapshot_to_events(self, snapshot: dict) -> list[dict]:
        host_id = snapshot.get("host_id") or "unknown"
        timestamp = snapshot.get("timestamp") or utc_now_iso()
        events: list[dict] = []

        for proc in snapshot.get("processes", [])[:100]:
            events.append(
                {
                    "host_id": host_id,
                    "event_type": "process_execution",
                    "severity": "medium",
                    "timestamp": timestamp,
                    "process_name": proc.get("name", ""),
                    "command_line": proc.get("exe", ""),
                    "pid": proc.get("pid"),
                    "source": "agent",
                    "platform": snapshot.get("platform", ""),
                    "details": {"cpu": proc.get("cpu"), "mem": proc.get("mem")},
                }
            )

        for conn in snapshot.get("connections", [])[:100]:
            events.append(
                {
                    "host_id": host_id,
                    "event_type": "network_connection",
                    "severity": "low",
                    "timestamp": timestamp,
                    "process_name": conn.get("process", ""),
                    "network_dst_ip": conn.get("dst_ip", ""),
                    "network_dst_port": conn.get("dst_port"),
                    "network_direction": "outbound",
                    "source": "agent",
                    "details": {"status": conn.get("status", ""), "external": conn.get("external", False)},
                }
            )
        return events

    def ship_snapshot(self, snapshot: dict) -> dict:
        events = self.snapshot_to_events(snapshot)
        pending = self.buffer.drain(limit=200) + events
        ok, payload = self.client.send_events(pending)
        if not ok:
            for item in pending:
                self.buffer.enqueue(item)
        return {"ok": ok, "queued": 0 if ok else len(pending), "response": payload}
