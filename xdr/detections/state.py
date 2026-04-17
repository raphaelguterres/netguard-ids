"""State tracking and lightweight baseline helpers for XDR detections."""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from .base import canonical_command, parse_event_timestamp, related_event_ref

try:
    from engine.ml_baseline import MLBaseline, SKLEARN_AVAILABLE
except Exception:  # pragma: no cover - graceful degradation
    MLBaseline = None
    SKLEARN_AVAILABLE = False


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address((ip or "").strip()).is_private
    except ValueError:
        return True


@dataclass
class HostBehaviorProfile:
    host_id: str
    process_counts: Counter[str] = field(default_factory=Counter)
    parent_child_counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    command_counts: Counter[str] = field(default_factory=Counter)
    login_hours: defaultdict[str, Counter[int]] = field(default_factory=lambda: defaultdict(Counter))
    auth_attempts: defaultdict[tuple[str, str], deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=60))
    )
    network_dest_counts: Counter[tuple[str, int]] = field(default_factory=Counter)
    network_dest_times: defaultdict[tuple[str, int], deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20))
    )
    process_index: dict[int, dict[str, Any]] = field(default_factory=dict)
    recent_event_refs: deque = field(default_factory=lambda: deque(maxlen=250))
    recent_process_window: deque = field(default_factory=lambda: deque(maxlen=64))
    recent_network_window: deque = field(default_factory=lambda: deque(maxlen=64))
    recent_port_window: deque = field(default_factory=lambda: deque(maxlen=32))
    total_process_events: int = 0
    total_auth_successes: int = 0
    total_network_events: int = 0

    def observe(self, event) -> None:
        now = parse_event_timestamp(event.timestamp).timestamp()
        self.recent_event_refs.appendleft(related_event_ref(event))

        if event.event_type in {"process_execution", "script_execution"}:
            process = (event.process_name or "").lower()
            parent = (event.parent_process or "").lower()
            command = canonical_command(event.command_line)
            if process:
                self.process_counts[process] += 1
                self.total_process_events += 1
                self.recent_process_window.append(now)
            if process and parent:
                self.parent_child_counts[(parent, process)] += 1
            if command:
                self.command_counts[command] += 1
            if event.pid:
                self.process_index[int(event.pid)] = {
                    "pid": int(event.pid),
                    "ppid": int(event.ppid or 0),
                    "process_name": event.process_name,
                    "parent_process": event.parent_process,
                    "command_line": event.command_line,
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                }
                if len(self.process_index) > 512:
                    oldest_pid = min(
                        self.process_index,
                        key=lambda pid: parse_event_timestamp(self.process_index[pid].get("timestamp", "")).timestamp(),
                    )
                    self.process_index.pop(oldest_pid, None)

        if event.event_type == "authentication":
            key = ((event.username or "").lower(), event.auth_source_ip or "")
            bucket = self.auth_attempts[key]
            bucket.append(
                {
                    "timestamp": now,
                    "result": (event.auth_result or "").lower(),
                    "event_id": event.event_id,
                    "hour": parse_event_timestamp(event.timestamp).hour,
                }
            )
            if (event.auth_result or "").lower() == "success" and event.username:
                self.login_hours[event.username.lower()][parse_event_timestamp(event.timestamp).hour] += 1
                self.total_auth_successes += 1

        if event.event_type == "network_connection" and (event.network_direction or "").lower() == "outbound":
            dest_ip = event.network_dst_ip or ""
            dest_port = int(event.network_dst_port or 0)
            if dest_ip:
                key = (dest_ip, dest_port)
                self.network_dest_counts[key] += 1
                self.network_dest_times[key].append(now)
                self.recent_network_window.append((now, dest_ip, dest_port))
                if dest_port:
                    self.recent_port_window.append(dest_port)
                self.total_network_events += 1

    def recent_related_events(
        self,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for event_ref in self.recent_event_refs:
            if predicate and not predicate(event_ref):
                continue
            items.append(dict(event_ref))
            if len(items) >= limit:
                break
        return items

    def recent_auth(
        self,
        key: tuple[str, str],
        *,
        within_seconds: int,
        result: str | None = None,
        reference_ts: float | None = None,
    ) -> list[dict[str, Any]]:
        cutoff = (reference_ts if reference_ts is not None else time.time()) - within_seconds
        matches = []
        for item in self.auth_attempts.get(key, ()):
            if item["timestamp"] < cutoff:
                continue
            if result and item["result"] != result:
                continue
            matches.append(item)
        return matches

    def login_hour_distribution(self, username: str) -> Counter[int]:
        return self.login_hours.get((username or "").lower(), Counter())

    def recent_intervals(self, dest_key: tuple[str, int], *, sample_size: int = 5) -> list[float]:
        points = list(self.network_dest_times.get(dest_key, ()))
        if len(points) < sample_size:
            return []
        points = points[-sample_size:]
        return [round(points[idx] - points[idx - 1], 3) for idx in range(1, len(points))]

    def lineage_for(self, event, *, depth: int = 4) -> list[dict[str, Any]]:
        lineage: list[dict[str, Any]] = []
        seen: set[int] = set()

        current = {
            "process_name": event.process_name,
            "parent_process": event.parent_process,
            "command_line": event.command_line,
            "pid": event.pid,
            "ppid": event.ppid,
            "timestamp": event.timestamp,
            "event_id": event.event_id,
        }
        if any(current.values()):
            lineage.append(current)

        next_pid = int(event.ppid or 0)
        while next_pid and next_pid not in seen and len(lineage) < max(depth, 1):
            seen.add(next_pid)
            parent = self.process_index.get(next_pid)
            if not parent:
                break
            lineage.append(dict(parent))
            next_pid = int(parent.get("ppid") or 0)

        if not lineage and event.parent_process:
            lineage.append(
                {
                    "process_name": event.process_name,
                    "parent_process": event.parent_process,
                    "command_line": event.command_line,
                    "pid": event.pid,
                    "ppid": event.ppid,
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                }
            )
        return lineage

    def synthetic_snapshot(self, event) -> dict[str, Any]:
        cpu_value = 0.0
        try:
            cpu_value = float((event.details or {}).get("cpu", 0) or 0)
        except (TypeError, ValueError):
            cpu_value = 0.0

        process_count = max(1, min(len(self.recent_process_window), 32))
        recent_connections = list(self.recent_network_window)[-20:]
        processes = [{"cpu": cpu_value} for _ in range(process_count)]
        connections = [{"dst_ip": dest_ip} for _, dest_ip, _ in recent_connections]
        ports = [{"port": port} for port in list(self.recent_port_window)[-16:]]
        return {"processes": processes, "connections": connections, "ports": ports}


class HostBehaviorStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._profiles: dict[str, HostBehaviorProfile] = {}

    def observe(self, event) -> HostBehaviorProfile:
        with self._lock:
            profile = self._profiles.get(event.host_id)
            if profile is None:
                profile = HostBehaviorProfile(host_id=event.host_id)
                self._profiles[event.host_id] = profile
            profile.observe(event)
            return profile


class BehavioralBaselineAdapter:
    """Hybrid baseline adapter: lightweight counters + optional MLBaseline."""

    def __init__(self, *, enable_ml: bool = True):
        self._lock = threading.RLock()
        self._enable_ml = bool(enable_ml and MLBaseline and SKLEARN_AVAILABLE)
        self._models: dict[str, Any] = {}

    def assess(self, event, profile: HostBehaviorProfile) -> dict[str, Any]:
        process = (event.process_name or "").lower()
        parent = (event.parent_process or "").lower()
        username = (event.username or "").lower()
        command = canonical_command(event.command_line)
        signals: dict[str, Any] = {}

        if event.event_type in {"process_execution", "script_execution"} and process:
            signals["rare_process"] = profile.total_process_events >= 6 and profile.process_counts[process] == 1
            if parent:
                signals["rare_parent_child"] = (
                    profile.total_process_events >= 8
                    and profile.parent_child_counts[(parent, process)] == 1
                )
            if command:
                signals["rare_command_pattern"] = (
                    profile.total_process_events >= 8
                    and profile.command_counts[command] == 1
                )

        if event.event_type == "authentication" and (event.auth_result or "").lower() == "success" and username:
            hour_distribution = profile.login_hour_distribution(username)
            current_hour = parse_event_timestamp(event.timestamp).hour
            total = sum(hour_distribution.values())
            dominant_hour = max(hour_distribution, key=hour_distribution.get) if hour_distribution else current_hour
            signals["unusual_login_hour"] = (
                total >= 6
                and hour_distribution[current_hour] == 1
                and abs(current_hour - dominant_hour) >= 4
            )

        if event.event_type == "network_connection" and (event.network_direction or "").lower() == "outbound":
            dest_key = (event.network_dst_ip or "", int(event.network_dst_port or 0))
            signals["rare_outbound_destination"] = (
                profile.total_network_events >= 8
                and dest_key[0]
                and not _is_private_ip(dest_key[0])
                and profile.network_dest_counts[dest_key] == 1
            )
            signals["beacon_intervals"] = profile.recent_intervals(dest_key)
            signals["possible_beaconing"] = self._looks_like_beacon(signals["beacon_intervals"])

        ml_signal = self._assess_ml(event, profile)
        if ml_signal:
            signals["ml_behavior_deviation"] = ml_signal

        return signals

    def _assess_ml(self, event, profile: HostBehaviorProfile) -> dict[str, Any] | None:
        if not self._enable_ml:
            return None
        if event.event_type not in {"process_execution", "script_execution", "network_connection"}:
            return None
        with self._lock:
            model = self._models.get(event.host_id)
            if model is None:
                model = MLBaseline(host_id=event.host_id, min_samples=16, contamination=0.08, window_size=128)
                self._models[event.host_id] = model
        try:
            result = model.add_sample(profile.synthetic_snapshot(event))
        except Exception:
            return None
        if not result:
            return None
        return {
            "severity": str(result.get("severity", "MEDIUM")).lower(),
            "description": result.get("description", "Baseline deviation detected."),
            "details": result.get("details", {}),
        }

    @staticmethod
    def _looks_like_beacon(intervals: list[float]) -> bool:
        if len(intervals) < 4:
            return False
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return False
        variance = sum((item - mean) ** 2 for item in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        return stddev <= max(3.0, mean * 0.2)
