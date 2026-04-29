"""
SOC-style Alert correlation — operates on `Alert` objects produced by
`detection_engine.DetectionEngine`. Sits *next to* the existing
`engine.correlation_engine` (which correlates raw telemetry); this
module focuses on cross-rule pattern fusion.

Correlation rules (per spec):

  CORR-PS-NET     PowerShell rule + network rule (same host, 5 min)  → HIGH
  CORR-PERSIST-EX Persistence rule + Execution rule (same host)     → CRITICAL
  CORR-BURST      ≥3 alerts on same host within `burst_window_s`     → HIGH
  CORR-AUTH-MIX   Failed login(s) followed by successful login       → HIGH

Output: `Alert` objects with `rule_id` starting `CORR-`. They reference
the source alert IDs in `event_ids` so the dashboard can drill in.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from storage.repository import Alert

from . import mitre_mapper

logger = logging.getLogger("netguard.correlation.soc")


# ── Tag helpers ──────────────────────────────────────────────────────


def _is_powershell_alert(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    if "PS-" in rid or "POWERSHELL" in rid:
        return True
    return a.mitre_technique.startswith("T1059.001")


def _is_network_alert(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    if "-NET-" in rid or "NETWORK" in rid:
        return True
    return a.mitre_tactic in {"Command and Control", "Exfiltration"}


def _is_persistence_alert(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    if "PERSIST" in rid:
        return True
    return a.mitre_tactic == "Persistence"


def _is_execution_alert(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    if "EXEC" in rid or "LOLBIN" in rid:
        return True
    return a.mitre_tactic in {"Execution", "Defense Evasion"}


def _is_failed_auth(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    return "AUTH-FAIL" in rid or "BRUTE" in rid


def _is_successful_auth(a: Alert) -> bool:
    rid = (a.rule_id or "").upper()
    return "AUTH-SUCCESS" in rid or "LOGIN-OK" in rid


def _parse_iso(ts: str) -> datetime:
    """Parse ISO-8601 with optional Z suffix. Falls back to now."""
    if not ts:
        return datetime.now(timezone.utc)
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Engine ───────────────────────────────────────────────────────────


@dataclass
class CorrelationConfig:
    ps_net_window_s: int = 300         # PowerShell + network, 5 min
    persist_exec_window_s: int = 600   # Persistence + execution, 10 min
    burst_window_s: int = 120          # 3+ alerts, 2 min
    burst_threshold: int = 3
    auth_mix_window_s: int = 600       # failed→success login, 10 min


class SocCorrelator:
    """
    Cross-rule correlation. Stateless — give it a window of alerts,
    receive correlation alerts back. Same window → same output (dedup
    is on the (rule_id, host_id, bucket) key).

    This deliberately does *not* maintain background state. The caller
    (ingestion pipeline) is responsible for fetching the look-back
    window from the repository.
    """

    def __init__(self, config: CorrelationConfig | None = None):
        self.cfg = config or CorrelationConfig()

    def correlate(self, alerts: Iterable[Alert]) -> list[Alert]:
        alerts = sorted(list(alerts), key=lambda a: _parse_iso(a.timestamp))
        if not alerts:
            return []

        out: list[Alert] = []
        out.extend(self._corr_ps_net(alerts))
        out.extend(self._corr_persist_exec(alerts))
        out.extend(self._corr_burst(alerts))
        out.extend(self._corr_auth_mix(alerts))

        # Dedup: same (rule_id, host_id, bucketed-time)
        seen = set()
        dedup: list[Alert] = []
        for a in out:
            bucket = a.timestamp[:16]  # minute bucket
            key = (a.rule_id, a.host_id, bucket)
            if key in seen:
                continue
            seen.add(key)
            dedup.append(a)
        return dedup

    # ── individual correlations ──

    def _by_host(self, alerts: list[Alert]) -> dict[str, list[Alert]]:
        out: dict[str, list[Alert]] = {}
        for a in alerts:
            out.setdefault(a.host_id, []).append(a)
        return out

    def _corr_ps_net(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        window = timedelta(seconds=self.cfg.ps_net_window_s)
        for host, host_alerts in self._by_host(alerts).items():
            ps = [a for a in host_alerts if _is_powershell_alert(a)]
            net = [a for a in host_alerts if _is_network_alert(a)]
            for p in ps:
                pt = _parse_iso(p.timestamp)
                near = [n for n in net
                        if abs(_parse_iso(n.timestamp) - pt) <= window]
                if near:
                    out.append(self._build(
                        rule_id="CORR-PS-NET",
                        title="PowerShell activity followed by outbound network",
                        severity="high",
                        confidence=82,
                        technique="T1059.001",
                        host_id=host,
                        timestamp=p.timestamp,
                        evidence=f"PS alert {p.rule_id} + {len(near)} network alert(s) within {self.cfg.ps_net_window_s//60}m",
                        event_ids=[p.alert_id, *(n.alert_id for n in near)],
                    ))
        return out

    def _corr_persist_exec(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        window = timedelta(seconds=self.cfg.persist_exec_window_s)
        for host, host_alerts in self._by_host(alerts).items():
            persist = [a for a in host_alerts if _is_persistence_alert(a)]
            exec_ = [a for a in host_alerts if _is_execution_alert(a)]
            if not persist or not exec_:
                continue
            for p in persist:
                pt = _parse_iso(p.timestamp)
                near = [e for e in exec_
                        if abs(_parse_iso(e.timestamp) - pt) <= window]
                if near:
                    out.append(self._build(
                        rule_id="CORR-PERSIST-EXEC",
                        title="Persistence + Execution chain on host",
                        severity="critical",
                        confidence=90,
                        technique="T1547.001",
                        host_id=host,
                        timestamp=p.timestamp,
                        evidence=f"Persistence alert {p.rule_id} co-occurs with {len(near)} execution alert(s)",
                        event_ids=[p.alert_id, *(e.alert_id for e in near)],
                    ))
        return out

    def _corr_burst(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        window = timedelta(seconds=self.cfg.burst_window_s)
        thr = max(2, int(self.cfg.burst_threshold))
        for host, host_alerts in self._by_host(alerts).items():
            host_alerts = sorted(host_alerts, key=lambda a: _parse_iso(a.timestamp))
            n = len(host_alerts)
            for i in range(n):
                start = _parse_iso(host_alerts[i].timestamp)
                bucket = [host_alerts[i]]
                for j in range(i + 1, n):
                    if _parse_iso(host_alerts[j].timestamp) - start <= window:
                        bucket.append(host_alerts[j])
                    else:
                        break
                if len(bucket) >= thr:
                    out.append(self._build(
                        rule_id="CORR-BURST",
                        title=f"Alert burst on host ({len(bucket)} in {self.cfg.burst_window_s//60}m)",
                        severity="high",
                        confidence=70,
                        technique="T1059",
                        host_id=host,
                        timestamp=host_alerts[i].timestamp,
                        evidence=f"{len(bucket)} alerts within {self.cfg.burst_window_s}s",
                        event_ids=[a.alert_id for a in bucket],
                    ))
                    break  # one burst alert per host per call
        return out

    def _corr_auth_mix(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        window = timedelta(seconds=self.cfg.auth_mix_window_s)
        for host, host_alerts in self._by_host(alerts).items():
            failed = [a for a in host_alerts if _is_failed_auth(a)]
            success = [a for a in host_alerts if _is_successful_auth(a)]
            if not failed or not success:
                continue
            for f in failed:
                ft = _parse_iso(f.timestamp)
                near_success = [
                    s for s in success
                    if 0 <= (_parse_iso(s.timestamp) - ft).total_seconds() <= window.total_seconds()
                ]
                if near_success:
                    out.append(self._build(
                        rule_id="CORR-AUTH-MIX",
                        title="Failed authentication followed by success",
                        severity="high",
                        confidence=80,
                        technique="T1110",
                        host_id=host,
                        timestamp=near_success[0].timestamp,
                        evidence=f"Failed auth {f.rule_id} → success within {window.total_seconds()/60:.0f}m",
                        event_ids=[f.alert_id, near_success[0].alert_id],
                    ))
        return out

    # ── builder ──

    def _build(
        self,
        *,
        rule_id: str,
        title: str,
        severity: str,
        confidence: int,
        technique: str,
        host_id: str,
        timestamp: str,
        evidence: str,
        event_ids: list[str],
    ) -> Alert:
        return Alert(
            alert_id=_stable_correlation_alert_id(rule_id, host_id, event_ids),
            host_id=host_id,
            rule_id=rule_id,
            severity=severity,
            confidence=int(confidence),
            timestamp=timestamp or _now_iso(),
            title=title,
            evidence=evidence,
            mitre_tactic=mitre_mapper.tactic_for(technique),
            mitre_technique=technique,
            event_ids=list(event_ids),
            status="open",
        )


def _stable_correlation_alert_id(
    rule_id: str,
    host_id: str,
    event_ids: list[str],
) -> str:
    seed = "|".join([
        "netguard:correlation",
        rule_id,
        host_id,
        *sorted(str(item) for item in event_ids if item),
    ])
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
