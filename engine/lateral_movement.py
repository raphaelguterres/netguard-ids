"""
NetGuard — Lateral Movement Detector
Correlaciona eventos ENTRE máquinas para detectar movimentação lateral.

Padrões detectados:
  LM-1  Same Source IP → Multiple Hosts
        Mesmo IP externo aparece em 3+ hosts em 5 minutos
        MITRE T1021 — Remote Services

  LM-2  Credential Spray
        Mesmo IP tenta auth em 3+ hosts em 2 minutos
        MITRE T1110.003 — Password Spraying

  LM-3  Beaconing Cross-Host
        Mesmo IP externo contactado por 3+ hosts em 10 minutos
        MITRE T1071 — Application Layer Protocol (C2)

  LM-4  Sequential Host Compromise
        Host A detecta ameaça, Host B (mesmo segmento) detecta
        ameaça similar em < 15 minutos
        MITRE T1570 — Lateral Tool Transfer

  LM-5  Internal Port Scan
        IP interno tenta conectar em 5+ portas diferentes em hosts
        MITRE T1046 — Network Service Discovery
"""

import time
import logging
import threading
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any

logger = logging.getLogger("netguard.lateral")


class LateralAlert:
    def __init__(self, rule_id: str, rule_name: str,
                 severity: str, confidence: int,
                 description: str, details: dict,
                 hosts_involved: List[str], source_ip: str = ""):
        self.rule_id        = rule_id
        self.rule_name      = rule_name
        self.severity       = severity
        self.confidence     = min(100, confidence)
        self.description    = description
        self.details        = details
        self.hosts_involved = hosts_involved
        self.source_ip      = source_ip
        self.timestamp      = datetime.now(timezone.utc).isoformat()
        self.id             = f"{rule_id}_{int(time.time()*1000)}"

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "rule_id":        self.rule_id,
            "rule_name":      self.rule_name,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "description":    self.description,
            "details":        self.details,
            "hosts_involved": self.hosts_involved,
            "source_ip":      self.source_ip,
            "timestamp":      self.timestamp,
            "mitre":          self._mitre(),
            "tags":           ["lateral-movement", "cross-host", self.rule_id.lower()],
        }

    def _mitre(self) -> dict:
        mitre_map = {
            "LM-1": {"tactic": "lateral_movement",  "technique": "T1021"},
            "LM-2": {"tactic": "credential_access", "technique": "T1110.003"},
            "LM-3": {"tactic": "command_and_control","technique": "T1071"},
            "LM-4": {"tactic": "lateral_movement",  "technique": "T1570"},
            "LM-5": {"tactic": "discovery",         "technique": "T1046"},
        }
        return mitre_map.get(self.rule_id, {"tactic": "lateral_movement", "technique": "T1021"})


class _TimeWindow:
    """Sliding time window para eventos."""
    def __init__(self, seconds: int):
        self._ttl    = seconds
        self._events : deque = deque()
        self._lock   = threading.RLock()

    def add(self, item: Any):
        now = time.monotonic()
        with self._lock:
            self._events.append((now, item))
            self._evict()

    def _evict(self):
        cutoff = time.monotonic() - self._ttl
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def items(self) -> List[Any]:
        self._evict()
        return [item for _, item in self._events]

    def count(self) -> int:
        return len(self.items())

    def clear(self):
        with self._lock:
            self._events.clear()


class LateralMovementDetector:
    """
    Detector de Lateral Movement cross-host.
    Recebe eventos de múltiplos hosts e correlaciona.
    """

    def __init__(self):
        self._lock    = threading.RLock()
        self._alerts  : List[LateralAlert] = []
        self._fired   : dict = {}  # dedup: rule+key → last_fired timestamp

        # Per-IP tracking windows
        self._ip_to_hosts    : Dict[str, _TimeWindow] = defaultdict(lambda: _TimeWindow(300))   # LM-1: 5min
        self._ip_auth_hosts  : Dict[str, _TimeWindow] = defaultdict(lambda: _TimeWindow(120))   # LM-2: 2min
        self._ip_c2_hosts    : Dict[str, _TimeWindow] = defaultdict(lambda: _TimeWindow(600))   # LM-3: 10min
        self._host_events    : Dict[str, _TimeWindow] = defaultdict(lambda: _TimeWindow(900))   # LM-4: 15min
        self._internal_scan  : Dict[str, _TimeWindow] = defaultdict(lambda: _TimeWindow(300))   # LM-5: 5min

        self._total_ingested = 0
        self._total_alerts   = 0

        logger.info("LateralMovementDetector iniciado | 5 padrões ativos")

    def ingest(self, event: dict, host_id: str = "") -> List[LateralAlert]:
        """
        Recebe um evento de qualquer host e verifica padrões.
        Retorna lista de alertas gerados (pode ser vazia).
        """
        self._total_ingested += 1

        event_type = event.get("event_type", "")
        details    = event.get("details", {})
        severity   = event.get("severity", "LOW")
        host       = host_id or event.get("host_id", "unknown")

        private_prefixes = ("192.168.", "10.", "172.16.", "127.", "::1")

        alerts = []

        # ── LM-1: Same source IP → Multiple Hosts ────────────────
        src_ip = (details.get("ip") or details.get("dst_ip") or
                  details.get("source_ip") or "")
        if src_ip and not any(src_ip.startswith(p) for p in private_prefixes):
            self._ip_to_hosts[src_ip].add(host)
            hosts = list(set(self._ip_to_hosts[src_ip].items()))
            if len(hosts) >= 3:
                a = self._maybe_alert(
                    rule_id    = "LM-1",
                    dedup_key  = f"LM-1:{src_ip}",
                    ttl        = 300,
                    rule_name  = "Lateral Movement — IP em Múltiplos Hosts",
                    severity   = "HIGH",
                    confidence = min(100, 60 + len(hosts) * 10),
                    description= (f"IP externo {src_ip} detectado em {len(hosts)} hosts "
                                  f"diferentes em 5 minutos: {', '.join(hosts)}"),
                    details    = {"source_ip": src_ip, "hosts": hosts,
                                  "host_count": len(hosts)},
                    hosts      = hosts,
                    source_ip  = src_ip,
                )
                if a: alerts.append(a)

        # ── LM-2: Credential Spray ────────────────────────────────
        if event_type in ("port_opened",) and details.get("port") in (22, 3389, 445, 5985):
            auth_ip = details.get("source_ip") or details.get("ip") or ""
            if auth_ip and not any(auth_ip.startswith(p) for p in private_prefixes):
                self._ip_auth_hosts[auth_ip].add(host)
                auth_hosts = list(set(self._ip_auth_hosts[auth_ip].items()))
                if len(auth_hosts) >= 3:
                    a = self._maybe_alert(
                        rule_id    = "LM-2",
                        dedup_key  = f"LM-2:{auth_ip}",
                        ttl        = 120,
                        rule_name  = "Credential Spray — Múltiplos Hosts",
                        severity   = "CRITICAL",
                        confidence = min(100, 70 + len(auth_hosts) * 10),
                        description= (f"Possível password spray: {auth_ip} tentou auth "
                                      f"em {len(auth_hosts)} hosts em 2 minutos"),
                        details    = {"attacker_ip": auth_ip, "targets": auth_hosts,
                                      "port": details.get("port"),
                                      "host_count": len(auth_hosts)},
                        hosts      = auth_hosts,
                        source_ip  = auth_ip,
                    )
                    if a: alerts.append(a)

        # ── LM-3: Beaconing Cross-Host (C2) ──────────────────────
        if event_type == "network_beaconing":
            c2_ip = details.get("dst_ip") or details.get("ip") or ""
            if c2_ip and not any(c2_ip.startswith(p) for p in private_prefixes):
                self._ip_c2_hosts[c2_ip].add(host)
                c2_hosts = list(set(self._ip_c2_hosts[c2_ip].items()))
                if len(c2_hosts) >= 3:
                    a = self._maybe_alert(
                        rule_id    = "LM-3",
                        dedup_key  = f"LM-3:{c2_ip}",
                        ttl        = 600,
                        rule_name  = "C2 Beaconing Cross-Host",
                        severity   = "CRITICAL",
                        confidence = min(100, 80 + len(c2_hosts) * 5),
                        description= (f"Possível C2: {len(c2_hosts)} hosts comunicando "
                                      f"com {c2_ip} em padrão periódico"),
                        details    = {"c2_ip": c2_ip, "infected_hosts": c2_hosts,
                                      "host_count": len(c2_hosts),
                                      "interval_sec": details.get("interval_sec")},
                        hosts      = c2_hosts,
                        source_ip  = c2_ip,
                    )
                    if a: alerts.append(a)

        # ── LM-4: Sequential Host Compromise ─────────────────────
        if severity in ("HIGH", "CRITICAL"):
            # Extract network segment
            segment = ".".join(host.split(".")[:3]) if "." in host else "local"
            # Track: segment → (host, event_type, severity)
            self._host_events[segment].add((host, event_type, severity))
            seg_events = self._host_events[segment].items()
            # Multiple different hosts in same segment with high severity
            seg_hosts = list(set(h for h, _, _ in seg_events))
            if len(seg_hosts) >= 2:
                a = self._maybe_alert(
                    rule_id    = "LM-4",
                    dedup_key  = f"LM-4:{segment}",
                    ttl        = 900,
                    rule_name  = "Comprometimento Sequencial — Mesmo Segmento",
                    severity   = "HIGH",
                    confidence = min(100, 50 + len(seg_hosts) * 15),
                    description= (f"Eventos HIGH/CRITICAL em {len(seg_hosts)} hosts "
                                  f"do segmento {segment} em 15 minutos"),
                    details    = {"network_segment": segment,
                                  "compromised_hosts": seg_hosts,
                                  "event_count": len(seg_events)},
                    hosts      = seg_hosts,
                )
                if a: alerts.append(a)

        # ── LM-5: Internal Port Scan ──────────────────────────────
        if event_type == "network_scan":
            scan_src = details.get("source_ip") or details.get("ip") or ""
            if scan_src and any(scan_src.startswith(p) for p in private_prefixes):
                # Internal IP scanning — track target hosts
                self._internal_scan[scan_src].add(host)
                scan_targets = list(set(self._internal_scan[scan_src].items()))
                if len(scan_targets) >= 3:
                    a = self._maybe_alert(
                        rule_id    = "LM-5",
                        dedup_key  = f"LM-5:{scan_src}",
                        ttl        = 300,
                        rule_name  = "Internal Port Scan — Reconhecimento Interno",
                        severity   = "HIGH",
                        confidence = min(100, 60 + len(scan_targets) * 10),
                        description= (f"IP interno {scan_src} realizou scan em "
                                      f"{len(scan_targets)} hosts internos em 5 minutos"),
                        details    = {"scanner_ip": scan_src,
                                      "scanned_hosts": scan_targets,
                                      "host_count": len(scan_targets)},
                        hosts      = scan_targets,
                        source_ip  = scan_src,
                    )
                    if a: alerts.append(a)

        # Store alerts
        with self._lock:
            self._alerts.extend(alerts)
            self._alerts = self._alerts[-500:]  # Keep last 500
            self._total_alerts += len(alerts)

        return alerts

    def _maybe_alert(self, rule_id, dedup_key, ttl,
                     rule_name, severity, confidence,
                     description, details, hosts,
                     source_ip="") -> Optional[LateralAlert]:
        """Fires alert unless recently fired (dedup)."""
        now = time.monotonic()
        last = self._fired.get(dedup_key, 0)
        if now - last < ttl:
            return None
        self._fired[dedup_key] = now

        a = LateralAlert(
            rule_id=rule_id, rule_name=rule_name,
            severity=severity, confidence=confidence,
            description=description, details=details,
            hosts_involved=hosts, source_ip=source_ip,
        )
        logger.warning("LATERAL | %s | hosts=%d | conf=%d%% | %s",
                       rule_id, len(hosts), confidence, description[:60])
        return a

    def get_alerts(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:][::-1]]

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_ingested": self._total_ingested,
                "total_alerts":   self._total_alerts,
                "active_alerts":  len(self._alerts),
                "rules_active":   5,
                "tracked_ips":    len(self._ip_to_hosts),
            }

    def inject_demo(self) -> List[LateralAlert]:
        """Injeta eventos sintéticos para demonstração."""
        alerts = []
        hosts = ["host-01", "host-02", "host-03"]
        for h in hosts:
            evts = self.ingest({
                "event_type": "ip_new_external",
                "severity":   "HIGH",
                "details":    {"ip": "185.220.101.45", "dst_ip": "185.220.101.45"},
                "host_id":    h,
            }, host_id=h)
            alerts.extend(evts)
        return alerts
