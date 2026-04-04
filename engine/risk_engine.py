"""
NetGuard — Risk Engine
Risk Score por host estilo CrowdStrike / Microsoft Defender / Elastic.

Calcula score 0-100 por host baseado em:
- Severidade e quantidade de eventos recentes
- Táticas MITRE detectadas
- Progressão na Kill Chain
- Fatores de contexto (processo, rede, web)

Estrutura multi-host: cada host tem seu próprio score, baseline e histórico.
"""

import time
import threading
import logging
from datetime import datetime, timezone, timedelta  # noqa: F401
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("netguard.risk")

# ── Score weights por severidade ─────────────────────────────────
SEV_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     12,
    "MEDIUM":    5,
    "LOW":       1,
}

# ── Bonus por tática MITRE (progressão avançada = mais score) ────
TACTIC_BONUS = {
    "impact":               30,
    "exfiltration":         25,
    "command_and_control":  20,
    "lateral_movement":     18,
    "credential_access":    16,
    "privilege_escalation": 14,
    "defense_evasion":      12,
    "execution":            10,
    "persistence":           8,
    "discovery":             5,
    "initial_access":        5,
    "reconnaissance":        3,
}

# ── Decay: eventos antigos perdem peso ───────────────────────────
DECAY_HALF_LIFE_HOURS = 6  # score cai pela metade a cada 6h


@dataclass
class RiskFactor:
    category:    str
    description: str
    score:       int
    severity:    str
    timestamp:   str


@dataclass
class HostRiskProfile:
    """Perfil completo de risco de um host."""
    host_id:      str
    score:        int                   = 0
    risk_level:   str                   = "LOW"
    factors:      List[RiskFactor]      = field(default_factory=list)
    tactics:      List[str]             = field(default_factory=list)
    event_counts: Dict[str, int]        = field(default_factory=dict)
    last_updated: str                   = ""
    first_seen:   str                   = ""
    alert_count:  int                   = 0
    top_threats:  List[str]             = field(default_factory=list)

    @property
    def risk_color(self) -> str:
        return {"CRITICAL":"#ff1a4b","HIGH":"#ff8800",
                "MEDIUM":"#ffdd00","LOW":"#00ffaa"}.get(self.risk_level,"#00ffaa")

    def to_dict(self) -> dict:
        return {
            "host_id":      self.host_id,
            "score":        self.score,
            "risk_level":   self.risk_level,
            "risk_color":   self.risk_color,
            "factors":      [
                {"category": f.category, "description": f.description,
                 "score": f.score, "severity": f.severity}
                for f in self.factors[:10]
            ],
            "tactics":      self.tactics,
            "event_counts": self.event_counts,
            "last_updated": self.last_updated,
            "first_seen":   self.first_seen,
            "alert_count":  self.alert_count,
            "top_threats":  self.top_threats[:5],
        }


class RiskEngine:
    """
    Motor de Risk Score multi-host.
    Calcula e mantém score de risco para múltiplos hosts.
    Compatível com conceito de CrowdStrike Host Score e Elastic Risk Score.
    """

    def __init__(self, decay_enabled: bool = True):
        self._hosts:   Dict[str, HostRiskProfile] = {}
        self._events:  Dict[str, list]             = defaultdict(list)
        # host_id → list of (timestamp, event_dict)
        self._lock     = threading.RLock()
        self._decay    = decay_enabled
        logger.info("RiskEngine iniciado | decay=%s", decay_enabled)

    # ── Ingest event ─────────────────────────────────────────────

    def ingest_event(self, event: dict) -> int:
        """
        Ingere um evento e recalcula o risk score do host.
        Retorna o novo score.
        """
        host_id = event.get("host_id") or event.get("host") or "unknown"
        now     = datetime.now(timezone.utc).isoformat()

        with self._lock:
            # Cria perfil se não existe
            if host_id not in self._hosts:
                self._hosts[host_id] = HostRiskProfile(
                    host_id    = host_id,
                    first_seen = now,
                )

            # Armazena evento
            self._events[host_id].append((time.time(), event))
            # Mantém apenas últimas 24h
            cutoff = time.time() - 86400
            self._events[host_id] = [
                (ts, e) for ts, e in self._events[host_id] if ts > cutoff
            ]

            # Recalcula
            score = self._calculate_score(host_id)
            return score

    def ingest_batch(self, events: list) -> Dict[str, int]:
        """Ingere múltiplos eventos. Retorna dict host_id → novo score."""
        results = {}
        for event in events:
            host = event.get("host_id","unknown")
            results[host] = self.ingest_event(event)
        return results

    # ── Score calculation ─────────────────────────────────────────

    def _calculate_score(self, host_id: str) -> int:
        profile = self._hosts[host_id]
        events  = self._events.get(host_id, [])
        now     = time.time()

        raw_score    = 0
        factors      = []
        sev_counts   = defaultdict(int)
        tactic_set   = set()
        rule_names   = []

        for ts, event in events:
            sev     = (event.get("severity") or "LOW").upper()
            tactic  = (event.get("mitre_tactic") or
                       (event.get("mitre") or {}).get("tactic","")).lower()
            rule    = event.get("rule_name","")

            # Decay factor
            age_hours = (now - ts) / 3600
            if self._decay:
                decay = 0.5 ** (age_hours / DECAY_HALF_LIFE_HOURS)
            else:
                decay = 1.0

            # Base score from severity
            base   = SEV_WEIGHTS.get(sev, 1)
            bonus  = TACTIC_BONUS.get(tactic, 0)
            pts    = (base + bonus) * decay

            raw_score += pts
            sev_counts[sev] += 1

            if tactic:
                tactic_set.add(tactic)
            if rule and rule not in rule_names:
                rule_names.append(rule)

            # Create factor for HIGH/CRITICAL
            if sev in ("HIGH","CRITICAL"):
                factors.append(RiskFactor(
                    category    = tactic or "unknown",
                    description = rule or event.get("event_type",""),
                    score       = int(pts),
                    severity    = sev,
                    timestamp   = event.get("timestamp",""),
                ))

        # Kill chain bonus: more tactics = higher bonus
        kc_bonus = len(tactic_set) * 3
        raw_score += kc_bonus

        # Cap at 100
        final_score = min(100, int(raw_score))

        # Risk level
        if final_score >= 75:   level = "CRITICAL"
        elif final_score >= 50: level = "HIGH"
        elif final_score >= 25: level = "MEDIUM"
        else:                   level = "LOW"

        # Update profile
        profile.score        = final_score
        profile.risk_level   = level
        profile.factors      = sorted(factors, key=lambda f: f.score, reverse=True)[:10]
        profile.tactics      = sorted(tactic_set,
                                       key=lambda t: TACTIC_BONUS.get(t,0), reverse=True)
        profile.event_counts = dict(sev_counts)
        profile.last_updated = datetime.now(timezone.utc).isoformat()
        profile.alert_count  = len(events)
        profile.top_threats  = rule_names[:5]

        return final_score

    # ── Query API ─────────────────────────────────────────────────

    def get_host(self, host_id: str) -> Optional[dict]:
        with self._lock:
            p = self._hosts.get(host_id)
            return p.to_dict() if p else None

    def get_all_hosts(self) -> List[dict]:
        with self._lock:
            return sorted(
                [p.to_dict() for p in self._hosts.values()],
                key=lambda h: h["score"],
                reverse=True
            )

    def get_summary(self) -> dict:
        with self._lock:
            hosts = [p for p in self._hosts.values()]
            return {
                "total_hosts":    len(hosts),
                "critical_hosts": sum(1 for h in hosts if h.risk_level == "CRITICAL"),
                "high_hosts":     sum(1 for h in hosts if h.risk_level == "HIGH"),
                "medium_hosts":   sum(1 for h in hosts if h.risk_level == "MEDIUM"),
                "low_hosts":      sum(1 for h in hosts if h.risk_level == "LOW"),
                "max_score":      max((h.score for h in hosts), default=0),
                "avg_score":      round(sum(h.score for h in hosts) / max(len(hosts),1), 1),
                "timestamp":      datetime.now(timezone.utc).isoformat(),
            }

    def reset_host(self, host_id: str) -> bool:
        with self._lock:
            if host_id in self._hosts:
                del self._hosts[host_id]
                self._events.pop(host_id, None)
                return True
            return False

    def generate_report(self, host_id: str) -> dict:
        """Gera relatório completo de risco para um host."""
        with self._lock:
            profile = self._hosts.get(host_id)
            if not profile:
                return {"error": f"Host {host_id} não encontrado"}

            events = self._events.get(host_id, [])

            # Group by severity
            by_sev = defaultdict(list)
            for _, event in events:
                sev = (event.get("severity") or "LOW").upper()
                by_sev[sev].append({
                    "rule":      event.get("rule_name",""),
                    "type":      event.get("event_type",""),
                    "tactic":    (event.get("mitre") or {}).get("tactic",""),
                    "timestamp": event.get("timestamp",""),
                })

            return {
                "host_id":     host_id,
                "score":       profile.score,
                "risk_level":  profile.risk_level,
                "risk_color":  profile.risk_color,
                "summary":     self._generate_summary(profile),
                "by_severity": {
                    "CRITICAL": by_sev.get("CRITICAL",[]),
                    "HIGH":     by_sev.get("HIGH",[]),
                    "MEDIUM":   by_sev.get("MEDIUM",[]),
                    "LOW":      by_sev.get("LOW",[]),
                },
                "tactics":     profile.tactics,
                "top_threats": profile.top_threats,
                "event_counts": profile.event_counts,
                "first_seen":  profile.first_seen,
                "last_updated": profile.last_updated,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

    def _generate_summary(self, profile: HostRiskProfile) -> str:
        counts = profile.event_counts
        crit   = counts.get("CRITICAL", 0)
        high   = counts.get("HIGH", 0)
        med    = counts.get("MEDIUM", 0)
        total  = sum(counts.values())
        tactics_str = " → ".join(profile.tactics[:4]) if profile.tactics else "nenhuma"
        return (
            f"Host {profile.host_id} com score de risco {profile.score}/100 ({profile.risk_level}). "
            f"{total} eventos nas últimas 24h: {crit} CRITICAL, {high} HIGH, {med} MEDIUM. "
            f"Táticas MITRE: {tactics_str}."
        )


# ── Instância global ──────────────────────────────────────────────
risk_engine = RiskEngine(decay_enabled=True)
