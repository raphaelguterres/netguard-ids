"""
NetGuard — Correlation Engine
Detecta padrões de ataque complexos correlacionando eventos ao longo do tempo.

Conceito: igual ao Elastic SIEM Correlation Rules / Splunk ES Correlation Searches.
Cada regra de correlação observa uma janela de tempo e dispara quando
um padrão multi-evento é detectado.

Padrões implementados:
  COR-1  Execução Suspeita        processo desconhecido + CPU alta + conn externa
  COR-2  Reconhecimento           novo IP + porta scan + DNS suspeito
  COR-3  C2 Beaconing             conexões regulares para mesmo IP externo
  COR-4  Lateral Movement         processo acessando múltiplos IPs internos
  COR-5  Brute Force              muitas tentativas de auth em curto período
"""

import time
import threading
import logging
import math  # noqa: F401
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable

logger = logging.getLogger("netguard.correlation")


# ── Correlation Alert ─────────────────────────────────────────────
@dataclass
class CorrelationAlert:
    rule_id:      str
    rule_name:    str
    severity:     str
    confidence:   int          # 0-100
    host_id:      str
    description:  str
    evidence:     List[dict]   # eventos que dispararam
    mitre_tactic: str
    mitre_tech:   str
    tags:         List[str]
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pattern_key:  str = ""     # chave única para deduplicação

    def to_dict(self) -> dict:
        return {
            "id":           f"{self.rule_id}-{self.timestamp[:19]}",
            "rule_id":      self.rule_id,
            "rule_name":    self.rule_name,
            "severity":     self.severity,
            "confidence":   self.confidence,
            "host_id":      self.host_id,
            "description":  self.description,
            "evidence":     self.evidence[:5],
            "evidence_count": len(self.evidence),
            "mitre": {
                "tactic":    self.mitre_tactic,
                "technique": self.mitre_tech,
            },
            "tags":         self.tags,
            "timestamp":    self.timestamp,
            "type":         "CORRELATION",
        }


# ── Event window: sliding window por host/chave ──────────────────
class EventWindow:
    """Janela deslizante de eventos por chave."""
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self._data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._lock = threading.RLock()

    def add(self, key: str, event: dict):
        with self._lock:
            self._data[key].append((time.time(), event))

    def get_recent(self, key: str, seconds: int = None) -> List[dict]:
        w = seconds or self.window
        cutoff = time.time() - w
        with self._lock:
            return [e for ts, e in self._data[key] if ts > cutoff]

    def get_keys(self) -> List[str]:
        with self._lock:
            return list(self._data.keys())

    def count(self, key: str, seconds: int = None) -> int:
        return len(self.get_recent(key, seconds))

    def clear_old(self):
        cutoff = time.time() - self.window * 2
        with self._lock:
            for key in list(self._data.keys()):
                while self._data[key] and self._data[key][0][0] < cutoff:
                    self._data[key].popleft()


# ── Correlation Engine ────────────────────────────────────────────
class CorrelationEngine:
    """
    Motor de correlação de eventos.
    Recebe eventos do SOC Engine e detecta padrões multi-evento.
    """

    def __init__(self, host_id: str = "netguard-host",
                 callback: Optional[Callable] = None):
        self.host_id  = host_id
        self.callback = callback
        self._lock    = threading.RLock()

        # Janelas de eventos por tipo
        self._proc_events   = EventWindow(600)   # 10 min
        self._net_events    = EventWindow(300)   # 5 min
        self._auth_events   = EventWindow(120)   # 2 min
        self._all_events    = EventWindow(900)   # 15 min

        # Estado interno das regras
        self._suspicious_procs:  Dict[str, float] = {}   # proc → ts first seen
        self._high_cpu_procs:    Dict[str, float] = {}
        self._external_procs:    Dict[str, float] = {}
        self._new_ips:           Dict[str, float] = {}
        self._beacon_tracking:   Dict[str, list]  = defaultdict(list)
        self._internal_reach:    Dict[str, set]   = defaultdict(set)
        self._auth_attempts:     Dict[str, list]  = defaultdict(list)

        # Correlações já disparadas (dedup com TTL)
        self._fired: Dict[str, float] = {}  # pattern_key → ts
        self._fired_ttl = 300  # não repete a mesma correlação por 5 min

        # Histórico de alertas
        self._alerts: deque = deque(maxlen=500)

        logger.info("CorrelationEngine iniciado | host=%s", host_id)

    # ── Ingest ───────────────────────────────────────────────────

    def ingest(self, event: dict) -> List[CorrelationAlert]:
        """
        Ingere um evento SOC e retorna correlações detectadas.
        Chamado a cada evento gerado pelo SOC Engine.
        """
        et      = (event.get("event_type") or "").lower()
        sev     = (event.get("severity")   or "LOW").upper()
        details = event.get("details") or {}
        # Normaliza host_id — substitui valores inválidos pelo host do engine
        raw_host = event.get("host_id") or ""
        host = raw_host if raw_host and raw_host.lower() not in ("new","localhost","")                else self.host_id
        now     = time.time()

        # Indexa nas janelas certas
        self._all_events.add(host, event)

        if "process" in et or "powershell" in et or "shell" in et:
            self._proc_events.add(host, event)
        if "network" in et or "port" in et or "ip" in et or "conn" in et or "beacon" in et or "dns" in et:
            self._net_events.add(host, event)
        if "auth" in et or "brute" in et or "login" in et or "fail" in et:
            self._auth_events.add(host, event)

        # Atualiza rastreadores internos
        self._update_trackers(et, sev, details, host, now)

        # Roda regras de correlação
        alerts = []
        for rule_fn in [
            self._rule_suspicious_execution,
            self._rule_recon_pattern,
            self._rule_c2_beaconing,
            self._rule_lateral_movement,
            self._rule_brute_force,
        ]:
            try:
                alert = rule_fn(host, now)
                if alert and self._should_fire(alert):
                    self._alerts.append(alert)
                    self._fired[alert.pattern_key] = now
                    alerts.append(alert)
                    logger.warning(
                        "CORRELATION | %s | host=%s | conf=%d%% | %s",
                        alert.rule_id, host, alert.confidence, alert.rule_name
                    )
                    if self.callback:
                        try: self.callback(alert.to_dict())
                        except Exception: pass
            except Exception as e:
                logger.debug("Correlation rule error: %s", e)

        # Cleanup periódico
        if now % 60 < 2:
            self._cleanup(now)

        return alerts

    def ingest_batch(self, events: List[dict]) -> List[CorrelationAlert]:
        all_alerts = []
        for e in events:
            all_alerts.extend(self.ingest(e))
        return all_alerts

    # ── Rastreadores ─────────────────────────────────────────────

    def _update_trackers(self, et: str, sev: str, details: dict,
                         host: str, now: float):
        proc = (details.get("process") or details.get("process_name") or "").lower()
        ip   = details.get("dst_ip") or details.get("ip") or ""

        # Processo suspeito/desconhecido
        if et in ("process_unknown", "process_suspicious_path", "shell_spawned_from_office"):
            if proc:
                self._suspicious_procs[proc] = now

        # CPU alta
        if et == "process_high_cpu" and proc:
            self._high_cpu_procs[proc] = now

        # Conexão externa
        if et in ("ip_new_external", "process_external_conn") and proc:
            self._external_procs[proc] = now

        # Novo IP
        if et == "ip_new_external" and ip:
            self._new_ips[ip] = now

        # Beaconing
        if et == "network_beaconing" and ip:
            self._beacon_tracking[ip].append(now)

        # IPs internos alcançados por processo
        if ip and not self._is_private(ip) is False:
            if self._is_internal(ip) and proc:
                self._internal_reach[proc].add(ip)

        # Auth attempts
        if et in ("auth_failure", "brute_force", "login_failed", "port_opened") and ip:
            self._auth_attempts[ip].append(now)

    # ── COR-1: Execução Suspeita ─────────────────────────────────
    def _rule_suspicious_execution(self, host: str, now: float) -> Optional[CorrelationAlert]:
        """
        Processo desconhecido + CPU alta + conexão externa
        em janela de 10 minutos → execução de malware/RAT
        """
        window = 600
        matches = []

        for proc in list(self._suspicious_procs.keys()):
            ts_susp = self._suspicious_procs.get(proc, 0)
            ts_cpu  = self._high_cpu_procs.get(proc, 0)
            ts_ext  = self._external_procs.get(proc, 0)

            if not ts_susp: continue

            # Precisa pelo menos 2 dos 3 sinais dentro da janela
            signals = sum([
                now - ts_susp < window,
                now - ts_cpu  < window if ts_cpu else False,
                now - ts_ext  < window if ts_ext else False,
            ])
            if signals < 2: continue

            # Constrói evidência
            evidence = []
            recent = self._proc_events.get_recent(host, window)
            for e in recent:
                p = (e.get("details",{}).get("process") or
                     e.get("details",{}).get("process_name","")).lower()
                if p == proc:
                    evidence.append({
                        "event_type": e.get("event_type"),
                        "severity":   e.get("severity"),
                        "detail":     proc,
                    })

            confidence = 60 + (signals * 15)
            sev = "CRITICAL" if confidence >= 85 else "HIGH"
            matches.append((proc, signals, confidence, sev, evidence))

        if not matches:
            return None

        proc, signals, confidence, sev, evidence = max(matches, key=lambda x: x[2])
        return CorrelationAlert(
            rule_id      = "COR-1",
            rule_name    = "Execução Suspeita — Possível Malware/RAT",
            severity     = sev,
            confidence   = confidence,
            host_id      = host,
            description  = (f"Processo '{proc}' detectado como desconhecido"
                            f"{', com CPU alta' if self._high_cpu_procs.get(proc) else ''}"
                            f"{', fazendo conexões externas' if self._external_procs.get(proc) else ''}."
                            f" {signals}/3 sinais de comprometimento."),
            evidence     = evidence,
            mitre_tactic = "execution",
            mitre_tech   = "T1059",
            tags         = ["correlation","malware","rat","execution"],
            pattern_key  = f"COR-1:{host}:{proc}:{int(now//300)}",
        )

    # ── COR-2: Reconhecimento ────────────────────────────────────
    def _rule_recon_pattern(self, host: str, now: float) -> Optional[CorrelationAlert]:
        """
        Novo IP + scan de portas + DNS suspeito em 5 minutos
        → reconhecimento ativo
        """
        window = 300
        recent = self._net_events.get_recent(host, window)

        new_ips    = [e for e in recent if e.get("event_type") == "ip_new_external"]
        port_scans = [e for e in recent if e.get("event_type") in
                      ("network_scan", "port_new_listen", "port_opened")]
        dns_susp   = [e for e in recent if e.get("event_type") == "dns_suspicious"]

        signals = sum([
            len(new_ips)    >= 3,
            len(port_scans) >= 2,
            len(dns_susp)   >= 1,
        ])
        if signals < 2:
            return None

        confidence = 50 + (signals * 15) + min(len(new_ips) * 3, 15)
        evidence = (
            [{"event_type": e.get("event_type"), "detail": e.get("details",{}).get("ip","")}
             for e in new_ips[:3]] +
            [{"event_type": e.get("event_type"), "detail": str(e.get("details",{}).get("port",""))}
             for e in port_scans[:2]] +
            [{"event_type": e.get("event_type"), "detail": e.get("details",{}).get("domain","")}
             for e in dns_susp[:2]]
        )

        return CorrelationAlert(
            rule_id      = "COR-2",
            rule_name    = "Reconhecimento Ativo Detectado",
            severity     = "HIGH",
            confidence   = min(confidence, 100),
            host_id      = host,
            description  = (f"{len(new_ips)} novos IPs externos, "
                            f"{len(port_scans)} eventos de porta, "
                            f"{len(dns_susp)} DNS suspeito(s) nos últimos 5 minutos."),
            evidence     = evidence,
            mitre_tactic = "reconnaissance",
            mitre_tech   = "T1595",
            tags         = ["correlation","recon","scan","discovery"],
            pattern_key  = f"COR-2:{host}",
        )

    # ── COR-3: C2 Beaconing ──────────────────────────────────────
    def _rule_c2_beaconing(self, host: str, now: float) -> Optional[CorrelationAlert]:
        """
        Conexões periódicas para mesmo IP externo com baixo jitter
        → possível canal C2
        """
        window = 900  # 15 min
        recent = self._net_events.get_recent(host, window)

        # Agrupa por IP destino
        by_ip: Dict[str, list] = defaultdict(list)
        for e in recent:
            et = e.get("event_type","")
            if et in ("ip_new_external", "network_beaconing", "process_external_conn"):
                ip = (e.get("details",{}).get("ip") or
                      e.get("details",{}).get("dst_ip",""))
                if ip and not self._is_private(ip):
                    by_ip[ip].append(e)

        # Procura beaconing
        beacon_ip   = None
        beacon_ev   = []
        beacon_conf = 0

        for ip, events in by_ip.items():
            # Beaconing explícito
            if any(e.get("event_type") == "network_beaconing" for e in events):
                conf = 90
                if conf > beacon_conf:
                    beacon_ip, beacon_ev, beacon_conf = ip, events, conf
                continue

            # Beaconing implícito: mesmo processo + mesmo IP, 5+ vezes
            if len(events) >= 5:
                procs = {(e.get("details",{}).get("process","")) for e in events}
                if len(procs) == 1:  # mesmo processo
                    conf = min(70 + len(events) * 2, 100)
                    if conf > beacon_conf:
                        beacon_ip, beacon_ev, beacon_conf = ip, events, conf

        if not beacon_ip:
            return None

        proc = (beacon_ev[0].get("details",{}).get("process","") if beacon_ev else "")
        return CorrelationAlert(
            rule_id      = "COR-3",
            rule_name    = "C2 Beaconing — Canal de Comando Suspeito",
            severity     = "CRITICAL" if beacon_conf >= 85 else "HIGH",
            confidence   = beacon_conf,
            host_id      = host,
            description  = (f"Processo '{proc}' fazendo conexões periódicas para "
                            f"{beacon_ip} ({len(beacon_ev)}x em 15min). "
                            f"Padrão consistente com canal C2."),
            evidence     = [{"event_type": e.get("event_type"),
                             "detail": beacon_ip,
                             "process": e.get("details",{}).get("process","")}
                            for e in beacon_ev[:5]],
            mitre_tactic = "command_and_control",
            mitre_tech   = "T1071.001",
            tags         = ["correlation","c2","beaconing","apt"],
            pattern_key  = f"COR-3:{host}:{beacon_ip}:{proc}",
        )

    # ── COR-4: Lateral Movement ──────────────────────────────────
    def _rule_lateral_movement(self, host: str, now: float) -> Optional[CorrelationAlert]:
        """
        Processo acessando múltiplos IPs internos em sequência
        → movimento lateral na rede
        """
        window = 300
        recent = self._net_events.get_recent(host, window)

        # Agrupar por processo → IPs internos
        proc_internal: Dict[str, set] = defaultdict(set)
        for e in recent:
            ip   = (e.get("details",{}).get("dst_ip") or
                    e.get("details",{}).get("ip",""))
            proc = (e.get("details",{}).get("process","")).lower()
            if ip and proc and self._is_internal(ip):
                proc_internal[proc].add(ip)

        # Também verifica rastreador persistente
        for proc, ips in self._internal_reach.items():
            proc_internal[proc].update(ips)

        # Filtra: processo suspeito acessando 3+ IPs internos
        candidates = {
            proc: ips for proc, ips in proc_internal.items()
            if len(ips) >= 3
        }
        if not candidates:
            return None

        # Prioriza processos que também são suspeitos
        best_proc = max(
            candidates,
            key=lambda p: len(candidates[p]) + (5 if p in self._suspicious_procs else 0)
        )
        ips = candidates[best_proc]
        is_susp = best_proc in self._suspicious_procs
        confidence = min(55 + len(ips) * 8 + (20 if is_susp else 0), 100)

        return CorrelationAlert(
            rule_id      = "COR-4",
            rule_name    = "Movimento Lateral Detectado",
            severity     = "CRITICAL" if is_susp else "HIGH",
            confidence   = confidence,
            host_id      = host,
            description  = (f"Processo '{best_proc}' acessou {len(ips)} IPs internos "
                            f"em menos de 5 minutos: {', '.join(list(ips)[:4])}. "
                            f"{'Processo marcado como suspeito.' if is_susp else ''}"),
            evidence     = [{"event_type": "internal_connection",
                             "detail": ip, "process": best_proc}
                            for ip in list(ips)[:5]],
            mitre_tactic = "lateral_movement",
            mitre_tech   = "T1021",
            tags         = ["correlation","lateral","movement","network"],
            pattern_key  = f"COR-4:{host}:{best_proc}:{len(ips)}",
        )

    # ── COR-5: Brute Force ───────────────────────────────────────
    def _rule_brute_force(self, host: str, now: float) -> Optional[CorrelationAlert]:
        """
        Muitas tentativas de auth / conexões para porta 22/3389/445
        vindo do mesmo IP em curto período
        """
        window = 120  # 2 minutos
        recent = self._net_events.get_recent(host, window)

        # Conta conexões por IP origem para portas de autenticação
        auth_ports = {22, 3389, 445, 1433, 5985, 23, 21}
        by_src: Dict[str, list] = defaultdict(list)

        for e in recent:
            port  = int(e.get("details",{}).get("port") or
                        e.get("details",{}).get("dst_port") or 0)
            src   = (e.get("details",{}).get("source_ip") or
                     e.get("details",{}).get("src_ip") or
                     e.get("details",{}).get("ip",""))
            if port in auth_ports and src and not self._is_internal(src):
                by_src[src].append(e)

        # Também verifica histórico de auth_attempts
        for src, times in self._auth_attempts.items():
            recent_times = [t for t in times if now - t < window]
            if len(recent_times) >= 5:
                by_src[src].extend([{"synthetic": True}] * len(recent_times))

        candidates = {src: evs for src, evs in by_src.items() if len(evs) >= 5}
        if not candidates:
            return None

        worst_src = max(candidates, key=lambda s: len(candidates[s]))
        count      = len(candidates[worst_src])
        confidence = min(60 + count * 3, 100)

        return CorrelationAlert(
            rule_id      = "COR-5",
            rule_name    = "Brute Force Detectado",
            severity     = "HIGH",
            confidence   = confidence,
            host_id      = host,
            description  = (f"{count} tentativas de conexão em portas de autenticação "
                            f"originadas de {worst_src} nos últimos 2 minutos. "
                            f"Possível ataque de força bruta."),
            evidence     = [{"event_type": "auth_attempt",
                             "detail": worst_src, "count": count}],
            mitre_tactic = "credential_access",
            mitre_tech   = "T1110",
            tags         = ["correlation","brute_force","auth","credential"],
            pattern_key  = f"COR-5:{host}:{worst_src}:{int(now//120)}",
        )

    # ── Helpers ──────────────────────────────────────────────────

    def _should_fire(self, alert: CorrelationAlert) -> bool:
        key = alert.pattern_key
        last = self._fired.get(key, 0)
        return (time.time() - last) > self._fired_ttl

    @staticmethod
    def _is_private(ip: str) -> bool:
        return any(ip.startswith(p) for p in (
            "192.168.","10.","172.16.","172.17.","172.18.","172.19.",
            "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
            "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
            "127.","0.","::1",
        ))

    @staticmethod
    def _is_internal(ip: str) -> bool:
        return any(ip.startswith(p) for p in (
            "192.168.","10.","172.16.","172.17.","172.18.","172.19.",
            "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
            "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
        ))

    def _cleanup(self, now: float):
        ttl = self._fired_ttl
        self._fired = {k: v for k, v in self._fired.items() if now - v < ttl * 10}
        old = now - 600
        for d in [self._suspicious_procs, self._high_cpu_procs,
                  self._external_procs, self._new_ips]:
            for k in [k for k, v in d.items() if v < old]:
                del d[k]
        for src in list(self._auth_attempts.keys()):
            self._auth_attempts[src] = [t for t in self._auth_attempts[src] if now - t < 300]
        self._all_events.clear_old()
        self._net_events.clear_old()
        self._proc_events.clear_old()

    # ── Public API ────────────────────────────────────────────────

    def get_alerts(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in list(self._alerts)[-limit:][::-1]]

    def get_stats(self) -> dict:
        with self._lock:
            alerts = list(self._alerts)
            by_rule = defaultdict(int)
            by_sev  = defaultdict(int)
            for a in alerts:
                by_rule[a.rule_id] += 1
                by_sev[a.severity] += 1
            return {
                "total":         len(alerts),
                "by_rule":       dict(by_rule),
                "by_severity":   dict(by_sev),
                "rules_active":  5,
                "host_id":       self.host_id,
                "suspicious_procs": len(self._suspicious_procs),
                "tracked_beacons":  sum(1 for v in self._beacon_tracking.values() if v),
            }

    def inject_demo(self) -> List[CorrelationAlert]:
        """Injeta eventos de demonstração para testar as 5 regras."""
        now = time.time()
        demo_events = [
            # COR-1: Suspicious execution
            {"event_type": "process_unknown",      "severity": "MEDIUM", "host_id": self.host_id,
             "details": {"process": "update_helper.exe"}, "mitre_tactic": "execution"},
            {"event_type": "process_high_cpu",     "severity": "HIGH",   "host_id": self.host_id,
             "details": {"process": "update_helper.exe", "cpu_usage": 94}, "mitre_tactic": "execution"},
            {"event_type": "ip_new_external",      "severity": "LOW",    "host_id": self.host_id,
             "details": {"ip": "185.220.101.45", "process": "update_helper.exe"}, "mitre_tactic": "reconnaissance"},
            # COR-2: Recon
            {"event_type": "ip_new_external",      "severity": "LOW",    "host_id": self.host_id,
             "details": {"ip": "91.108.56.22"}, "mitre_tactic": "reconnaissance"},
            {"event_type": "ip_new_external",      "severity": "LOW",    "host_id": self.host_id,
             "details": {"ip": "185.220.101.47"}, "mitre_tactic": "reconnaissance"},
            {"event_type": "network_scan",         "severity": "HIGH",   "host_id": self.host_id,
             "details": {"unique_ips": 25, "process": "svchost.exe"}, "mitre_tactic": "discovery"},
            {"event_type": "dns_suspicious",       "severity": "HIGH",   "host_id": self.host_id,
             "details": {"domain": "abc123xyz987.ngrok.io"}, "mitre_tactic": "command_and_control"},
            # COR-3: Beaconing
            {"event_type": "network_beaconing",    "severity": "HIGH",   "host_id": self.host_id,
             "details": {"process": "update_helper.exe", "dst_ip": "185.220.101.45",
                         "interval_sec": 30.2, "jitter_cv": 0.04}, "mitre_tactic": "command_and_control"},
            # COR-5: Brute force
            *[{"event_type": "port_opened", "severity": "HIGH",   "host_id": self.host_id,
               "details": {"port": 3389, "source_ip": "45.152.84.57", "ip": "45.152.84.57"},
               "mitre_tactic": "credential_access"} for _ in range(8)],
        ]
        return self.ingest_batch(demo_events)


# ── Instância global ──────────────────────────────────────────────
correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine(host_id: str = "netguard-host",
                           callback=None) -> CorrelationEngine:
    global correlation_engine
    if correlation_engine is None:
        correlation_engine = CorrelationEngine(host_id=host_id, callback=callback)
    return correlation_engine
