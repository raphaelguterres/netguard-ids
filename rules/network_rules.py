"""
NetGuard — Network Detection Rules
Pack completo de regras de detecção de rede.
"""

import re
import time
import math
import logging
from collections import defaultdict, deque
from typing import Optional, List  # noqa: F401
from models.event_model import make_event, Severity, EventType

logger = logging.getLogger("netguard.rules.network")

COMMON_PORTS = {
    22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,
    8080,8443,8888,135,137,138,139,445,1433,3389,5985,5986,
    1024,3000,4000,5000,5001,8000,8001,9000,27015,27017,
    49152,49153,49154,49155,6040,6463,6600,7680,27036,
}

PRIVATE_PREFIXES = (
    "192.168.","10.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
    "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
    "127.","0.0.0.0","::1","169.254.",
)

# Domínios de C2 conhecidos / suspeitos (padrões)
SUSPICIOUS_DNS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"[a-z0-9]{20,}\.(com|net|io|xyz|top|club)$",  # DGA-like
        r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",             # IP em hostname
        r"(onion|i2p|tor2web)",                           # dark web
        r"(ngrok|serveo|pagekite|localtunnel)",           # tunnel services
        r"(pastebin|ghostbin|hastebin)",                  # paste sites
        r"(dyndns|no-ip|afraid\.org|ddns)",              # dynamic DNS
        r"(temp-mail|guerrillamail|mailinator)",          # temp email
    ]
]


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


class NetworkRules:
    def __init__(self, repository=None):
        self.repo = repository
        self._conn_times    = defaultdict(lambda: deque(maxlen=500))
        self._proc_ips      = defaultdict(lambda: deque(maxlen=200))
        self._known_listen  : set = set()
        self._known_proc_ports = defaultdict(set)
        self._alerted_ips   : set = set()
        self._alerted_ports : set = set()

        # Beaconing detection: ip → list of timestamps
        self._beacon_times  = defaultdict(list)
        self._beacon_checked: set = set()

    # ── N-R1: Spike de conexões ───────────────────────────────────
    def detect_connection_spike(self, connections: list, threshold: int = 50,
                                window: int = 10) -> List:
        events = []
        now = time.time()
        by_src = defaultdict(list)
        for conn in connections:
            dst = conn.get("dst_ip","")
            if dst and not is_private(dst):
                by_src[dst].append(now)

        for ip, times in by_src.items():
            self._conn_times[ip].extend(times)
            recent = [t for t in self._conn_times[ip] if now - t <= window]
            if len(recent) >= threshold:
                events.append(make_event(
                    event_type      = EventType.NETWORK_SPIKE,
                    severity        = Severity.HIGH,
                    source          = "agent.network",
                    details         = {"dst_ip": ip, "count": len(recent),
                                       "window_sec": window},
                    rule_id         = "N-R1",
                    rule_name       = "Spike de Conexões",
                    mitre_tactic    = "reconnaissance",
                    mitre_technique = "T1046",
                    tags            = ["network","spike","scan"],
                ))
                self._conn_times[ip].clear()
        return events

    # ── N-R2: Muitos IPs únicos (scan / worm) ────────────────────
    def detect_multi_ip(self, connections: list, threshold: int = 20,
                        window: int = 30) -> List:
        events = []
        now = time.time()
        by_proc = defaultdict(list)
        for conn in connections:
            dst  = conn.get("dst_ip","")
            proc = conn.get("process","").lower()
            if dst and proc and not is_private(dst):
                by_proc[proc].append((now, dst))

        for proc, entries in by_proc.items():
            self._proc_ips[proc].extend(entries)
            recent_ips = {ip for t,ip in self._proc_ips[proc] if now-t <= window}
            if len(recent_ips) >= threshold:
                events.append(make_event(
                    event_type      = EventType.NETWORK_SCAN,
                    severity        = Severity.HIGH,
                    source          = "agent.network",
                    details         = {"process": proc, "unique_ips": len(recent_ips),
                                       "sample": list(recent_ips)[:5]},
                    rule_id         = "N-R2",
                    rule_name       = "Múltiplos IPs — Bot/Worm",
                    mitre_tactic    = "discovery",
                    mitre_technique = "T1046",
                    tags            = ["network","scan","worm"],
                ))
                self._proc_ips[proc].clear()
        return events

    # ── N-R3: Porta incomum em LISTEN ────────────────────────────
    def detect_new_listen_port(self, ports: list, baseline_ports: set) -> List:
        events = []
        for port_info in ports:
            port  = int(port_info.get("port") or 0)
            proto = port_info.get("proto","tcp")
            proc  = (port_info.get("process") or "").lower()
            key   = f"{proto}/{port}"
            if not port or port in COMMON_PORTS: continue
            if key in self._known_listen or key in baseline_ports: continue
            if key in self._alerted_ports: continue
            events.append(make_event(
                event_type      = EventType.PORT_NEW_LISTEN,
                severity        = Severity.MEDIUM,
                source          = "agent.network",
                details         = {"port": port, "proto": proto, "process": proc},
                rule_id         = "N-R3",
                rule_name       = "Nova Porta em LISTEN",
                mitre_tactic    = "persistence",
                mitre_technique = "T1205",
                tags            = ["network","listen","port"],
            ))
            self._known_listen.add(key)
            self._alerted_ports.add(key)
        return events

    # ── N-R4: Novo IP externo ─────────────────────────────────────
    def detect_new_external_ip(self, connections: list, baseline_ips: set) -> List:
        events = []
        seen = set()
        for conn in connections:
            ip   = conn.get("dst_ip","")
            proc = conn.get("process","")
            if not ip or is_private(ip): continue
            if ip in baseline_ips or ip in seen or ip in self._alerted_ips: continue
            events.append(make_event(
                event_type      = EventType.IP_NEW_EXTERNAL,
                severity        = Severity.LOW,
                source          = "agent.network",
                details         = {"ip": ip, "process": proc},
                rule_id         = "N-R4",
                rule_name       = "Novo IP Externo",
                mitre_tactic    = "reconnaissance",
                mitre_technique = "T1590",
                tags            = ["network","ip","baseline"],
            ))
            seen.add(ip)
            self._alerted_ips.add(ip)
        return events

    # ── N-R5: Beaconing pattern ───────────────────────────────────
    def detect_beaconing(self, connections: list, min_samples: int = 5,
                         jitter_threshold: float = 0.15) -> List:
        """
        Detecta padrão de beaconing: processo conectando no mesmo IP
        em intervalos regulares (baixo coeficiente de variação).
        """
        events = []
        now = time.time()
        by_pair = defaultdict(list)
        for conn in connections:
            ip   = conn.get("dst_ip","")
            proc = conn.get("process","").lower()
            if ip and proc and not is_private(ip):
                by_pair[f"{proc}→{ip}"].append(now)

        for pair, times in by_pair.items():
            self._beacon_times[pair].extend(times)
            # Keep last 20 samples
            self._beacon_times[pair] = self._beacon_times[pair][-20:]
            ts_list = sorted(self._beacon_times[pair])
            if len(ts_list) < min_samples: continue
            if pair in self._beacon_checked: continue

            intervals = [ts_list[i+1]-ts_list[i] for i in range(len(ts_list)-1)]
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 5: continue  # muito rápido não é beacon
            variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
            cv = math.sqrt(variance) / mean_interval if mean_interval > 0 else 1
            if cv < jitter_threshold:
                proc, ip = pair.split("→")
                self._beacon_checked.add(pair)
                events.append(make_event(
                    event_type      = "network_beaconing",
                    severity        = Severity.HIGH,
                    source          = "agent.network",
                    details         = {"process": proc, "dst_ip": ip,
                                       "interval_sec": round(mean_interval, 1),
                                       "jitter_cv": round(cv, 3),
                                       "samples": len(ts_list)},
                    rule_id         = "N-R5",
                    rule_name       = "Padrão de Beaconing Detectado",
                    mitre_tactic    = "command_and_control",
                    mitre_technique = "T1071.001",
                    tags            = ["network","c2","beaconing"],
                ))
        return events

    # ── N-R6: DNS suspeito ────────────────────────────────────────
    def detect_suspicious_dns(self, dns_queries: list) -> List:
        events = []
        for query in dns_queries:
            domain = (query.get("domain") or query.get("name") or "").lower()
            if not domain: continue
            for pattern in SUSPICIOUS_DNS_PATTERNS:
                if pattern.search(domain):
                    key = f"dns:{domain}"
                    if key in self._alerted_ips: continue
                    self._alerted_ips.add(key)
                    events.append(make_event(
                        event_type      = "dns_suspicious",
                        severity        = Severity.HIGH,
                        source          = "agent.network",
                        details         = {"domain": domain,
                                           "process": query.get("process",""),
                                           "pattern": pattern.pattern},
                        rule_id         = "N-R6",
                        rule_name       = "Consulta DNS Suspeita",
                        mitre_tactic    = "command_and_control",
                        mitre_technique = "T1071.004",
                        tags            = ["network","dns","c2"],
                    ))
                    break
        return events

    def analyze(self, connections: list, ports: list,
                baseline_ports: set, baseline_ips: set,
                dns_queries: list = None) -> List:
        events = []
        events.extend(self.detect_connection_spike(connections))
        events.extend(self.detect_multi_ip(connections))
        events.extend(self.detect_new_listen_port(ports, baseline_ports))
        events.extend(self.detect_new_external_ip(connections, baseline_ips))
        events.extend(self.detect_beaconing(connections))
        if dns_queries:
            events.extend(self.detect_suspicious_dns(dns_queries))
        return events
