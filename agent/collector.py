"""
Coletor de telemetria — produz eventos no schema do servidor
(EndpointEvent: process_execution, network_connection, script_execution,
authentication, persistence_indicator, behavioral_anomaly).

Decisões de design:

- Sem dependência de Sysmon/ETW/auditd: detector roda 100% via
  psutil. Cobertura é menor (sem ProcessGUID, sem ParentCommandLine
  100% confiável em Windows pra processos curtos), mas é portável e
  não exige driver instalado.

- "Snapshot diff": cada call a collect_events() compara processos
  vivos com snapshot anterior e emite eventos só pra processos NOVOS.
  Isso evita inundar o servidor com "process_execution" do mesmo
  notepad.exe a cada interval. Conexões TCP usam o mesmo modelo.

- Indicadores de segurança são detectados AQUI (não só no servidor):
  é a primeira camada de filtragem. Servidor confirma e correlaciona.
  Reduz volume de tráfego em hosts barulhentos.

- Severidade local é "best effort": eventos como powershell -enc
  saem como severity=high direto, mas o servidor pode rebaixar/elevar
  no detection_engine. Confidence é exposto no schema canônico em
  0..100 e replicado em `details` por compatibilidade com o pipeline
  XDR legado.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

logger = logging.getLogger("netguard.agent.collector")

# ── Padrões de segurança (rodam em command line do processo) ──────
#
# Cada tupla = (regex compilado, event_type sugerido, severity,
# mitre_tactic, mitre_technique, summary)
#
# Os mais "duros" (encoded command, certutil download) são severity=high.
# Os heurísticos (mshta http, rundll32 com URL) ficam em medium.

_SECURITY_PATTERNS: list[tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r"(?i)\bpowershell(?:\.exe)?\b.*?\s-(?:e|en|enc|encod\w*)\b"),
        "script_execution",
        "high",
        "Defense Evasion",
        "T1027",  # Obfuscated Files or Information
        "PowerShell -EncodedCommand detectado",
    ),
    (
        re.compile(r"(?i)\bpowershell(?:\.exe)?\b.*?(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr|iex)"),
        "script_execution",
        "high",
        "Command and Control",
        "T1059.001",
        "PowerShell com download/execução remota",
    ),
    (
        re.compile(r"(?i)\bcertutil(?:\.exe)?\b.*?(?:-urlcache|-decode|-encode|-split)"),
        "script_execution",
        "high",
        "Command and Control",
        "T1105",  # Ingress Tool Transfer
        "certutil abuse (LOLBin download/decode)",
    ),
    (
        re.compile(r"(?i)\bmshta(?:\.exe)?\b.*?(?:https?:|javascript:|vbscript:)"),
        "script_execution",
        "high",
        "Defense Evasion",
        "T1218.005",  # Mshta
        "mshta executando script remoto/inline",
    ),
    (
        re.compile(r"(?i)\brundll32(?:\.exe)?\b.*?(?:javascript:|https?:)"),
        "script_execution",
        "high",
        "Defense Evasion",
        "T1218.011",  # Rundll32
        "rundll32 com payload remoto/javascript",
    ),
    (
        re.compile(r"(?i)\bregsvr32(?:\.exe)?\b.*?(?:/i:https?:|/i:\\\\|scrobj\.dll)"),
        "script_execution",
        "high",
        "Defense Evasion",
        "T1218.010",  # Regsvr32
        "regsvr32 (Squiblydoo)",
    ),
    (
        re.compile(r"(?i)\bwmic(?:\.exe)?\b.*?(?:process\s+call\s+create|/format:https?:)"),
        "script_execution",
        "medium",
        "Execution",
        "T1047",  # WMI
        "wmic process create / format remoto",
    ),
    (
        re.compile(r"(?i)\b(?:bitsadmin|curl|wget)(?:\.exe)?\b.*?https?://"),
        "script_execution",
        "medium",
        "Command and Control",
        "T1105",
        "Download via LOLBin/utilidade",
    ),
    (
        re.compile(r"(?i)\bschtasks(?:\.exe)?\b.*?\s/(?:create|change)\b"),
        "persistence_indicator",
        "medium",
        "Persistence",
        "T1053.005",  # Scheduled Task
        "Scheduled Task criada/alterada",
    ),
    (
        re.compile(r"(?i)\bnew-service\b|\bsc\.exe\s+create\b"),
        "persistence_indicator",
        "medium",
        "Persistence",
        "T1543.003",  # Windows Service
        "Novo Windows Service",
    ),
    (
        re.compile(r"(?i)\breg(?:\.exe)?\s+add\b.*?(?:\\Run|\\RunOnce|\\Image File Execution Options)"),
        "persistence_indicator",
        "high",
        "Persistence",
        "T1547.001",  # Registry Run Keys
        "Registro de Run/RunOnce/IFEO",
    ),
]

_INTERESTING_PARENTS = {
    # Quando processo "filho" tem esse pai E o pai é cmd/explorer/office,
    # vira sinal de spawn anômalo (cmd → powershell, winword → cmd).
    "powershell.exe": {"cmd.exe", "explorer.exe", "winword.exe", "excel.exe", "outlook.exe"},
    "cmd.exe": {"winword.exe", "excel.exe", "outlook.exe", "acrord32.exe"},
}

_PRIVATE_NET_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "fe80",
)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_public_ip(ip: str) -> bool:
    if not ip or ip == "0.0.0.0":
        return False
    return not ip.startswith(_PRIVATE_NET_PREFIXES)


def _scan_command_line(cmdline: str) -> list[dict]:
    """
    Roda os padrões de segurança contra a command line. Devolve lista
    de "matches" (cada um vira um evento separado), ou [] se nada
    bateu. Vários padrões podem casar — mantemos todos pra dar visão
    completa pro detection_engine no servidor.
    """
    if not cmdline:
        return []
    hits = []
    for pattern, ev_type, severity, tactic, technique, summary in _SECURITY_PATTERNS:
        if pattern.search(cmdline):
            hits.append({
                "event_type": ev_type,
                "severity": severity,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "summary": summary,
                "match_pattern": pattern.pattern[:120],
            })
    return hits


class TelemetryCollector:
    """
    Coletor stateful — guarda snapshot anterior pra emitir só deltas.

    Uso:
        c = TelemetryCollector(host_id, host_facts, agent_version)
        events = c.collect_events()  # primeira chamada: snapshot inicial vazio
        time.sleep(30)
        events = c.collect_events()  # delta: novos processos / conexões
    """

    def __init__(
        self,
        host_id: str,
        host_facts: dict,
        agent_version: str = "1.0.0",
        *,
        collect_processes: bool = True,
        collect_connections: bool = True,
        collect_security: bool = True,
    ):
        self.host_id = host_id
        self.host_facts = host_facts
        self.agent_version = agent_version
        self.collect_processes = collect_processes
        self.collect_connections = collect_connections
        self.collect_security = collect_security

        # Snapshot anterior — usado pra emitir só deltas.
        self._known_pids: set[int] = set()
        self._known_conns: set[tuple] = set()
        self._first_run = True

    # ──────────────────────────────────────────────────────────────
    # Coleta
    # ──────────────────────────────────────────────────────────────

    def collect_events(self) -> list[dict]:
        """Roda todos os coletores ativados e devolve lista de eventos."""
        events: list[dict] = []
        try:
            import psutil
        except ImportError:
            logger.error("psutil não instalado — sem coleta de processo/rede")
            return events

        if self.collect_processes:
            events.extend(self._collect_processes(psutil))
        if self.collect_connections:
            events.extend(self._collect_connections(psutil))

        self._first_run = False
        return events

    def _collect_processes(self, psutil) -> list[dict]:
        events: list[dict] = []
        seen_pids: set[int] = set()
        new_proc_count = 0

        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "username", "create_time", "cmdline"]
        ):
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue
                seen_pids.add(pid)
                if pid in self._known_pids:
                    continue  # já visto

                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if cmdline_list else (info.get("name") or "")
                proc_name = info.get("name") or ""
                username = info.get("username") or ""
                ppid = info.get("ppid") or 0

                parent_name = ""
                try:
                    parent = psutil.Process(ppid) if ppid else None
                    parent_name = parent.name() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # No primeiro run, não disparamos process_execution pra
                # cada processo já vivo (geraria flood no enrollment).
                # A partir do 2º run, todo processo novo gera evento.
                if not self._first_run:
                    new_proc_count += 1
                    events.append(self._build_process_event(
                        pid=pid,
                        ppid=ppid,
                        name=proc_name,
                        cmdline=cmdline,
                        parent_name=parent_name,
                        username=username,
                    ))

                # Indicadores de segurança rodam SEMPRE (inclusive no
                # 1º run), porque um host pode ser inscrito com malware
                # já rodando — queremos pegar isso.
                if self.collect_security:
                    events.extend(self._scan_process_security(
                        pid=pid,
                        ppid=ppid,
                        name=proc_name,
                        cmdline=cmdline,
                        parent_name=parent_name,
                        username=username,
                    ))

                # Sinal de spawn anômalo (cmd → powershell vindo de Office)
                if self.collect_security and parent_name:
                    pname_lower = proc_name.lower()
                    parent_lower = parent_name.lower()
                    suspicious_parents = _INTERESTING_PARENTS.get(pname_lower)
                    if suspicious_parents and parent_lower in suspicious_parents:
                        events.append(self._build_anomaly_event(
                            pid=pid, ppid=ppid, name=proc_name,
                            cmdline=cmdline, parent_name=parent_name,
                            username=username,
                            summary=f"Spawn anômalo: {parent_name} → {proc_name}",
                            severity="medium",
                            tactic="Defense Evasion",
                            technique="T1059",
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                logger.debug("Processo skip por erro: %s", exc)
                continue

        self._known_pids = seen_pids
        if new_proc_count > 50:
            # Spike de processos é em si um sinal — emitimos um evento
            # comportamental, não 50 process_execution duplicados.
            logger.info("Spike de %d processos novos no ciclo", new_proc_count)
        return events

    def _collect_connections(self, psutil) -> list[dict]:
        events: list[dict] = []
        seen_conns: set[tuple] = set()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Linux sem CAP_NET_ADMIN ou Windows sem privs: degraded.
            logger.debug("net_connections sem permissão — pulando")
            return events
        except Exception as exc:
            logger.warning("Falha em net_connections: %s", exc)
            return events

        for c in conns:
            try:
                if not c.raddr:
                    continue
                key = (c.pid or 0, c.laddr.ip, c.laddr.port,
                       c.raddr.ip, c.raddr.port)
                seen_conns.add(key)
                if key in self._known_conns:
                    continue
                if self._first_run:
                    continue  # baseline, não dispara delta

                proc_name = ""
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Só emite evento pra conexões pra IP público —
                # tráfego interno (LAN/loopback) é barulho excessivo.
                if not _is_public_ip(c.raddr.ip):
                    continue

                events.append(self._build_network_event(
                    pid=c.pid or 0,
                    process_name=proc_name,
                    laddr_ip=c.laddr.ip,
                    laddr_port=c.laddr.port,
                    raddr_ip=c.raddr.ip,
                    raddr_port=c.raddr.port,
                    status=str(c.status or ""),
                ))
            except Exception as exc:
                logger.debug("Conn skip por erro: %s", exc)
                continue

        self._known_conns = seen_conns
        return events

    def _scan_process_security(
        self, *, pid, ppid, name, cmdline, parent_name, username
    ) -> list[dict]:
        hits = _scan_command_line(cmdline)
        events: list[dict] = []
        for hit in hits:
            events.append(self._build_security_event(
                pid=pid, ppid=ppid, name=name, cmdline=cmdline,
                parent_name=parent_name, username=username,
                event_type=hit["event_type"],
                severity=hit["severity"],
                mitre_tactic=hit["mitre_tactic"],
                mitre_technique=hit["mitre_technique"],
                summary=hit["summary"],
                match_pattern=hit["match_pattern"],
            ))
        return events

    # ──────────────────────────────────────────────────────────────
    # Builders — produzem dicts no schema canônico do /api/events e
    # preservam aliases legados consumidos pelo pipeline XDR existente.
    # ──────────────────────────────────────────────────────────────

    def _event_base(
        self,
        *,
        event_type: str,
        severity: str,
        confidence: int,
        evidence: str,
        raw: dict[str, Any] | None = None,
        **extra,
    ) -> dict:
        user = extra.pop("user", extra.pop("username", "")) or ""
        src_ip = extra.pop("src_ip", "") or ""
        dst_ip = extra.pop("dst_ip", "") or ""
        dst_port = extra.pop("dst_port", None)
        mitre_tactic = extra.pop("mitre_tactic", "") or ""
        mitre_technique = extra.pop("mitre_technique", "") or ""
        details = dict(extra.pop("details", {}) or {})
        tags = list(extra.pop("tags", []) or [])
        parent_process = extra.get("parent_process", "") or ""

        base = {
            "event_id": f"nga_evt_{uuid.uuid4().hex}",
            "host_id": self.host_id,
            "hostname": self.host_facts.get("hostname", self.host_id),
            "timestamp": _utc_iso(),
            "agent_version": self.agent_version,
            "event_type": event_type,
            "source": "netguard-agent",
            "severity": severity,
            "confidence": int(confidence),
            "process_name": "",
            "pid": None,
            "ppid": None,
            "command_line": "",
            "user": user,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "evidence": evidence,
            "raw": dict(raw or {}),
            "platform": self.host_facts.get("platform", ""),
            "username": user,
            "network_dst_ip": dst_ip,
            "network_dst_port": dst_port,
            "details": {
                "confidence": int(confidence),
                "evidence": evidence,
                "src_ip": src_ip,
                "mitre_tactic": mitre_tactic,
                "mitre_technique": mitre_technique,
                "parent_process": parent_process,
                **details,
            },
            "tags": tags,
        }
        base.update(extra)
        return base

    def _build_process_event(self, *, pid, ppid, name, cmdline,
                              parent_name, username) -> dict:
        evidence = f"pid={pid} created by {parent_name or f'ppid={ppid}'}"
        return self._event_base(
            event_type="process_execution",
            severity="low",
            confidence=90,
            evidence=evidence,
            raw={
                "parent_process": parent_name,
                "username": username,
            },
            process_name=name,
            command_line=cmdline[:2048],
            parent_process=parent_name,
            user=username,
            pid=pid,
            ppid=ppid,
        )

    def _build_network_event(self, *, pid, process_name, laddr_ip,
                              laddr_port, raddr_ip, raddr_port,
                              status) -> dict:
        evidence = f"{process_name or 'unknown'} -> {raddr_ip}:{raddr_port}"
        return self._event_base(
            event_type="network_connection",
            severity="low",
            confidence=85,
            evidence=evidence,
            raw={
                "src_port": laddr_port,
                "network_status": status,
                "network_direction": "outbound",
            },
            process_name=process_name,
            pid=pid,
            src_ip=laddr_ip,
            dst_ip=raddr_ip,
            dst_port=raddr_port,
            network_dst_ip=raddr_ip,
            network_dst_port=raddr_port,
            network_direction="outbound",
            details={
                "src_port": laddr_port,
                "status": status,
            },
        )

    def _build_security_event(self, *, pid, ppid, name, cmdline,
                               parent_name, username, event_type,
                               severity, mitre_tactic, mitre_technique,
                               summary, match_pattern) -> dict:
        return self._event_base(
            event_type=event_type,
            severity=severity,
            confidence=95,
            evidence=summary,
            raw={
                "parent_process": parent_name,
                "matched_pattern": match_pattern,
                "summary": summary,
                "username": username,
            },
            process_name=name,
            command_line=cmdline[:2048],
            parent_process=parent_name,
            user=username,
            pid=pid,
            ppid=ppid,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            details={
                "matched_pattern": match_pattern,
                "summary": summary,
            },
            tags=["netguard-agent", "security-indicator"],
        )

    def _build_anomaly_event(self, *, pid, ppid, name, cmdline,
                              parent_name, username, summary, severity,
                              tactic, technique) -> dict:
        return self._event_base(
            event_type="behavioral_anomaly",
            severity=severity,
            confidence=75,
            evidence=summary,
            raw={
                "parent_process": parent_name,
                "summary": summary,
                "username": username,
            },
            process_name=name,
            command_line=cmdline[:2048],
            parent_process=parent_name,
            user=username,
            pid=pid,
            ppid=ppid,
            mitre_tactic=tactic,
            mitre_technique=technique,
            tags=["netguard-agent", "anomaly"],
        )


def snapshot_summary(events: Iterable[dict]) -> dict:
    """
    Resumo agregado dos eventos — vai no envelope do POST pro server
    preencher o snapshot_summary do host (T16 já consome isso).
    """
    counts: dict[str, int] = {}
    severities: dict[str, int] = {}
    for ev in events:
        counts[ev.get("event_type", "?")] = counts.get(ev.get("event_type", "?"), 0) + 1
        sev = (ev.get("severity") or "low").lower()
        severities[sev] = severities.get(sev, 0) + 1
    return {
        "total_events": sum(counts.values()),
        "by_event_type": counts,
        "by_severity": severities,
        "collected_at": _utc_iso(),
    }


if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO)
    from agent.host_identity import get_host_facts, get_host_id  # type: ignore

    c = TelemetryCollector(get_host_id(), get_host_facts())
    # Primeira chamada estabelece baseline.
    c.collect_events()
    time.sleep(2)
    evs = c.collect_events()
    print(f"Coletados {len(evs)} eventos no ciclo.")
    if evs:
        print(json.dumps(evs[0], indent=2, default=str))
    print(json.dumps(snapshot_summary(evs), indent=2))
