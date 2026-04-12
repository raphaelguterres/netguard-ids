"""
NetGuard Kill Chain Correlator v1.0
Correlação automática de eventos em Kill Chain MITRE ATT&CK.

Detecta sequências de ataque coordenadas pelo mesmo IP ao longo do tempo,
gera Incident Reports completos e mapeia no MITRE ATT&CK Navigator.

Substitui 2-4h de trabalho manual de analista SOC nível 1/2 por análise instantânea.
"""

import time
import threading
import logging
from datetime import datetime, timedelta, timezone  # noqa: F401
from collections import defaultdict
from typing import List, Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("ids.killchain")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# ── MITRE ATT&CK Tactic Order (Kill Chain progression) ────────────
TACTIC_ORDER = {
    "reconnaissance":       0,
    "resource_development": 1,
    "initial_access":       2,
    "execution":            3,
    "persistence":          4,
    "privilege_escalation": 5,
    "defense_evasion":      6,
    "credential_access":    7,
    "discovery":            8,
    "lateral_movement":     9,
    "collection":           10,
    "command_and_control":  11,
    "exfiltration":         12,
    "impact":               13,
}

TACTIC_LABELS = {
    "reconnaissance":       "Reconhecimento",
    "resource_development": "Desenvolvimento de Recursos",
    "initial_access":       "Acesso Inicial",
    "execution":            "Execução",
    "persistence":          "Persistência",
    "privilege_escalation": "Escalada de Privilégio",
    "defense_evasion":      "Evasão de Defesas",
    "credential_access":    "Acesso a Credenciais",
    "discovery":            "Descoberta",
    "lateral_movement":     "Movimento Lateral",
    "collection":           "Coleta",
    "command_and_control":  "Comando e Controle",
    "exfiltration":         "Exfiltração",
    "impact":               "Impacto",
}

TACTIC_COLORS = {
    "reconnaissance":       "#4488ff",
    "initial_access":       "#ff7700",
    "execution":            "#ff2255",
    "persistence":          "#aa55ff",
    "privilege_escalation": "#ff2255",
    "defense_evasion":      "#ffcc00",
    "credential_access":    "#ff2255",
    "discovery":            "#00ccff",
    "lateral_movement":     "#ff7700",
    "collection":           "#aa55ff",
    "command_and_control":  "#ff2255",
    "exfiltration":         "#ff2255",
    "impact":               "#ff2255",
}

# ── Mapeamento threat_name → tática MITRE ─────────────────────────
THREAT_TO_TACTIC = {
    # Reconnaissance
    "Port Scan":                    ("reconnaissance",     "T1046"),
    "SYN Flood":                    ("reconnaissance",     "T1046"),
    "Network Reconnaissance":       ("reconnaissance",     "T1046"),
    "DNS Tunneling":                ("command_and_control","T1071.004"),
    "ARP Spoofing":                 ("reconnaissance",     "T1018"),

    # Initial Access
    "Brute Force":                  ("initial_access",     "T1110"),
    "SQL Injection":                ("initial_access",     "T1190"),
    "Path Traversal":               ("initial_access",     "T1190"),
    "XSS Attempt":                  ("initial_access",     "T1190"),
    "Command Injection":            ("initial_access",     "T1190"),
    "Log4Shell":                    ("initial_access",     "T1190"),
    "Spring4Shell":                 ("initial_access",     "T1190"),
    "SSRF":                         ("initial_access",     "T1190"),
    "XXE":                          ("initial_access",     "T1190"),
    "SSTI":                         ("initial_access",     "T1190"),

    # Execution
    "PowerShell Encoded Command":   ("execution",          "T1059.001"),
    "PowerShell Download Cradle":   ("execution",          "T1059.001"),
    "WMIC Remote Execution":        ("execution",          "T1047"),
    "Rundll32 Suspicious":          ("execution",          "T1218.011"),
    "Regsvr32 Execution":           ("execution",          "T1218.010"),
    "Metasploit Framework":         ("execution",          "T1059"),
    "Cobalt Strike Beacon":         ("command_and_control","T1071"),

    # Persistence
    "Scheduled Task Creation":      ("persistence",        "T1053.005"),
    "Registry Run Key":             ("persistence",        "T1547.001"),
    "New Service Created":          ("persistence",        "T1543.003"),

    # Privilege Escalation
    "UAC Bypass":                   ("privilege_escalation","T1548.002"),
    "Pass the Hash":                ("lateral_movement",   "T1550.002"),

    # Defense Evasion
    "Windows Defender Disabled":    ("defense_evasion",    "T1562.001"),
    "Clear Event Logs":             ("defense_evasion",    "T1070.001"),
    "AMSI Bypass":                  ("defense_evasion",    "T1562.001"),

    # Credential Access
    "Mimikatz":                     ("credential_access",  "T1003"),
    "LSASS Memory Dump":            ("credential_access",  "T1003.001"),
    "Credential Stuffing":          ("credential_access",  "T1110"),
    "Failed Logon (4625)":          ("credential_access",  "T1110"),
    "JWT None Algorithm":           ("initial_access",     "T1550"),

    # Discovery
    "Windows Account Enumeration":  ("discovery",          "T1087"),
    "System Information Discovery": ("discovery",          "T1082"),

    # Lateral Movement
    "PsExec Remote Execution":      ("lateral_movement",   "T1570"),

    # Exfiltration
    "Data Exfiltration via DNS":    ("exfiltration",       "T1048.003"),
    "Suspicious Archive Creation":  ("exfiltration",       "T1074"),

    # Impact
    "Shadow Copy Deletion":         ("impact",             "T1490"),
    "Ransomware File Extension":    ("impact",             "T1486"),
}

def map_threat_to_tactic(threat_name: str, existing_tactic: str = "") -> tuple:
    """Mapeia nome da ameaça para tática MITRE. Retorna (tactic, technique)."""
    # Busca exata
    for key, val in THREAT_TO_TACTIC.items():
        if key.lower() in threat_name.lower():
            return val
    # Usa tática existente se disponível
    if existing_tactic:
        tac = existing_tactic.lower().replace(" ", "_").replace("-","_")
        if tac in TACTIC_ORDER:
            return (tac, "T????")
    # Fallback por palavras-chave
    tl = threat_name.lower()
    if any(x in tl for x in ["scan","probe","enum","recon"]): return ("reconnaissance","T1046")
    if any(x in tl for x in ["inject","sqli","xss","rfi","lfi"]): return ("initial_access","T1190")
    if any(x in tl for x in ["brute","force","login","auth"]): return ("initial_access","T1110")
    if any(x in tl for x in ["exec","shell","cmd","powershell"]): return ("execution","T1059")
    if any(x in tl for x in ["persist","startup","service","registry"]): return ("persistence","T1547")
    if any(x in tl for x in ["cred","password","hash","dump"]): return ("credential_access","T1003")
    if any(x in tl for x in ["lateral","psexec","smb","rdp"]): return ("lateral_movement","T1570")
    if any(x in tl for x in ["exfil","data","transfer","upload"]): return ("exfiltration","T1048")
    if any(x in tl for x in ["c2","c&c","beacon","cobalt","meterp"]): return ("command_and_control","T1071")
    if any(x in tl for x in ["ransom","encrypt","shadow","wiper"]): return ("impact","T1486")
    return ("initial_access", "T1190")


@dataclass
class KillChainEvent:
    """Evento individual numa kill chain."""
    timestamp:  str
    threat_name: str
    severity:   str
    tactic:     str
    technique:  str
    source_ip:  str
    method:     str
    log_entry:  str = ""
    confidence: float = 1.0


@dataclass
class Incident:
    """Incidente correlacionado — sequência de eventos do mesmo IP."""
    id:           str
    source_ip:    str
    first_seen:   str
    last_seen:    str
    events:       List[KillChainEvent] = field(default_factory=list)
    tactics:      List[str] = field(default_factory=list)
    techniques:   List[str] = field(default_factory=list)
    severity:     str = "low"
    stage:        str = ""      # Estágio atual da kill chain
    stage_index:  int = 0
    complete:     bool = False  # True se atingiu exfiltração ou impacto
    actor_profile: str = ""

    @property
    def duration_seconds(self) -> int:
        try:
            t0 = datetime.fromisoformat(self.first_seen.replace("Z",""))
            t1 = datetime.fromisoformat(self.last_seen.replace("Z",""))
            return int((t1 - t0).total_seconds())
        except Exception:
            return 0

    @property
    def duration_str(self) -> str:
        s = self.duration_seconds
        if s < 60:   return f"{s}s"
        if s < 3600: return f"{s//60}m {s%60}s"
        return f"{s//3600}h {(s%3600)//60}m"

    def highest_severity(self) -> str:
        order = {"critical":0,"high":1,"medium":2,"low":3}
        return min(self.events, key=lambda e: order.get(e.severity,4)).severity if self.events else "low"

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "source_ip":     self.source_ip,
            "first_seen":    self.first_seen,
            "last_seen":     self.last_seen,
            "duration":      self.duration_str,
            "event_count":   len(self.events),
            "tactics":       self.tactics,
            "techniques":    self.techniques,
            "severity":      self.highest_severity(),
            "stage":         self.stage,
            "stage_index":   self.stage_index,
            "complete":      self.complete,
            "actor_profile": self.actor_profile,
            "events": [{
                "timestamp":   e.timestamp,
                "threat_name": e.threat_name,
                "severity":    e.severity,
                "tactic":      e.tactic,
                "technique":   e.technique,
                "method":      e.method,
                "log_entry":   e.log_entry[:120],
            } for e in self.events],
        }


class KillChainCorrelator:
    """
    Correlaciona eventos de segurança em Kill Chains MITRE ATT&CK.
    
    - Agrupa eventos pelo mesmo IP em janela de tempo configurável
    - Detecta progressão tática (recon → exec → exfil)
    - Gera Incident Reports completos
    - Produz heatmap MITRE ATT&CK Navigator
    """

    def __init__(self, window_minutes: int = 60, min_events: int = 2):
        self.window = window_minutes * 60  # em segundos
        self.min_events = min_events
        self._events: Dict[str, List[dict]] = defaultdict(list)  # ip → eventos brutos
        self._incidents: Dict[str, Incident] = {}                # ip → incidente ativo
        self._closed: List[Incident] = []                        # incidentes finalizados
        self._lock = threading.Lock()
        logger.info("KillChain correlator iniciado (janela=%dm, min_events=%d)", window_minutes, min_events)

    def ingest(self, detection: dict):
        """Ingere uma detecção e tenta correlacionar."""
        ip = detection.get("source_ip","").strip()
        if not ip or ip.startswith("127.") or ip.startswith("192.168."):
            return

        threat = detection.get("threat_name","")
        tactic, technique = map_threat_to_tactic(
            threat,
            detection.get("mitre_tactic","")
        )

        event = KillChainEvent(
            timestamp=detection.get("timestamp", _utc_iso()),
            threat_name=threat,
            severity=detection.get("severity","low"),
            tactic=tactic,
            technique=technique,
            source_ip=ip,
            method=detection.get("method","ids"),
            log_entry=detection.get("log_entry",""),
            confidence=float(detection.get("confidence",1.0)),
        )

        with self._lock:
            self._add_event(ip, event)

    def _add_event(self, ip: str, event: KillChainEvent):
        """Adiciona evento e atualiza/cria incidente."""
        now = time.time()

        # Limpa eventos antigos
        self._events[ip] = [
            e for e in self._events[ip]
            if (now - self._ts_to_epoch(e.timestamp)) < self.window
        ]
        self._events[ip].append(event)

        # Cria ou atualiza incidente
        if ip not in self._incidents:
            inc_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{ip.replace('.','')[-6:]}"
            self._incidents[ip] = Incident(
                id=inc_id,
                source_ip=ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )

        inc = self._incidents[ip]
        inc.last_seen = event.timestamp

        # Evita eventos duplicados na mesma janela
        already = any(
            e.threat_name == event.threat_name and
            abs(self._ts_to_epoch(e.timestamp) - self._ts_to_epoch(event.timestamp)) < 30
            for e in inc.events
        )
        if not already:
            inc.events.append(event)

        # Atualiza táticas únicas em ordem
        if event.tactic not in inc.tactics:
            inc.tactics.append(event.tactic)
            inc.tactics.sort(key=lambda t: TACTIC_ORDER.get(t, 99))

        # Atualiza técnicas
        if event.technique not in inc.techniques:
            inc.techniques.append(event.technique)

        # Atualiza estágio atual (mais avançado)
        max_idx = max(TACTIC_ORDER.get(t, 0) for t in inc.tactics)
        inc.stage_index = max_idx
        inc.stage = TACTIC_LABELS.get(
            [k for k,v in TACTIC_ORDER.items() if v==max_idx][0], ""
        )

        # Detecta se é kill chain completa (chegou em exfil ou impact)
        if max_idx >= TACTIC_ORDER["exfiltration"]:
            inc.complete = True

        # Perfil do ator baseado nas táticas
        inc.actor_profile = self._profile_actor(inc)

        if len(inc.events) >= self.min_events:
            logger.warning(
                "KILL CHAIN | ip=%s | estágio=%s | eventos=%d | táticas=%s",
                ip, inc.stage, len(inc.events), "→".join(inc.tactics[:4])
            )

    def _profile_actor(self, inc: Incident) -> str:
        """Infere perfil do ator baseado nas táticas e técnicas."""
        tactics = set(inc.tactics)
        techniques = set(inc.techniques)

        if "T1003" in techniques or "T1003.001" in techniques:
            return "Credential Harvester — provável APT ou insider threat"
        if "T1071" in techniques or "command_and_control" in tactics:
            return "Operador C2 — malware com beacon ativo"
        if "T1486" in techniques or "T1490" in techniques:
            return "Ransomware Operator"
        if "lateral_movement" in tactics and "credential_access" in tactics:
            return "APT / Movimento Lateral Sofisticado"
        if "initial_access" in tactics and len(tactics) <= 2:
            return "Scanner Automatizado / Oportunista"
        if "exfiltration" in tactics:
            return "Data Theft Actor"
        if len(tactics) >= 5:
            return "Ator Avançado (APT) — múltiplas fases detectadas"
        return "Atacante Genérico"

    def get_incidents(self, min_events: int = 2) -> List[dict]:
        """Retorna todos os incidentes com >= min_events eventos."""
        with self._lock:
            result = []
            for inc in self._incidents.values():
                if len(inc.events) >= min_events:
                    result.append(inc.to_dict())
            # Ordena por severity e evento count
            sev_order = {"critical":0,"high":1,"medium":2,"low":3}
            result.sort(key=lambda x: (sev_order.get(x["severity"],4), -x["event_count"]))
            return result

    def get_incident_by_ip(self, ip: str) -> Optional[dict]:
        with self._lock:
            inc = self._incidents.get(ip)
            return inc.to_dict() if inc else None

    def generate_report(self, ip: str) -> dict:
        """Gera Incident Report completo para um IP."""
        with self._lock:
            inc = self._incidents.get(ip)
            if not inc:
                return {"error": "Incidente não encontrado"}

        d = inc.to_dict()

        # Timeline detalhada
        timeline = []
        for e in inc.events:
            timeline.append({
                "time":     e.timestamp,
                "tactic":   TACTIC_LABELS.get(e.tactic, e.tactic),
                "technique": e.technique,
                "threat":   e.threat_name,
                "severity": e.severity,
                "method":   e.method,
                "color":    TACTIC_COLORS.get(e.tactic, "#4488ff"),
            })

        # MITRE ATT&CK heatmap data
        heatmap = {}
        for e in inc.events:
            tac = e.tactic
            if tac not in heatmap:
                heatmap[tac] = {
                    "tactic":     tac,
                    "label":      TACTIC_LABELS.get(tac, tac),
                    "color":      TACTIC_COLORS.get(tac, "#4488ff"),
                    "techniques": [],
                    "count":      0,
                }
            heatmap[tac]["count"] += 1
            if e.technique not in heatmap[tac]["techniques"]:
                heatmap[tac]["techniques"].append(e.technique)

        # Recomendações baseadas nas táticas detectadas
        recs = self._generate_recommendations(inc)

        # Severity score (0-100)
        score = min(100, len(inc.events) * 8 + inc.stage_index * 6)
        if inc.complete: score = min(100, score + 20)

        return {
            **d,
            "score":           score,
            "timeline":        timeline,
            "mitre_heatmap":   list(heatmap.values()),
            "recommendations": recs,
            "summary":         self._generate_summary(inc, score),
            "generated_at":    _utc_iso(),
        }

    def _generate_summary(self, inc: Incident, score: int) -> str:
        sev = inc.highest_severity()
        tactics_str = " → ".join(TACTIC_LABELS.get(t,"?") for t in inc.tactics[:5])
        complete_str = "Kill chain COMPLETA detectada. " if inc.complete else ""
        return (
            f"{complete_str}"
            f"IP {inc.source_ip} executou {len(inc.events)} eventos maliciosos "
            f"ao longo de {inc.duration_str} "
            f"cobrindo {len(inc.tactics)} táticas MITRE ATT&CK: {tactics_str}. "
            f"Perfil: {inc.actor_profile}. "
            f"Score de risco: {score}/100 ({sev.upper()})."
        )

    def _generate_recommendations(self, inc: Incident) -> List[dict]:
        recs = []
        tactics = set(inc.tactics)

        if "reconnaissance" in tactics:
            recs.append({"priority":"high","action":"Bloquear IP no firewall imediatamente","tactic":"Reconnaissance","mitre":"T1046"})
        if "initial_access" in tactics:
            recs.append({"priority":"critical","action":"Verificar se qualquer requisição do IP chegou a um endpoint vulnerável","tactic":"Initial Access","mitre":"T1190"})
            recs.append({"priority":"high","action":"Revisar logs do servidor web para respostas 200 após tentativas de injeção","tactic":"Initial Access","mitre":"T1190"})
        if "execution" in tactics:
            recs.append({"priority":"critical","action":"Isolar a máquina da rede imediatamente — possível comprometimento","tactic":"Execution","mitre":"T1059"})
            recs.append({"priority":"critical","action":"Analisar processos em execução e conexões de rede estabelecidas","tactic":"Execution","mitre":"T1059"})
        if "persistence" in tactics:
            recs.append({"priority":"critical","action":"Verificar chaves de registro Run, tarefas agendadas e serviços novos","tactic":"Persistence","mitre":"T1547"})
        if "credential_access" in tactics:
            recs.append({"priority":"critical","action":"Resetar TODAS as senhas do domínio imediatamente","tactic":"Credential Access","mitre":"T1003"})
            recs.append({"priority":"critical","action":"Habilitar MFA em todos os serviços expostos","tactic":"Credential Access","mitre":"T1003"})
        if "lateral_movement" in tactics:
            recs.append({"priority":"critical","action":"Segmentar rede — impedir propagação lateral via VLAN isolation","tactic":"Lateral Movement","mitre":"T1570"})
        if "exfiltration" in tactics:
            recs.append({"priority":"critical","action":"Bloquear tráfego de saída do IP imediatamente — dados podem estar sendo exfiltrados","tactic":"Exfiltration","mitre":"T1048"})
            recs.append({"priority":"critical","action":"Notificar DPO — possível violação LGPD/GDPR","tactic":"Exfiltration","mitre":"T1048"})
        if "impact" in tactics:
            recs.append({"priority":"critical","action":"PARE TUDO — ransomware ou wiper detectado. Desconectar da rede agora","tactic":"Impact","mitre":"T1486"})
            recs.append({"priority":"critical","action":"Acionar plano de recuperação de desastres e backup imediatamente","tactic":"Impact","mitre":"T1486"})

        # Sempre recomendar bloqueio se >= 3 eventos
        recs.append({"priority":"high","action":f"Bloquear IP {inc.source_ip} no firewall e em todos os edge devices","tactic":"All","mitre":"M1037"})
        recs.append({"priority":"medium","action":"Preservar todos os logs para análise forense e possível abertura de B.O.","tactic":"All","mitre":"M1057"})

        return recs

    def clear_ip(self, ip: str):
        with self._lock:
            self._incidents.pop(ip, None)
            self._events.pop(ip, None)

    @staticmethod
    def _ts_to_epoch(ts: str) -> float:
        try:
            return datetime.fromisoformat(ts.replace("Z","")).timestamp()
        except Exception:
            return time.time()

    def stats(self) -> dict:
        with self._lock:
            active = [i for i in self._incidents.values() if len(i.events) >= self.min_events]
            complete = [i for i in active if i.complete]
            return {
                "active_incidents":   len(active),
                "complete_chains":    len(complete),
                "tracked_ips":        len(self._incidents),
                "window_minutes":     self.window // 60,
                "min_events":         self.min_events,
            }


# Instância global
