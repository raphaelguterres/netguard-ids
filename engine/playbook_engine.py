"""
NetGuard IDS — Incident Response Playbook Engine
Executa playbooks automáticos quando detecções críticas ocorrem.

Playbooks disponíveis:
  • brute_force      — Resposta a brute force SSH/RDP/Web
  • web_attack       — SQL Injection, XSS, RCE detectados
  • malware_detected — Hash/IP/domínio malicioso confirmado
  • data_exfiltration— Exfiltração de dados detectada
  • ransomware       — Comportamento de ransomware
  • apt_lateral      — Movimento lateral APT
  • generic_critical — Qualquer detecção crítica sem playbook específico
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.playbook")

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS pb_incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  TEXT NOT NULL UNIQUE,
    playbook     TEXT NOT NULL,
    trigger_event TEXT NOT NULL DEFAULT '{}',
    severity     TEXT NOT NULL DEFAULT 'critical',
    status       TEXT NOT NULL DEFAULT 'open',  -- open, in_progress, contained, resolved, false_positive
    opened_at    TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    closed_at    TEXT,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    assignee     TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS pb_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  TEXT NOT NULL,
    step_order   INTEGER NOT NULL,
    step_name    TEXT NOT NULL,
    step_type    TEXT NOT NULL,   -- auto, manual, notify, block, collect
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending, running, done, skipped, failed
    started_at   TEXT,
    finished_at  TEXT,
    output       TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(incident_id) REFERENCES pb_incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_pb_incidents_tenant ON pb_incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_pb_steps_incident   ON pb_steps(incident_id);
"""

# ── Playbook definitions ──────────────────────────────────────────────────────
PLAYBOOKS: dict[str, dict] = {
    "brute_force": {
        "label": "🔐 Brute Force Attack",
        "description": "Resposta a ataques de força bruta em SSH, RDP ou autenticação Web.",
        "severity_threshold": "high",
        "triggers": ["brute", "credential", "password", "login failure", "failed logon"],
        "steps": [
            {"name": "Coletar evidências",    "type": "collect",  "desc": "Capturar logs de autenticação, IPs de origem e timestamps dos últimos 100 eventos"},
            {"name": "Verificar IP no TI",    "type": "auto",     "desc": "Checar IP atacante em Feodo/ThreatFox/URLhaus"},
            {"name": "Bloquear IP atacante",  "type": "block",    "desc": "Adicionar IP à lista de bloqueio via Fail2Ban / firewall rule"},
            {"name": "Resetar contas afetadas","type":"manual",   "desc": "Se credenciais válidas foram encontradas, forçar reset de senha"},
            {"name": "Notificar equipe",      "type": "notify",   "desc": "Enviar alerta via webhook para canal de segurança"},
            {"name": "Habilitar MFA",         "type": "manual",   "desc": "Verificar se MFA está habilitado em contas expostas"},
            {"name": "Fechar incidente",      "type": "manual",   "desc": "Confirmar contenção e fechar com RCA"},
        ],
    },
    "web_attack": {
        "label": "🌐 Web Application Attack",
        "description": "SQL Injection, XSS, RCE, Path Traversal ou outro ataque web detectado.",
        "severity_threshold": "high",
        "triggers": ["sql injection", "xss", "rce", "path traversal", "owasp", "injection", "log4shell"],
        "steps": [
            {"name": "Coletar request completo", "type": "collect", "desc": "Capturar headers, payload, IP de origem e endpoint alvo"},
            {"name": "Analisar payload",          "type": "auto",   "desc": "Decodificar e analisar payload: URL encode, base64, obfuscação"},
            {"name": "Verificar comprometimento", "type": "manual", "desc": "Verificar se ataque foi bem-sucedido via logs de resposta HTTP"},
            {"name": "Bloquear IP/User-Agent",    "type": "block",  "desc": "Bloquear origem no WAF e adicionar regra OWASP CRS"},
            {"name": "Varredura de vulnerabilidade","type":"manual","desc": "Executar scanner no endpoint afetado"},
            {"name": "Patch emergencial",         "type": "manual", "desc": "Aplicar patch ou WAF virtual patch para vulnerabilidade explorada"},
            {"name": "Notificar equipe",          "type": "notify", "desc": "Alerta para dev team e security team"},
        ],
    },
    "malware_detected": {
        "label": "☣ Malware Detectado",
        "description": "Hash malicioso, IP de C2 ou domínio de distribuição detectado.",
        "severity_threshold": "high",
        "triggers": ["malware", "trojan", "ransomware", "c2", "command and control", "botnet", "ioc match"],
        "steps": [
            {"name": "Isolar host afetado",      "type": "block",  "desc": "Cortar acesso de rede do host infectado (isolamento de quarentena)"},
            {"name": "Snapshot forense",         "type": "collect","desc": "Capturar processos, conexões, memória e arquivos suspeitos"},
            {"name": "Identificar paciente zero","type": "manual", "desc": "Rastrear vetor de infecção inicial (email, USB, download)"},
            {"name": "Verificar propagação",     "type": "auto",   "desc": "Verificar outros hosts com mesma assinatura nas últimas 24h"},
            {"name": "Bloquear C2 no firewall",  "type": "block",  "desc": "Adicionar IP/domínio C2 em todos os controles de borda"},
            {"name": "Acionar IR team",          "type": "notify", "desc": "Escalar para time de IR com snapshot forense"},
            {"name": "Remediar e limpar",        "type": "manual", "desc": "Reimagear host ou aplicar remoção guiada de malware"},
            {"name": "Análise post-mortem",      "type": "manual", "desc": "Root cause analysis e relatório de incidente"},
        ],
    },
    "data_exfiltration": {
        "label": "📤 Data Exfiltration",
        "description": "Transferência suspeita de dados para destino externo detectada.",
        "severity_threshold": "critical",
        "triggers": ["exfiltration", "data leak", "dns tunnel", "large upload", "beaconing"],
        "steps": [
            {"name": "Bloquear tráfego externo", "type": "block",  "desc": "Bloquear imediatamente conexões de saída do host suspeito"},
            {"name": "Capturar tráfego",         "type": "collect","desc": "Iniciar tcpdump/pcap na interface afetada"},
            {"name": "Quantificar vazamento",    "type": "auto",   "desc": "Estimar volume de dados transferidos e destino"},
            {"name": "Identificar dados expostos","type":"manual", "desc": "Determinar quais dados foram exfiltrados (PII, IP, financeiro)"},
            {"name": "Acionar DPO/Jurídico",     "type": "notify", "desc": "Se PII vazou → notificação LGPD/GDPR obrigatória em 72h"},
            {"name": "Preservar evidências",     "type": "collect","desc": "Preservar logs, pcap e artefatos para cadeia de custódia"},
            {"name": "Notificar ANPD",           "type": "manual", "desc": "Avaliar necessidade de notificação regulatória"},
            {"name": "Relatório de incidente",   "type": "manual", "desc": "Preparar relatório forense completo"},
        ],
    },
    "ransomware": {
        "label": "💀 Ransomware",
        "description": "Comportamento de ransomware detectado (criptografia em massa, shadow copies deletadas).",
        "severity_threshold": "critical",
        "triggers": ["ransomware", "shadow copy", "vssadmin", "bcdedit", "encrypt", "ransom"],
        "steps": [
            {"name": "ISOLAMENTO IMEDIATO",     "type": "block",  "desc": "🚨 Desconectar host da rede IMEDIATAMENTE — não desligue"},
            {"name": "Alertar liderança",       "type": "notify", "desc": "CEO, CTO, CISO — ransomware ativo. Ativar plano de continuidade"},
            {"name": "Identificar variante",    "type": "collect","desc": "Identificar família de ransomware e verificar decryptors disponíveis"},
            {"name": "Avaliar propagação",      "type": "auto",   "desc": "Verificar outros hosts com comportamento similar nas últimas 2h"},
            {"name": "Preservar backups",       "type": "manual", "desc": "Verificar integridade de backups offline e isolar storage de backup"},
            {"name": "Iniciar recuperação",     "type": "manual", "desc": "Restaurar de backup limpo ou usar decryptor se disponível"},
            {"name": "Acionar seguro cyber",    "type": "manual", "desc": "Notificar seguradora de cyber se aplicável"},
            {"name": "Relatório ANPD/Policial", "type": "manual", "desc": "Boletim de ocorrência + notificação ANPD se dados criptografados"},
        ],
    },
    "apt_lateral": {
        "label": "🕵 APT / Movimento Lateral",
        "description": "Indicadores de APT: movimento lateral, escalação de privilégio, persistência.",
        "severity_threshold": "high",
        "triggers": ["lateral movement", "privilege escalation", "psexec", "wmi", "pass the hash", "golden ticket", "kerberoast"],
        "steps": [
            {"name": "Mapeamento de comprometimento","type":"collect","desc": "Identificar todos os hosts comprometidos e timeline de acesso"},
            {"name": "Isolar hosts comprometidos",  "type": "block",  "desc": "Isolar segmento de rede comprometido"},
            {"name": "Coleta forense",              "type": "collect","desc": "Dump de memória, artefatos de persistência, chaves de registro"},
            {"name": "Reset de credenciais",        "type": "manual", "desc": "Resetar TODAS as contas privilegiadas e service accounts"},
            {"name": "Análise de persistência",     "type": "auto",   "desc": "Verificar scheduled tasks, services, registry run keys, cron"},
            {"name": "Threat hunt ativo",           "type": "manual", "desc": "Caçar IOCs da campanha em toda a rede"},
            {"name": "Reconstruir hosts",           "type": "manual", "desc": "Reimagear hosts comprometidos do zero"},
            {"name": "Purple team review",          "type": "manual", "desc": "Exercício purple team para validar detecção e gaps"},
        ],
    },
    "generic_critical": {
        "label": "⚠ Incidente Crítico",
        "description": "Playbook genérico para detecções críticas sem playbook específico.",
        "severity_threshold": "critical",
        "triggers": [],
        "steps": [
            {"name": "Avaliar impacto",        "type": "collect","desc": "Identificar sistemas afetados e potencial impacto"},
            {"name": "Coletar evidências",     "type": "collect","desc": "Logs, conexões, processos do momento da detecção"},
            {"name": "Conter ameaça",          "type": "block",  "desc": "Bloquear IP/processo/conta suspeita"},
            {"name": "Notificar responsável",  "type": "notify", "desc": "Alertar analista de plantão e gestor de segurança"},
            {"name": "Análise e remediação",   "type": "manual", "desc": "Investigar root cause e aplicar correção"},
            {"name": "Documentar incidente",   "type": "manual", "desc": "Registrar timeline, impacto e ações tomadas"},
        ],
    },
}


SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PlaybookEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._db() as c:
            c.executescript(SCHEMA)

    # ── Trigger logic ─────────────────────────────────────────────────────────

    def match_playbook(self, threat_name: str, severity: str,
                       mitre_tactic: str = "") -> Optional[str]:
        """Retorna nome do playbook mais adequado para a detecção."""
        sev_num = SEV_ORDER.get(severity.lower(), 0)
        text    = f"{threat_name} {mitre_tactic}".lower()

        best_key   = None
        best_score = -1

        for pb_key, pb in PLAYBOOKS.items():
            if pb_key == "generic_critical":
                continue
            min_sev = SEV_ORDER.get(pb["severity_threshold"], 2)
            if sev_num < min_sev:
                continue
            for trigger in pb["triggers"]:
                if trigger in text:
                    score = len(trigger)
                    if score > best_score:
                        best_score = score
                        best_key   = pb_key

        if best_key:
            return best_key
        if sev_num >= SEV_ORDER.get("critical", 3):
            return "generic_critical"
        return None

    def open_incident(self, playbook_key: str, trigger_event: dict,
                      tenant_id: str = "default") -> dict:
        """Cria novo incidente com steps do playbook."""
        if playbook_key not in PLAYBOOKS:
            raise ValueError(f"Playbook desconhecido: {playbook_key}")

        import uuid
        incident_id = "INC-" + uuid.uuid4().hex[:8].upper()
        now = _now()
        pb  = PLAYBOOKS[playbook_key]

        with self._db() as c:
            c.execute(
                "INSERT INTO pb_incidents(incident_id,playbook,trigger_event,severity,"
                "status,opened_at,updated_at,tenant_id) VALUES(?,?,?,?,?,?,?,?)",
                (incident_id, playbook_key,
                 json.dumps(trigger_event),
                 trigger_event.get("severity", "critical"),
                 "open", now, now, tenant_id),
            )
            for i, step in enumerate(pb["steps"], 1):
                c.execute(
                    "INSERT INTO pb_steps(incident_id,step_order,step_name,step_type,description,status) "
                    "VALUES(?,?,?,?,?,?)",
                    (incident_id, i, step["name"], step["type"], step["desc"], "pending"),
                )

        logger.info("Incidente aberto: %s [%s] tenant=%s", incident_id, playbook_key, tenant_id)
        return self.get_incident(incident_id)

    def auto_trigger(self, detection: dict, tenant_id: str = "default") -> Optional[dict]:
        """Chamado pelo pipeline de detecção — abre incidente se necessário."""
        sev  = detection.get("severity", "low")
        name = detection.get("threat_name", "")
        mitre= detection.get("mitre_tactic", "")

        pb_key = self.match_playbook(name, sev, mitre)
        if not pb_key:
            return None

        # Evitar duplicatas: só 1 incidente aberto por playbook/tenant nos últimos 10min
        with self._db() as c:
            recent = c.execute(
                "SELECT id FROM pb_incidents WHERE playbook=? AND tenant_id=? AND status='open' "
                "AND opened_at > datetime('now','-10 minutes')",
                (pb_key, tenant_id),
            ).fetchone()
        if recent:
            return None

        try:
            return self.open_incident(pb_key, detection, tenant_id)
        except Exception as e:
            logger.error("Erro ao abrir incidente: %s", e)
            return None

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._db() as c:
            row = c.execute("SELECT * FROM pb_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if not row:
                return None
            inc = dict(row)
            steps = c.execute(
                "SELECT * FROM pb_steps WHERE incident_id=? ORDER BY step_order",
                (incident_id,),
            ).fetchall()
            inc["steps"]  = [dict(s) for s in steps]
            inc["playbook_meta"] = PLAYBOOKS.get(inc["playbook"], {})
        return inc

    def list_incidents(self, tenant_id: str = "default",
                       status: str = None, limit: int = 100) -> list:
        clauses = ["tenant_id=?"]
        params  = [tenant_id]
        if status:
            clauses.append("status=?"); params.append(status)
        where = " AND ".join(clauses)
        params.append(limit)
        with self._db() as c:
            rows = c.execute(
                f"SELECT * FROM pb_incidents WHERE {where} ORDER BY opened_at DESC LIMIT ?",
                params,
            ).fetchall()
        incidents = []
        for row in rows:
            inc = dict(row)
            inc["playbook_meta"] = PLAYBOOKS.get(inc["playbook"], {})
            incidents.append(inc)
        return incidents

    def update_step(self, incident_id: str, step_order: int,
                    status: str, output: str = "") -> bool:
        now = _now()
        with self._db() as c:
            c.execute(
                "UPDATE pb_steps SET status=?, output=?, "
                "started_at=COALESCE(started_at,?), "
                "finished_at=CASE WHEN ? IN ('done','failed','skipped') THEN ? ELSE finished_at END "
                "WHERE incident_id=? AND step_order=?",
                (status, output, now, status, now, incident_id, step_order),
            )
            c.execute(
                "UPDATE pb_incidents SET updated_at=?, status=CASE "
                "WHEN status='open' THEN 'in_progress' ELSE status END "
                "WHERE incident_id=?",
                (now, incident_id),
            )
        return True

    def update_incident_status(self, incident_id: str, status: str,
                               notes: str = "") -> bool:
        now = _now()
        with self._db() as c:
            c.execute(
                "UPDATE pb_incidents SET status=?, notes=?, updated_at=?, "
                "closed_at=CASE WHEN ? IN ('resolved','false_positive') THEN ? ELSE closed_at END "
                "WHERE incident_id=?",
                (status, notes, now, status, now, incident_id),
            )
        return True

    def stats(self, tenant_id: str = "default") -> dict:
        with self._db() as c:
            total  = c.execute("SELECT COUNT(*) FROM pb_incidents WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
            open_  = c.execute("SELECT COUNT(*) FROM pb_incidents WHERE tenant_id=? AND status='open'", (tenant_id,)).fetchone()[0]
            in_prog= c.execute("SELECT COUNT(*) FROM pb_incidents WHERE tenant_id=? AND status='in_progress'", (tenant_id,)).fetchone()[0]
            resolved=c.execute("SELECT COUNT(*) FROM pb_incidents WHERE tenant_id=? AND status='resolved'", (tenant_id,)).fetchone()[0]
            by_pb  = c.execute(
                "SELECT playbook, COUNT(*) as cnt FROM pb_incidents WHERE tenant_id=? GROUP BY playbook",
                (tenant_id,),
            ).fetchall()
        return {
            "total": total, "open": open_, "in_progress": in_prog,
            "resolved": resolved,
            "by_playbook": {r["playbook"]: r["cnt"] for r in by_pb},
            "playbooks": list(PLAYBOOKS.keys()),
        }

    def playbooks_list(self) -> list:
        return [
            {"key": k, "label": v["label"], "description": v["description"],
             "steps_count": len(v["steps"]), "severity_threshold": v["severity_threshold"]}
            for k, v in PLAYBOOKS.items()
        ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Singleton ─────────────────────────────────────────────────────────────────

_pb_instance: Optional[PlaybookEngine] = None
_pb_lock = threading.Lock()


def get_playbook_engine(db_path: str) -> PlaybookEngine:
    global _pb_instance
    with _pb_lock:
        if _pb_instance is None:
            _pb_instance = PlaybookEngine(db_path)
    return _pb_instance
