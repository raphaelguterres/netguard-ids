"""
NetGuard Fail2Ban Engine v1.0
Inspirado no Fail2Ban original — mas nativo no Windows via Windows Firewall.

Funcionalidades:
- Monitora tentativas de brute force, port scan, SQLi repetitivo
- Aplica ban automático por IP após N tentativas em janela de tempo
- Ban temporário (TTL configurável) ou permanente
- Whitelist de IPs confiáveis
- Histórico completo de bans com motivo e timestamp
- Integração com Windows Firewall (netsh advfirewall)
- Regras por categoria: ssh, http, smtp, custom
"""

import time
import threading
import subprocess  # noqa: F401
import logging
import json  # noqa: F401
import os  # noqa: F401
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field  # noqa: F401
from typing import Dict, List, Optional

logger = logging.getLogger("ids.fail2ban")

# ── Jail configuration (equiv. fail2ban jails) ────────────────────
JAILS = {
    "brute-force": {
        "label":      "Brute Force",
        "maxretry":   5,
        "findtime":   300,   # 5 minutos
        "bantime":    3600,  # 1 hora
        "triggers":   ["Brute Force", "Failed Logon", "4625", "brute"],
        "severity":   ["medium", "high", "critical"],
        "icon":       "🔑",
    },
    "port-scan": {
        "label":      "Port Scan",
        "maxretry":   3,
        "findtime":   120,
        "bantime":    1800,
        "triggers":   ["Port Scan", "SYN Flood", "port scan", "reconnaissance"],
        "severity":   ["low", "medium", "high"],
        "icon":       "🔍",
    },
    "web-attack": {
        "label":      "Web Attack",
        "maxretry":   10,
        "findtime":   300,
        "bantime":    7200,
        "triggers":   ["SQL Injection", "XSS", "Path Traversal", "Command Injection",
                       "Log4Shell", "SSRF", "XXE", "SSTI", "LFI"],
        "severity":   ["medium", "high", "critical"],
        "icon":       "🌐",
    },
    "malware-c2": {
        "label":      "Malware / C2",
        "maxretry":   1,
        "findtime":   3600,
        "bantime":    86400,  # 24 horas
        "triggers":   ["Cobalt Strike", "Metasploit", "Meterpreter", "beacon",
                       "command_and_control", "DNS Tunnel"],
        "severity":   ["critical"],
        "icon":       "☠️",
    },
    "credential-theft": {
        "label":      "Credential Theft",
        "maxretry":   1,
        "findtime":   3600,
        "bantime":    86400,
        "triggers":   ["Mimikatz", "LSASS", "credential", "Pass the Hash",
                       "JWT", "lsadump"],
        "severity":   ["critical"],
        "icon":       "🗝️",
    },
    "dos": {
        "label":      "DoS / Flood",
        "maxretry":   20,
        "findtime":   60,
        "bantime":    900,
        "triggers":   ["flood", "DoS", "DDoS", "SYN flood"],
        "severity":   ["medium", "high"],
        "icon":       "💥",
    },
}

# IPs que NUNCA serão banidos
DEFAULT_WHITELIST = {
    "127.0.0.1", "::1", "192.168.15.1", "192.168.15.2",
    "0.0.0.0", "255.255.255.255",
}

PRIVATE_PREFIXES = ["192.168.", "10.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.", "127.", "169.254."]


@dataclass
class BanEntry:
    ip:         str
    jail:       str
    jail_label: str
    reason:     str
    banned_at:  str
    expires_at: str        # "permanent" ou ISO timestamp
    bantime:    int        # segundos, -1 = permanente
    count:      int        # quantas detecções levaram ao ban
    active:     bool = True
    unbanned_at: str = ""
    firewall_rule: str = ""

    def is_expired(self) -> bool:
        if self.bantime == -1 or self.expires_at == "permanent":
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now() > exp
        except Exception:
            return False

    def time_remaining(self) -> str:
        if self.bantime == -1:
            return "Permanente"
        try:
            exp = datetime.fromisoformat(self.expires_at)
            rem = exp - datetime.now()
            if rem.total_seconds() <= 0:
                return "Expirado"
            s = int(rem.total_seconds())
            if s >= 3600:
                return f"{s//3600}h {(s%3600)//60}m"
            if s >= 60:
                return f"{s//60}m {s%60}s"
            return f"{s}s"
        except Exception:
            return "?"

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "jail":         self.jail,
            "jail_label":   self.jail_label,
            "reason":       self.reason,
            "banned_at":    self.banned_at,
            "expires_at":   self.expires_at,
            "bantime":      self.bantime,
            "count":        self.count,
            "active":       self.active,
            "unbanned_at":  self.unbanned_at,
            "time_remaining": self.time_remaining(),
            "permanent":    self.bantime == -1,
        }


class Fail2BanEngine:
    """
    Engine de banimento automático inspirado no Fail2Ban.
    Monitora detecções e bane IPs automaticamente no Windows Firewall.
    """

    def __init__(self, whitelist: set = None, enabled: bool = True):
        self.enabled    = enabled
        self.whitelist  = (whitelist or set()) | DEFAULT_WHITELIST
        self._attempts: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        # ip → jail → [timestamps]
        self._bans:     Dict[str, BanEntry] = {}   # ip → ban ativo
        self._history:  List[BanEntry]      = []   # histórico completo
        self._lock      = threading.Lock()
        self._stats     = {
            "total_bans":     0,
            "active_bans":    0,
            "total_unbans":   0,
            "bans_by_jail":   defaultdict(int),
            "bans_prevented": 0,
        }
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="fail2ban-cleanup"
        )
        self._cleanup_thread.start()
        logger.info("Fail2Ban engine iniciado | jails=%d | enabled=%s",
                    len(JAILS), enabled)

    def ingest(self, detection: dict) -> Optional[BanEntry]:
        """
        Processa uma detecção. Retorna BanEntry se um ban foi aplicado.
        """
        if not self.enabled:
            return None

        ip = detection.get("source_ip", "").strip()
        if not ip or self._is_whitelisted(ip):
            return None

        threat  = detection.get("threat_name", "")
        sev     = detection.get("severity", "low")
        now     = time.time()

        with self._lock:
            # IP já banido?
            if ip in self._bans and self._bans[ip].active:
                self._stats["bans_prevented"] += 1
                return None

            # Verifica qual jail se aplica
            for jail_id, jail_cfg in JAILS.items():
                # Verifica trigger
                triggered = any(
                    t.lower() in threat.lower()
                    for t in jail_cfg["triggers"]
                ) or sev in jail_cfg["severity"] and any(
                    t.lower() in threat.lower() for t in jail_cfg["triggers"]
                )

                if not triggered:
                    continue

                # Registra tentativa
                attempts = self._attempts[ip][jail_id]
                attempts.append(now)

                # Remove tentativas fora da janela
                findtime = jail_cfg["findtime"]
                self._attempts[ip][jail_id] = [
                    t for t in attempts if now - t <= findtime
                ]
                count = len(self._attempts[ip][jail_id])

                # Atingiu maxretry?
                if count >= jail_cfg["maxretry"]:
                    ban = self._apply_ban(ip, jail_id, jail_cfg, threat, count)
                    return ban

        return None

    def _apply_ban(self, ip: str, jail_id: str, jail_cfg: dict,
                   reason: str, count: int) -> BanEntry:
        """Aplica o ban no Windows Firewall e registra."""
        bantime  = jail_cfg["bantime"]
        now_str  = datetime.now().isoformat()
        if bantime == -1:
            expires_str = "permanent"
        else:
            expires_str = (datetime.now() + timedelta(seconds=bantime)).isoformat()

        rule_name = f"NetGuard_Ban_{ip.replace('.','_').replace(':','_')}"

        entry = BanEntry(
            ip=ip,
            jail=jail_id,
            jail_label=jail_cfg["label"],
            reason=reason,
            banned_at=now_str,
            expires_at=expires_str,
            bantime=bantime,
            count=count,
            active=True,
            firewall_rule=rule_name,
        )

        # Aplica no Windows Firewall
        fw_ok = self._firewall_ban(ip, rule_name)

        self._bans[ip] = entry
        self._history.append(entry)
        self._stats["total_bans"]  += 1
        self._stats["active_bans"] += 1
        self._stats["bans_by_jail"][jail_id] += 1
        # Limpa tentativas após ban
        self._attempts[ip] = defaultdict(list)

        logger.warning(
            "FAIL2BAN BAN | ip=%s | jail=%s | reason=%s | count=%d | expires=%s | fw=%s",
            ip, jail_id, reason, count, expires_str, "OK" if fw_ok else "FAILED"
        )
        return entry

    def _firewall_ban(self, ip: str, rule_name: str) -> bool:
        """Adiciona regra de bloqueio no firewall do sistema (Windows ou Linux)."""
        try:
            from platform_utils import block_ip
            return block_ip(ip, rule_name)
        except Exception as e:
            logger.error("Firewall ban failed for %s: %s", ip, e)
            return False

    def _firewall_unban(self, rule_name: str, ip: str = "") -> bool:
        """Remove regra de bloqueio do firewall do sistema."""
        try:
            from platform_utils import unblock_ip
            return unblock_ip(ip, rule_name)
        except Exception as e:
            logger.error("Firewall unban failed: %s", e)
            return False

    def unban(self, ip: str, reason: str = "manual") -> bool:
        """Remove ban de um IP manualmente."""
        with self._lock:
            entry = self._bans.get(ip)
            if not entry or not entry.active:
                return False
            entry.active      = False
            entry.unbanned_at = datetime.now().isoformat()
            self._stats["active_bans"]  = max(0, self._stats["active_bans"] - 1)
            self._stats["total_unbans"] += 1
            fw_ok = self._firewall_unban(entry.firewall_rule)
            logger.info("FAIL2BAN UNBAN | ip=%s | reason=%s | fw=%s",
                        ip, reason, "OK" if fw_ok else "FAILED")
            del self._bans[ip]
            return True

    def _cleanup_loop(self):
        """Remove bans expirados automaticamente."""
        while True:
            time.sleep(60)
            try:
                with self._lock:
                    expired = [
                        ip for ip, entry in self._bans.items()
                        if entry.active and entry.is_expired()
                    ]
                for ip in expired:
                    self.unban(ip, reason="expired")
                    logger.info("FAIL2BAN EXPIRED | ip=%s", ip)
            except Exception as e:
                logger.error("Fail2Ban cleanup error: %s", e)

    def _is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist or any(
            ip.startswith(p) for p in PRIVATE_PREFIXES
        )

    def add_whitelist(self, ip: str):
        self.whitelist.add(ip)

    def remove_whitelist(self, ip: str):
        self.whitelist.discard(ip)

    def get_active_bans(self) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in self._bans.values() if e.active]

    def get_history(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in reversed(self._history[-limit:])]

    def get_attempts(self, ip: str) -> dict:
        with self._lock:
            result = {}
            for jail_id, attempts in self._attempts.get(ip, {}).items():
                cfg = JAILS.get(jail_id, {})
                result[jail_id] = {
                    "count":    len(attempts),
                    "maxretry": cfg.get("maxretry", 5),
                    "label":    cfg.get("label", jail_id),
                }
            return result

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled":        self.enabled,
                "active_bans":    len([e for e in self._bans.values() if e.active]),
                "total_bans":     self._stats["total_bans"],
                "total_unbans":   self._stats["total_unbans"],
                "bans_prevented": self._stats["bans_prevented"],
                "bans_by_jail":   dict(self._stats["bans_by_jail"]),
                "jails":          {
                    jid: {
                        "label":    cfg["label"],
                        "maxretry": cfg["maxretry"],
                        "findtime": cfg["findtime"],
                        "bantime":  cfg["bantime"],
                        "icon":     cfg["icon"],
                        "bans":     self._stats["bans_by_jail"].get(jid, 0),
                    }
                    for jid, cfg in JAILS.items()
                },
                "whitelist_size": len(self.whitelist),
            }

    def set_enabled(self, val: bool):
        self.enabled = val
        logger.info("Fail2Ban %s", "habilitado" if val else "desabilitado")


# Instância global
fail2ban = Fail2BanEngine(enabled=True)
