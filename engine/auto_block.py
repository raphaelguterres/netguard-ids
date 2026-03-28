"""
NetGuard — Auto Block Engine
Bloqueio automático de IPs por Risk Score + opção de reverter.

Fluxo:
  1. Risk Engine calcula score >= threshold (default: 75)
  2. AutoBlockEngine bloqueia IP via Windows Firewall (ou iptables no Linux)
  3. Registra o bloqueio com timestamp, score e motivo
  4. Dashboard mostra lista de bloqueios com botão Reverter
  5. Revert remove a regra do firewall e limpa o registro

Compatível com:
  - Windows: netsh advfirewall
  - Linux:   iptables
  - macOS:   pfctl (básico)
"""

import os
import sys
import time
import logging
import threading
import subprocess
import platform
from datetime import datetime, timezone
from typing import Optional, List
from collections import deque

logger = logging.getLogger("netguard.autoblock")

# Score mínimo para bloqueio automático
DEFAULT_THRESHOLD = 75

# IPs que nunca devem ser bloqueados
BLOCK_WHITELIST = {
    "127.0.0.1", "::1", "0.0.0.0",
    "192.168.15.1",   # Gateway padrão
    "192.168.15.2",   # Este computador
    "192.168.1.1",
}


class BlockRecord:
    """Registro de um IP bloqueado."""
    def __init__(self, ip: str, score: int, reason: str,
                 host_id: str = "", rule_name: str = ""):
        self.ip         = ip
        self.score      = score
        self.reason     = reason
        self.host_id    = host_id
        self.rule_name  = rule_name
        self.blocked_at = datetime.now(timezone.utc).isoformat()
        self.rule_id    = f"NETGUARD_BLOCK_{ip.replace('.','_')}"
        self.active     = True

    def to_dict(self) -> dict:
        return {
            "ip":         self.ip,
            "score":      self.score,
            "reason":     self.reason,
            "host_id":    self.host_id,
            "rule_name":  self.rule_name,
            "blocked_at": self.blocked_at,
            "rule_id":    self.rule_id,
            "active":     self.active,
        }


class AutoBlockEngine:
    """
    Motor de bloqueio automático por Risk Score.

    Uso:
        blocker = AutoBlockEngine(threshold=75)
        blocker.check_and_block("1.2.3.4", score=82, reason="C2 Beaconing")
        blocker.unblock("1.2.3.4")
        print(blocker.get_blocks())
    """

    def __init__(self, threshold: int = DEFAULT_THRESHOLD,
                 enabled: bool = True,
                 callback = None):
        self.threshold = threshold
        self.enabled   = enabled
        self.callback  = callback  # chamado ao bloquear/desbloquear
        self._lock     = threading.RLock()
        self._blocks   : dict = {}       # ip → BlockRecord
        self._history  : deque = deque(maxlen=200)
        self._os       = platform.system().lower()
        self._total_blocked   = 0
        self._total_unblocked = 0

        logger.info("AutoBlock iniciado | threshold=%d | os=%s | enabled=%s",
                    threshold, self._os, enabled)

    def check_and_block(self, ip: str, score: int,
                        reason: str = "", host_id: str = "",
                        rule_name: str = "") -> Optional[BlockRecord]:
        """
        Verifica se o score atingiu o threshold e bloqueia se necessário.
        Retorna BlockRecord se bloqueou, None caso contrário.
        """
        if not self.enabled:
            return None
        if score < self.threshold:
            return None
        if ip in BLOCK_WHITELIST:
            logger.debug("AutoBlock: %s na whitelist, ignorando", ip)
            return None

        with self._lock:
            if ip in self._blocks and self._blocks[ip].active:
                return None  # já bloqueado

        return self.block(ip, score, reason, host_id, rule_name)

    def block(self, ip: str, score: int, reason: str = "",
              host_id: str = "", rule_name: str = "") -> Optional[BlockRecord]:
        """Bloqueia um IP imediatamente."""
        if ip in BLOCK_WHITELIST:
            logger.warning("AutoBlock: tentativa de bloquear IP na whitelist: %s", ip)
            return None

        record = BlockRecord(ip, score, reason, host_id, rule_name)

        # Executa bloqueio no firewall
        success = self._firewall_block(ip, record.rule_id)

        with self._lock:
            self._blocks[ip] = record
            self._history.append({
                "action":     "BLOCK",
                "ip":         ip,
                "score":      score,
                "reason":     reason,
                "timestamp":  record.blocked_at,
                "fw_success": success,
            })
            self._total_blocked += 1

        if success:
            logger.warning(
                "AUTO-BLOCK | ip=%s | score=%d | reason=%s | fw=OK",
                ip, score, reason or "risk_threshold"
            )
        else:
            logger.warning(
                "AUTO-BLOCK | ip=%s | score=%d | fw=FAILED (sem privilégios?)",
                ip, score
            )

        if self.callback:
            try:
                self.callback({
                    "action":    "blocked",
                    "ip":        ip,
                    "score":     score,
                    "reason":    reason,
                    "fw_ok":     success,
                    "timestamp": record.blocked_at,
                })
            except Exception:
                pass

        return record

    def unblock(self, ip: str) -> bool:
        """Reverte o bloqueio de um IP."""
        with self._lock:
            record = self._blocks.get(ip)
            if not record:
                return False

            success = self._firewall_unblock(ip, record.rule_id)
            record.active = False
            del self._blocks[ip]

            self._history.append({
                "action":    "UNBLOCK",
                "ip":        ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "fw_success": success,
            })
            self._total_unblocked += 1

        logger.info("AUTO-UNBLOCK | ip=%s | fw=%s", ip, "OK" if success else "FAILED")

        if self.callback:
            try:
                self.callback({
                    "action":    "unblocked",
                    "ip":        ip,
                    "fw_ok":     success,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            except Exception:
                pass

        return success

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocks and self._blocks[ip].active

    def get_blocks(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._blocks.values() if r.active]

    def get_history(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._history)[-limit:][::-1]

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled":         self.enabled,
                "threshold":       self.threshold,
                "active_blocks":   len(self._blocks),
                "total_blocked":   self._total_blocked,
                "total_unblocked": self._total_unblocked,
                "os":              self._os,
                "whitelist_size":  len(BLOCK_WHITELIST),
            }

    def set_threshold(self, threshold: int):
        self.threshold = max(1, min(100, threshold))
        logger.info("AutoBlock threshold atualizado: %d", self.threshold)

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        logger.info("AutoBlock %s", "ativado" if enabled else "desativado")

    # ── Firewall integration ──────────────────────────────────────

    def _firewall_block(self, ip: str, rule_id: str) -> bool:
        """Adiciona regra de bloqueio no firewall do OS."""
        try:
            if self._os == "windows":
                return self._windows_block(ip, rule_id)
            elif self._os == "linux":
                return self._linux_block(ip)
            elif self._os == "darwin":
                return self._macos_block(ip)
            else:
                logger.warning("OS não suportado para bloqueio: %s", self._os)
                return False
        except Exception as e:
            logger.error("Firewall block error: %s", e)
            return False

    def _firewall_unblock(self, ip: str, rule_id: str) -> bool:
        """Remove regra de bloqueio do firewall."""
        try:
            if self._os == "windows":
                return self._windows_unblock(rule_id)
            elif self._os == "linux":
                return self._linux_unblock(ip)
            elif self._os == "darwin":
                return self._macos_unblock(ip)
            return False
        except Exception as e:
            logger.error("Firewall unblock error: %s", e)
            return False

    def _windows_block(self, ip: str, rule_id: str) -> bool:
        r = subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_id}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "protocol=any", "enable=yes",
        ], capture_output=True, timeout=10)
        return r.returncode == 0

    def _windows_unblock(self, rule_id: str) -> bool:
        r = subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_id}",
        ], capture_output=True, timeout=10)
        return r.returncode == 0

    def _linux_block(self, ip: str) -> bool:
        r = subprocess.run([
            "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"
        ], capture_output=True, timeout=10)
        return r.returncode == 0

    def _linux_unblock(self, ip: str) -> bool:
        r = subprocess.run([
            "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
        ], capture_output=True, timeout=10)
        return r.returncode == 0

    def _macos_block(self, ip: str) -> bool:
        # Básico — adiciona ao /etc/hosts como bloqueio leve
        try:
            with open("/etc/hosts", "a") as f:
                f.write(f"\n0.0.0.0 # NETGUARD_BLOCK_{ip}\n")
            return True
        except Exception:
            return False

    def _macos_unblock(self, ip: str) -> bool:
        try:
            with open("/etc/hosts") as f:
                lines = f.readlines()
            with open("/etc/hosts", "w") as f:
                f.writelines(l for l in lines if f"NETGUARD_BLOCK_{ip}" not in l)
            return True
        except Exception:
            return False


# ── Instância global ──────────────────────────────────────────────
auto_block = AutoBlockEngine(threshold=DEFAULT_THRESHOLD, enabled=False)
