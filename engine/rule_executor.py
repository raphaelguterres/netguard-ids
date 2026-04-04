"""
NetGuard — Rule Executor
Pipeline de execução de regras de detecção.

Responsabilidades:
- Receber evento normalizado + lista de regras
- Executar cada regra com isolamento de erro
- Coletar e padronizar alertas gerados
- Retornar lista de alertas válidos

Design:
- Cada regra é uma função ou classe callable
- Falha em uma regra não para o pipeline
- Suporta regras síncronas e assíncronas (via wrapper)
- Métricas de execução incluídas
"""

import time
import logging
import traceback
from typing import Callable, Any, Optional  # noqa: F401
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = logging.getLogger("netguard.rule_executor")


# ── Alert model ───────────────────────────────────────────────────
@dataclass
class Alert:
    """
    Alerta gerado por uma regra de detecção.
    Estrutura padronizada para consumo pelo dashboard e storage.
    """
    rule_name:   str
    event_type:  str
    severity:    str
    description: str
    details:     dict

    # Auto-populados
    timestamp:   str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host_id:     str   = ""
    source:      str   = "engine.rule_executor"
    rule_id:     str   = ""
    mitre_tactic:  str = ""
    mitre_tech:    str = ""
    tags:        list  = field(default_factory=list)
    raw:         str   = ""

    def to_dict(self) -> dict:
        return {
            "timestamp":    self.timestamp,
            "host_id":      self.host_id,
            "rule_id":      self.rule_id,
            "rule_name":    self.rule_name,
            "event_type":   self.event_type,
            "severity":     self.severity,
            "source":       self.source,
            "description":  self.description,
            "details":      self.details,
            "mitre": {
                "tactic":    self.mitre_tactic,
                "technique": self.mitre_tech,
            },
            "tags":         self.tags,
            "raw":          self.raw[:300] if self.raw else "",
        }


# ── Rule interface ────────────────────────────────────────────────
# Uma regra é qualquer callable com assinatura:
#   rule(event: dict) -> Optional[Alert | list[Alert]]
#
# Convenção de retorno:
#   - None       → sem alerta
#   - Alert      → um alerta
#   - list[Alert] → múltiplos alertas
#
RuleFunc = Callable[[dict], Optional[Alert | list]]


# ── Execution result ─────────────────────────────────────────────
@dataclass
class ExecutionResult:
    """Resultado da execução do pipeline de regras."""
    alerts:          list[Alert]
    rules_executed:  int
    rules_triggered: int
    rules_failed:    int
    duration_ms:     float
    errors:          list[dict]

    @property
    def has_alerts(self) -> bool:
        return len(self.alerts) > 0

    @property
    def highest_severity(self) -> str:
        if not self.alerts:
            return "LOW"
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return max(self.alerts, key=lambda a: order.get(a.severity, 0)).severity

    def to_dict(self) -> dict:
        return {
            "alerts":          [a.to_dict() for a in self.alerts],
            "rules_executed":  self.rules_executed,
            "rules_triggered": self.rules_triggered,
            "rules_failed":    self.rules_failed,
            "duration_ms":     round(self.duration_ms, 2),
            "has_alerts":      self.has_alerts,
            "highest_severity": self.highest_severity,
        }


# ── Core executor ─────────────────────────────────────────────────
def execute_rules(
    event:  dict,
    rules:  list[RuleFunc],
    strict: bool = False,
) -> ExecutionResult:
    """
    Executa lista de regras contra um evento normalizado.

    Args:
        event:  Evento normalizado (dict com estrutura padrão)
        rules:  Lista de funções de regra
        strict: Se True, re-lança exceções (útil em tests)

    Returns:
        ExecutionResult com todos os alertas coletados
    """
    alerts:  list[Alert] = []
    errors:  list[dict]  = []
    triggered = 0
    failed    = 0

    host_id = event.get("host_id", "")
    t_start = time.perf_counter()

    for rule_fn in rules:
        rule_name = _get_rule_name(rule_fn)
        try:
            result = rule_fn(event)

            if result is None:
                continue

            # Normaliza resultado para lista
            raw_alerts = result if isinstance(result, list) else [result]

            for alert in raw_alerts:
                if not isinstance(alert, Alert):
                    logger.warning("Rule %s returned non-Alert: %s", rule_name, type(alert))
                    continue
                # Injeta host_id se ausente
                if not alert.host_id:
                    alert.host_id = host_id
                alerts.append(alert)
                triggered += 1

        except Exception as exc:
            failed += 1
            err_detail = {
                "rule":    rule_name,
                "error":   str(exc),
                "trace":   traceback.format_exc()[-500:],
            }
            errors.append(err_detail)
            logger.error("Rule %s failed: %s", rule_name, exc)
            if strict:
                raise

    duration_ms = (time.perf_counter() - t_start) * 1000

    if alerts:
        logger.info(
            "Rules executed=%d triggered=%d failed=%d alerts=%d host=%s",
            len(rules), triggered, failed, len(alerts), host_id
        )

    return ExecutionResult(
        alerts          = alerts,
        rules_executed  = len(rules),
        rules_triggered = triggered,
        rules_failed    = failed,
        duration_ms     = duration_ms,
        errors          = errors,
    )


def _get_rule_name(rule_fn: RuleFunc) -> str:
    """Extrai nome legível de uma função de regra."""
    if hasattr(rule_fn, "rule_name"):
        return rule_fn.rule_name
    if hasattr(rule_fn, "__name__"):
        return rule_fn.__name__
    if hasattr(rule_fn, "__class__"):
        return rule_fn.__class__.__name__
    return "unknown_rule"


# ── Rule registry ─────────────────────────────────────────────────
class RuleRegistry:
    """
    Registro central de regras de detecção.
    Permite registrar, habilitar/desabilitar e listar regras.

    Uso:
        registry = RuleRegistry()
        registry.register(my_rule, tags=["process", "baseline"])
        alerts = registry.execute(event)
    """

    def __init__(self):
        self._rules: list[dict] = []

    def register(
        self,
        rule_fn:  RuleFunc,
        enabled:  bool = True,
        tags:     list[str] = None,
        rule_id:  str = "",
    ) -> "RuleRegistry":
        """Registra uma regra. Retorna self para chaining."""
        self._rules.append({
            "fn":      rule_fn,
            "name":    _get_rule_name(rule_fn),
            "enabled": enabled,
            "tags":    tags or [],
            "id":      rule_id or _get_rule_name(rule_fn),
        })
        logger.debug("Registered rule: %s", _get_rule_name(rule_fn))
        return self

    def register_many(self, rules: list[RuleFunc]) -> "RuleRegistry":
        for r in rules:
            self.register(r)
        return self

    def disable(self, rule_name: str) -> None:
        for r in self._rules:
            if r["name"] == rule_name:
                r["enabled"] = False

    def enable(self, rule_name: str) -> None:
        for r in self._rules:
            if r["name"] == rule_name:
                r["enabled"] = True

    def execute(self, event: dict, tags: list[str] = None) -> ExecutionResult:
        """
        Executa todas as regras habilitadas contra um evento.
        Se tags fornecidas, executa apenas regras com pelo menos uma tag em comum.
        """
        active = [
            r["fn"] for r in self._rules
            if r["enabled"] and (
                not tags or any(t in r["tags"] for t in tags)
            )
        ]
        return execute_rules(event, active)

    def list_rules(self) -> list[dict]:
        return [
            {
                "id":      r["id"],
                "name":    r["name"],
                "enabled": r["enabled"],
                "tags":    r["tags"],
            }
            for r in self._rules
        ]

    @property
    def count(self) -> int:
        return len(self._rules)

    @property
    def active_count(self) -> int:
        return sum(1 for r in self._rules if r["enabled"])


# ── Helper: build alert quickly ───────────────────────────────────
def make_alert(
    rule_name:   str,
    event_type:  str,
    severity:    str,
    description: str,
    details:     dict,
    rule_id:     str  = "",
    tactic:      str  = "",
    technique:   str  = "",
    tags:        list = None,
    source:      str  = "engine.rule_executor",
    raw:         str  = "",
) -> Alert:
    """
    Factory para criar alertas de forma concisa nas regras.

    Exemplo de uso numa regra:
        return make_alert(
            rule_name   = "High CPU — Unknown Process",
            event_type  = "process_high_cpu",
            severity    = "HIGH",
            description = f"Processo {name} usando {cpu}% CPU",
            details     = {"process": name, "cpu": cpu},
            tactic      = "execution",
            technique   = "T1496",
        )
    """
    return Alert(
        rule_name    = rule_name,
        event_type   = event_type,
        severity     = severity,
        description  = description,
        details      = details,
        rule_id      = rule_id,
        source       = source,
        mitre_tactic = tactic,
        mitre_tech   = technique,
        tags         = tags or [],
        raw          = raw,
    )
