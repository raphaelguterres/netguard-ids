"""
NetGuard IDS — Custom Detection Rules
Permite que clientes criem, editem e ativem regras de detecção personalizadas.

Formato de regra:
    {
      "rule_id":    "CR-001",
      "name":       "Acesso fora do horário",
      "description":"Detecta logins entre 00h e 06h",
      "conditions": [
          {"field": "event_type", "op": "contains", "value": "login"},
          {"field": "hour",       "op": "between",  "value": [0, 6]}
      ],
      "logic":      "AND",   # AND | OR
      "severity":   "HIGH",
      "tags":       ["off-hours", "auth"],
      "enabled":    true
    }

Operadores suportados:
    eq, ne, contains, not_contains, starts_with, ends_with,
    gt, lt, gte, lte, between, in, not_in, regex, exists

Campos disponíveis:
    severity, event_type, source, rule_id, rule_name, host_id,
    raw, details.<key>, tags, hour, weekday, timestamp
"""

from __future__ import annotations  # noqa: F401

import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("ids.custom_rules")

# ── Operadores suportados ─────────────────────────────────────────────────────
OPERATORS = {
    "eq", "ne", "contains", "not_contains",
    "starts_with", "ends_with",
    "gt", "lt", "gte", "lte", "between",
    "in", "not_in", "regex", "exists",
}

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# ── DDL ───────────────────────────────────────────────────────────────────────
DDL_CUSTOM_RULES = """
CREATE TABLE IF NOT EXISTS custom_rules (
    rule_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    conditions  TEXT NOT NULL DEFAULT '[]',   -- JSON array of conditions
    logic       TEXT NOT NULL DEFAULT 'AND',  -- AND | OR
    severity    TEXT NOT NULL DEFAULT 'MEDIUM',
    tags        TEXT NOT NULL DEFAULT '[]',   -- JSON array
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    created_by  TEXT DEFAULT 'user',
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_hit    TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_tenant
    ON custom_rules (tenant_id, enabled);
"""

DDL_CUSTOM_HITS = """
CREATE TABLE IF NOT EXISTS custom_rule_hits (
    hit_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    event_id    TEXT,
    matched_at  TEXT NOT NULL,
    context     TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_custom_hits_tenant
    ON custom_rule_hits (tenant_id, matched_at DESC);
"""


# ── Extração de campo de evento ───────────────────────────────────────────────
def _extract_field(event: dict, field: str) -> Any:
    """Extrai valor de um campo do evento, suportando campos computados e details.<key>."""
    if field.startswith("details."):
        key     = field[8:]
        details = event.get("details") or {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (json.JSONDecodeError, ValueError):
                details = {}
        return details.get(key)

    if field == "hour":
        ts = event.get("timestamp") or ""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.hour
        except (ValueError, AttributeError):
            return None

    if field == "weekday":
        ts = event.get("timestamp") or ""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.weekday()  # 0=Mon, 6=Sun
        except (ValueError, AttributeError):
            return None

    return event.get(field)


# ── Avaliação de condição ─────────────────────────────────────────────────────
def _eval_condition(event: dict, condition: dict) -> bool:
    """Avalia uma condição contra um evento. Retorna True se matched."""
    field = condition.get("field", "")
    op    = condition.get("op", "eq")
    value = condition.get("value")

    actual = _extract_field(event, field)

    if op == "exists":
        return actual is not None and actual != ""

    if actual is None:
        return False

    # Normaliza para string para comparações textuais
    actual_str = str(actual).lower()
    value_str  = str(value).lower() if isinstance(value, str) else str(value)

    if op == "eq":
        return actual_str == value_str
    elif op == "ne":
        return actual_str != value_str
    elif op == "contains":
        return value_str in actual_str
    elif op == "not_contains":
        return value_str not in actual_str
    elif op == "starts_with":
        return actual_str.startswith(value_str)
    elif op == "ends_with":
        return actual_str.endswith(value_str)
    elif op == "regex":
        try:
            return bool(re.search(value_str, actual_str))
        except re.error:
            return False
    elif op in ("gt", "lt", "gte", "lte"):
        try:
            a = float(actual)
            v = float(value)
            if op == "gt":  return a > v
            if op == "lt":  return a < v
            if op == "gte": return a >= v
            if op == "lte": return a <= v
        except (TypeError, ValueError):
            return False
    elif op == "between":
        try:
            a   = float(actual)
            lo  = float(value[0])
            hi  = float(value[1])
            return lo <= a <= hi
        except (TypeError, ValueError, IndexError):
            return False
    elif op == "in":
        vals = [str(v).lower() for v in (value if isinstance(value, list) else [value])]
        return actual_str in vals
    elif op == "not_in":
        vals = [str(v).lower() for v in (value if isinstance(value, list) else [value])]
        return actual_str not in vals

    return False


def evaluate_rule(rule: dict, event: dict) -> bool:
    """
    Avalia uma regra customizada contra um evento.
    Retorna True se o evento satisfaz as condições da regra.
    """
    conditions = rule.get("conditions") or []
    if not conditions:
        return False

    if isinstance(conditions, str):
        try:
            conditions = json.loads(conditions)
        except (json.JSONDecodeError, ValueError):
            return False

    logic = (rule.get("logic") or "AND").upper()

    results = [_eval_condition(event, cond) for cond in conditions]

    if logic == "OR":
        return any(results)
    return all(results)  # AND (default)


# ── Manager ───────────────────────────────────────────────────────────────────
class CustomRuleEngine:
    """
    Gerencia regras de detecção customizadas por tenant.
    """

    def __init__(self, db_path: str = "netguard_events.db",
                 tenant_id: str = "default"):
        self.db_path   = db_path
        self.tenant_id = tenant_id
        self._rules_cache: Optional[list[dict]] = None
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(DDL_CUSTOM_RULES + DDL_CUSTOM_HITS)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ── Cache ──────────────────────────────────────────────────────────────
    def _load_rules_cache(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM custom_rules WHERE tenant_id=? AND enabled=1",
                (self.tenant_id,)
            ).fetchall()
        rules = []
        for r in rows:
            d = dict(r)
            d["conditions"] = json.loads(d.get("conditions") or "[]")
            d["tags"]       = json.loads(d.get("tags") or "[]")
            rules.append(d)
        self._rules_cache = rules
        return rules

    def _invalidate(self) -> None:
        self._rules_cache = None

    # ── Check ──────────────────────────────────────────────────────────────
    def check_event(self, event: dict) -> list[dict]:
        """
        Verifica um evento contra todas as regras ativas.
        Retorna lista de regras que fizeram match.
        """
        rules  = self._rules_cache if self._rules_cache is not None else self._load_rules_cache()
        hits   = []
        now    = datetime.now(timezone.utc).isoformat()
        event_id = event.get("event_id", "")

        for rule in rules:
            if evaluate_rule(rule, event):
                hit = {
                    "rule_id":   rule["rule_id"],
                    "rule_name": rule["name"],
                    "severity":  rule["severity"],
                    "tags":      rule.get("tags", []),
                    "matched_at": now,
                }
                hits.append(hit)
                self._record_hit(rule["rule_id"], event_id, now)

        return hits

    def _record_hit(self, rule_id: str, event_id: str, now: str) -> None:
        try:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE custom_rules SET hit_count=hit_count+1, last_hit=? "
                    "WHERE rule_id=? AND tenant_id=?",
                    (now, rule_id, self.tenant_id)
                )
                conn.execute(
                    "INSERT OR IGNORE INTO custom_rule_hits VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), self.tenant_id, rule_id,
                     event_id or None, now, "{}")
                )
        except Exception as e:
            logger.debug("Custom rule hit record failed: %s", e)

    # ── CRUD ──────────────────────────────────────────────────────────────
    def create_rule(self, name: str, conditions: list,
                    logic: str = "AND", severity: str = "MEDIUM",
                    description: str = "", tags: list = None,
                    created_by: str = "user") -> dict:
        """Cria uma nova regra customizada. Retorna o registro criado."""
        self._validate_rule(name, conditions, logic, severity)
        now     = datetime.now(timezone.utc).isoformat()
        rule_id = f"CR-{str(uuid.uuid4())[:8].upper()}"
        row = (
            rule_id, self.tenant_id, name, description,
            json.dumps(conditions), logic.upper(),
            severity.upper(), json.dumps(tags or []),
            1, now, now, created_by, 0, None
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO custom_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row
            )
        self._invalidate()
        logger.info("Custom rule created: %s '%s'", rule_id, name)
        return self.get_rule(rule_id)

    def update_rule(self, rule_id: str, **kwargs) -> Optional[dict]:
        """Atualiza campos de uma regra existente."""
        allowed = {"name", "description", "conditions", "logic",
                   "severity", "tags", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_rule(rule_id)

        # Serializa listas
        if "conditions" in updates:
            self._validate_conditions(updates["conditions"])
            updates["conditions"] = json.dumps(updates["conditions"])
        if "tags" in updates:
            updates["tags"] = json.dumps(updates["tags"] if isinstance(updates["tags"], list) else [])
        if "logic" in updates:
            updates["logic"] = updates["logic"].upper()
        if "severity" in updates:
            updates["severity"] = updates["severity"].upper()
            if updates["severity"] not in SEVERITY_LEVELS:
                raise ValueError(f"Severidade inválida: {updates['severity']}")

        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now

        set_clause = ", ".join(f"{k}=?" for k in updates)
        values     = list(updates.values()) + [rule_id, self.tenant_id]

        with self._conn() as conn:
            conn.execute(
                f"UPDATE custom_rules SET {set_clause} "
                f"WHERE rule_id=? AND tenant_id=?",
                values
            )
        self._invalidate()
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        with self._conn() as conn:
            r = conn.execute(
                "DELETE FROM custom_rules WHERE rule_id=? AND tenant_id=?",
                (rule_id, self.tenant_id)
            )
        self._invalidate()
        return r.rowcount > 0

    def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[dict]:
        return self.update_rule(rule_id, enabled=1 if enabled else 0)

    def get_rule(self, rule_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM custom_rules WHERE rule_id=? AND tenant_id=?",
                (rule_id, self.tenant_id)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["conditions"] = json.loads(d.get("conditions") or "[]")
        d["tags"]       = json.loads(d.get("tags") or "[]")
        return d

    def list_rules(self, enabled_only: bool = False) -> list[dict]:
        where  = ["tenant_id=?"]
        params = [self.tenant_id]
        if enabled_only:
            where.append("enabled=1")
        sql = f"SELECT * FROM custom_rules WHERE {' AND '.join(where)} ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["conditions"] = json.loads(d.get("conditions") or "[]")
            d["tags"]       = json.loads(d.get("tags") or "[]")
            result.append(d)
        return result

    def stats(self) -> dict:
        with self._conn() as conn:
            total   = conn.execute(
                "SELECT COUNT(*) FROM custom_rules WHERE tenant_id=?",
                (self.tenant_id,)
            ).fetchone()[0]
            active  = conn.execute(
                "SELECT COUNT(*) FROM custom_rules WHERE tenant_id=? AND enabled=1",
                (self.tenant_id,)
            ).fetchone()[0]
            hits    = conn.execute(
                "SELECT SUM(hit_count) FROM custom_rules WHERE tenant_id=?",
                (self.tenant_id,)
            ).fetchone()[0] or 0
        return {"total_rules": total, "active_rules": active, "total_hits": hits}

    def test_rule(self, rule: dict, sample_events: list[dict]) -> list[dict]:
        """
        Testa uma regra contra uma lista de eventos de amostra.
        Útil para validar a regra antes de ativar.
        """
        results = []
        for ev in sample_events:
            matched = evaluate_rule(rule, ev)
            results.append({
                "event_id": ev.get("event_id", ""),
                "matched":  matched,
                "event_type": ev.get("event_type", ""),
                "severity": ev.get("severity", ""),
            })
        return results

    # ── Validação ──────────────────────────────────────────────────────────
    def _validate_rule(self, name: str, conditions: list,
                        logic: str, severity: str) -> None:
        if not name or not name.strip():
            raise ValueError("Nome da regra é obrigatório.")
        if len(name) > 120:
            raise ValueError("Nome máximo: 120 caracteres.")
        if not conditions:
            raise ValueError("A regra precisa ter pelo menos uma condição.")
        self._validate_conditions(conditions)
        if logic.upper() not in ("AND", "OR"):
            raise ValueError("Logic deve ser AND ou OR.")
        if severity.upper() not in SEVERITY_LEVELS:
            raise ValueError(f"Severidade inválida. Use: {SEVERITY_LEVELS}")

    def _validate_conditions(self, conditions: list) -> None:
        if not isinstance(conditions, list):
            raise ValueError("Conditions deve ser uma lista.")
        for i, cond in enumerate(conditions):
            if not isinstance(cond, dict):
                raise ValueError(f"Condição {i+1} deve ser um objeto.")
            if not cond.get("field"):
                raise ValueError(f"Condição {i+1}: campo 'field' é obrigatório.")
            if cond.get("op") not in OPERATORS:
                raise ValueError(
                    f"Condição {i+1}: operador '{cond.get('op')}' inválido. "
                    f"Use: {sorted(OPERATORS)}"
                )


# ── Singleton ──────────────────────────────────────────────────────────────────
_engines: dict[str, CustomRuleEngine] = {}


def get_custom_rule_engine(db_path: str = "netguard_events.db",
                            tenant_id: str = "default") -> CustomRuleEngine:
    key = f"{db_path}::{tenant_id}"
    if key not in _engines:
        _engines[key] = CustomRuleEngine(db_path=db_path, tenant_id=tenant_id)
    return _engines[key]
