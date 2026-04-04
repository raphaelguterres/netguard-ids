"""
NetGuard — Threat Hunting Engine
Query language para busca em eventos históricos.

Sintaxe:
  field=value                    → igualdade
  field!=value                   → diferente
  field~value                    → contém (like)
  field>N  field<N  field>=N     → numérico
  expr AND expr                  → ambos
  expr OR expr                   → qualquer
  NOT expr                       → negação

Campos disponíveis:
  process, ip, port, severity, rule, host,
  type, tag, conn_count, cpu

Exemplos:
  process="powershell" AND severity="HIGH"
  ip~"185.220" OR ip~"10.0"
  rule="Brute Force" AND host="server-01"
  severity="CRITICAL" AND NOT process="svchost"
  conn_count>50 AND severity!="LOW"
"""

import re  # noqa: F401
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple  # noqa: F401

logger = logging.getLogger("netguard.hunter")

# ── Token types ───────────────────────────────────────────────────
TK_FIELD  = "FIELD"
TK_OP     = "OP"
TK_VALUE  = "VALUE"
TK_AND    = "AND"
TK_OR     = "OR"
TK_NOT    = "NOT"
TK_LPAREN = "LPAREN"
TK_RPAREN = "RPAREN"
TK_EOF    = "EOF"

# Map query field aliases → DB columns + extraction
FIELD_MAP = {
    "process":    ("details", "process"),
    "proc":       ("details", "process"),
    "ip":         ("details", "ip"),
    "src_ip":     ("details", "source_ip"),
    "dst_ip":     ("details", "dst_ip"),
    "port":       ("details", "port"),
    "severity":   ("severity", None),
    "sev":        ("severity", None),
    "rule":       ("rule_name", None),
    "rule_id":    ("rule_id", None),
    "host":       ("host_id", None),
    "host_id":    ("host_id", None),
    "type":       ("event_type", None),
    "event_type": ("event_type", None),
    "tag":        ("tags", None),
    "source":     ("source", None),
    "cpu":        ("details", "cpu_usage"),
    "conn_count": ("details", "conn_count"),
    "pid":        ("details", "pid"),
    "exe":        ("details", "exe"),
    "domain":     ("details", "domain"),
}

OPERATORS = {"=", "!=", "~", "!~", ">", "<", ">=", "<="}


class Token:
    def __init__(self, kind: str, value: str):
        self.kind  = kind
        self.value = value

    def __repr__(self):
        return f"Token({self.kind}, {self.value!r})"


class Lexer:
    """Tokeniza a query string."""

    def __init__(self, text: str):
        self.text = text.strip()
        self.pos  = 0
        self.tokens: List[Token] = []
        self._tokenize()

    def _tokenize(self):
        i = 0
        text = self.text
        while i < len(text):
            # Skip whitespace
            if text[i].isspace():
                i += 1
                continue

            # Parentheses
            if text[i] == '(':
                self.tokens.append(Token(TK_LPAREN, '('))
                i += 1
                continue
            if text[i] == ')':
                self.tokens.append(Token(TK_RPAREN, ')'))
                i += 1
                continue

            # Keywords AND OR NOT (case-insensitive)
            for kw, tk in [("AND", TK_AND), ("OR", TK_OR), ("NOT", TK_NOT)]:
                if text[i:i+len(kw)].upper() == kw:
                    next_ch = text[i+len(kw)] if i+len(kw) < len(text) else ' '
                    if not next_ch.isalnum() and next_ch != '_':
                        self.tokens.append(Token(tk, kw))
                        i += len(kw)
                        break
            else:
                # Operator: >=, <=, !=, !~, =, ~, >, <
                matched_op = None
                for op in [">=", "<=", "!=", "!~", "=", "~", ">", "<"]:
                    if text[i:i+len(op)] == op:
                        matched_op = op
                        break

                if matched_op:
                    # Everything before this is the field
                    # Find field start (go back to last non-field char)
                    self.tokens.append(Token(TK_OP, matched_op))
                    i += len(matched_op)
                    # Now read value
                    if i < len(text) and text[i] == '"':
                        # Quoted value
                        j = i + 1
                        while j < len(text) and text[j] != '"':
                            j += 1
                        self.tokens.append(Token(TK_VALUE, text[i+1:j]))
                        i = j + 1
                    else:
                        # Unquoted value
                        j = i
                        while j < len(text) and not text[j].isspace() and text[j] not in '()':
                            j += 1
                        self.tokens.append(Token(TK_VALUE, text[i:j]))
                        i = j
                    continue

                # Field name (identifier)
                if text[i].isalpha() or text[i] == '_':
                    j = i
                    while j < len(text) and (text[j].isalnum() or text[j] == '_'):
                        j += 1
                    word = text[i:j]
                    # Check if it's a keyword
                    if word.upper() == "AND":
                        self.tokens.append(Token(TK_AND, word))
                    elif word.upper() == "OR":
                        self.tokens.append(Token(TK_OR, word))
                    elif word.upper() == "NOT":
                        self.tokens.append(Token(TK_NOT, word))
                    else:
                        self.tokens.append(Token(TK_FIELD, word.lower()))
                    i = j
                    continue

                i += 1  # Skip unknown

        self.tokens.append(Token(TK_EOF, ""))


class QueryParser:
    """
    Converte tokens em SQL WHERE clause.
    Grammar:
      expr     := or_expr
      or_expr  := and_expr (OR and_expr)*
      and_expr := not_expr (AND not_expr)*
      not_expr := NOT not_expr | atom
      atom     := (expr) | field op value
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos    = 0
        self.params: List[Any] = []

    def current(self) -> Token:
        return self.tokens[self.pos]

    def consume(self, kind: str = None) -> Token:
        tok = self.tokens[self.pos]
        if kind and tok.kind != kind:
            raise ValueError(f"Expected {kind}, got {tok.kind} ({tok.value!r})")
        self.pos += 1
        return tok

    def parse(self) -> str:
        sql = self.parse_or()
        if self.current().kind != TK_EOF:
            raise ValueError(f"Unexpected token: {self.current().value!r}")
        return sql

    def parse_or(self) -> str:
        left = self.parse_and()
        while self.current().kind == TK_OR:
            self.consume(TK_OR)
            right = self.parse_and()
            left = f"({left} OR {right})"
        return left

    def parse_and(self) -> str:
        left = self.parse_not()
        while self.current().kind == TK_AND:
            self.consume(TK_AND)
            right = self.parse_not()
            left = f"({left} AND {right})"
        return left

    def parse_not(self) -> str:
        if self.current().kind == TK_NOT:
            self.consume(TK_NOT)
            expr = self.parse_atom()
            return f"NOT ({expr})"
        return self.parse_atom()

    def parse_atom(self) -> str:
        if self.current().kind == TK_LPAREN:
            self.consume(TK_LPAREN)
            expr = self.parse_or()
            self.consume(TK_RPAREN)
            return f"({expr})"

        # field op value
        field_tok = self.consume(TK_FIELD)
        op_tok    = self.consume(TK_OP)
        val_tok   = self.consume(TK_VALUE)

        field = field_tok.value
        op    = op_tok.value
        value = val_tok.value

        return self._build_condition(field, op, value)

    def _build_condition(self, field: str, op: str, value: str) -> str:
        mapping = FIELD_MAP.get(field)
        if not mapping:
            raise ValueError(f"Campo desconhecido: '{field}'. "
                             f"Campos válidos: {list(FIELD_MAP.keys())}")

        col, json_key = mapping

        # Direct column (not JSON)
        if json_key is None:
            if op == "=":
                self.params.append(value.upper() if col == "severity" else value)
                return f"UPPER({col}) = UPPER(?)"
            elif op == "!=":
                self.params.append(value)
                return f"UPPER({col}) != UPPER(?)"
            elif op == "~":
                self.params.append(f"%{value}%")
                return f"{col} LIKE ? COLLATE NOCASE"
            elif op == "!~":
                self.params.append(f"%{value}%")
                return f"{col} NOT LIKE ? COLLATE NOCASE"
            elif op in (">", "<", ">=", "<="):
                try:
                    num = float(value)
                    self.params.append(num)
                    return f"CAST({col} AS REAL) {op} ?"
                except ValueError:
                    self.params.append(value)
                    return f"{col} {op} ?"
            else:
                raise ValueError(f"Operador '{op}' não suportado para campo '{field}'")

        # JSON field extraction
        json_path = f"$.{json_key}"
        extracted = f"json_extract(details, '{json_path}')"

        if op == "=":
            self.params.append(value)
            return f"UPPER(COALESCE({extracted},'')) = UPPER(?)"
        elif op == "!=":
            self.params.append(value)
            return f"UPPER(COALESCE({extracted},'')) != UPPER(?)"
        elif op == "~":
            self.params.append(f"%{value}%")
            return f"COALESCE({extracted},'') LIKE ? COLLATE NOCASE"
        elif op == "!~":
            self.params.append(f"%{value}%")
            return f"COALESCE({extracted},'') NOT LIKE ? COLLATE NOCASE"
        elif op in (">", "<", ">=", "<="):
            try:
                num = float(value)
                self.params.append(num)
                return f"CAST(COALESCE({extracted},0) AS REAL) {op} ?"
            except ValueError:
                raise ValueError(f"Valor numérico esperado para '{field} {op}', mas recebeu '{value}'")
        else:
            raise ValueError(f"Operador '{op}' não suportado")


class ThreatHunter:
    """
    Motor de Threat Hunting.
    Executa queries na base de eventos históricos.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        logger.info("ThreatHunter iniciado | db=%s", db_path)

    def hunt(self, query: str, limit: int = 200,
             hours: int = 24, host_id: str = "") -> Dict[str, Any]:
        """
        Executa uma query de threat hunting.

        Returns:
          {
            "query":    str,
            "sql":      str,
            "results":  list of events,
            "count":    int,
            "elapsed_ms": float,
            "error":    str or None
          }
        """
        import time
        t0 = time.monotonic()

        result = {
            "query":      query,
            "sql":        "",
            "results":    [],
            "count":      0,
            "elapsed_ms": 0,
            "error":      None,
        }

        try:
            where_clause, params = self._compile(query)
        except ValueError as e:
            result["error"] = str(e)
            return result

        # Time window
        since = (datetime.now(timezone.utc) -
                 timedelta(hours=hours)).isoformat()
        params_full = [since] + params
        host_clause = ""
        if host_id:
            host_clause = "AND host_id = ?"
            params_full.append(host_id)

        sql = f"""
            SELECT event_id, timestamp, host_id, event_type, severity,
                   source, rule_id, rule_name, details, mitre, tags
            FROM events
            WHERE timestamp >= ?
            {host_clause}
            AND ({where_clause})
            ORDER BY timestamp DESC
            LIMIT {int(limit)}
        """

        result["sql"] = sql.strip()

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params_full).fetchall()
            conn.close()

            events = []
            for row in rows:
                ev = dict(row)
                try:
                    ev["details"] = json.loads(ev.get("details") or "{}")
                except Exception:
                    ev["details"] = {}
                try:
                    ev["mitre"] = json.loads(ev.get("mitre") or "{}")
                except Exception:
                    ev["mitre"] = {}
                try:
                    ev["tags"] = json.loads(ev.get("tags") or "[]")
                except Exception:
                    ev["tags"] = []
                events.append(ev)

            result["results"] = events
            result["count"]   = len(events)

        except Exception as e:
            result["error"] = f"DB error: {e}"
            logger.error("ThreatHunter DB error: %s", e)

        result["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("Hunt: %d results in %dms | query=%s",
                    result["count"], result["elapsed_ms"], query[:60])
        return result

    def _compile(self, query: str) -> Tuple[str, List]:
        """Compila query string em SQL WHERE + params."""
        if not query.strip():
            raise ValueError("Query vazia")
        lexer  = Lexer(query)
        parser = QueryParser(lexer.tokens)
        where  = parser.parse()
        return where, parser.params

    def validate(self, query: str) -> Dict[str, Any]:
        """Valida sintaxe sem executar."""
        try:
            where, params = self._compile(query)
            return {"valid": True, "sql": where, "params_count": len(params)}
        except ValueError as e:
            return {"valid": False, "error": str(e)}

    def suggest_queries(self) -> List[Dict]:
        """Retorna queries de exemplo pré-definidas."""
        return [
            {
                "name":  "PowerShell suspeito",
                "query": 'process~"powershell" AND severity="HIGH"',
                "desc":  "Processos PowerShell com severidade HIGH"
            },
            {
                "name":  "Conexões externas suspeitas",
                "query": 'type="ip_new_external" AND severity!="LOW"',
                "desc":  "Novos IPs externos com severidade relevante"
            },
            {
                "name":  "Brute force",
                "query": 'rule~"Brute Force"',
                "desc":  "Todos os eventos de brute force"
            },
            {
                "name":  "CPU alta",
                "query": 'type="process_high_cpu" AND severity="HIGH"',
                "desc":  "Processos com CPU alta detectados"
            },
            {
                "name":  "Críticos nas últimas 24h",
                "query": 'severity="CRITICAL"',
                "desc":  "Todos os eventos críticos"
            },
            {
                "name":  "SQLi ou XSS",
                "query": 'type="web_sqli" OR type="web_xss"',
                "desc":  "Ataques web detectados"
            },
            {
                "name":  "Kill chain - execução",
                "query": 'type~"process" AND severity!="LOW"',
                "desc":  "Eventos de fase de execução"
            },
            {
                "name":  "Porta nova em LISTEN",
                "query": 'type="port_new_listen"',
                "desc":  "Novas portas abertas para escuta"
            },
        ]
