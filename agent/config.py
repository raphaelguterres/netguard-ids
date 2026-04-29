"""
Carregamento de config.yaml com defaults seguros e override por env.

Decisões de design:

- YAML simples (sem anchors/refs/anchors complexos): config de agente
  precisa ser editável por quem desploya, não só por dev. Aceita
  fallback pra JSON se PyYAML não estiver instalado (PyInstaller bundle
  pode não trazer yaml em alguns setups).

- Env vars vencem do arquivo: deploy de produção quase sempre injeta
  api_key/server_url via env (NETGUARD_AGENT_API_KEY etc) em vez de
  gravar em disco. O arquivo é fallback pra workstations dev.

- verify_tls=true por default em produção, false só com warning.
  TLS off em prod é uma porta pra MitM no segredo da API key.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("netguard.agent.config")


_DEFAULT_CONFIG_FILES = [
    "config.yaml",
    "config.yml",
    "agent_config.yaml",
]

_ENV_PREFIX = "NETGUARD_AGENT_"
_NON_PROD_ENVS = {"dev", "development", "test", "testing", "local", "demo", "ci"}


@dataclass
class AgentConfig:
    server_url: str = "https://127.0.0.1:5000/api/events"
    api_key: str = ""
    interval_seconds: int = 30
    verify_tls: bool = True
    request_timeout: int = 15
    batch_max_events: int = 200
    offline_buffer_max: int = 5000
    log_path: str = ""
    credential_path: str = ""
    enable_response_actions: bool = True
    action_poll_interval_seconds: int = 30
    allow_destructive_response_actions: bool = False
    response_policy_secret: str = ""
    tenant_id: str = ""
    tags: list[str] = field(default_factory=list)
    # Coletor: quais módulos ativar. Default tudo on; operador pode
    # desligar collectors caros em estações lentas.
    collect_processes: bool = True
    collect_connections: bool = True
    collect_security_indicators: bool = True

    def validate(self) -> None:
        if not self.server_url.startswith(("http://", "https://")):
            raise ValueError(
                "server_url precisa começar com http:// ou https:// — "
                f"recebido: {self.server_url!r}"
            )
        environment = _agent_environment()
        if self.server_url.startswith("http://") and not _insecure_transport_allowed(
            self.server_url,
            environment,
        ):
            raise ValueError(
                "server_url HTTP recusado fora de dev/test/local. "
                "Use HTTPS em producao ou defina "
                "NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT=true apenas em lab."
            )
        if self.api_key in ("", "CHANGE_ME"):
            raise ValueError(
                "api_key não configurada. Defina via env "
                "NETGUARD_AGENT_API_KEY ou no config.yaml."
            )
        if self.interval_seconds < 5:
            # Janela mínima evita DoS contra próprio servidor.
            raise ValueError("interval_seconds < 5 é abusivo no servidor")
        if self.action_poll_interval_seconds < 10:
            raise ValueError("action_poll_interval_seconds < 10 e abusivo no servidor")
        if self.allow_destructive_response_actions and len(self.response_policy_secret or "") < 32:
            raise ValueError(
                "response_policy_secret precisa ter 32+ caracteres quando "
                "allow_destructive_response_actions=true"
            )
        if not self.verify_tls and self.server_url.startswith("https://"):
            if not _insecure_transport_allowed(self.server_url, environment):
                raise ValueError(
                    "verify_tls=false recusado fora de dev/test/local. "
                    "Mantenha validacao TLS ligada em producao."
                )
            logger.warning(
                "verify_tls=false com servidor HTTPS — vulnerável a MitM. "
                "Use só em ambiente de teste."
            )


def _coerce_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _coerce_int(val, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _agent_environment() -> str:
    return (
        os.environ.get("NETGUARD_AGENT_ENV")
        or os.environ.get("IDS_ENV")
        or os.environ.get("ENVIRONMENT")
        or "production"
    ).strip().lower()


def _insecure_transport_allowed(server_url: str, environment: str) -> bool:
    if _coerce_bool(os.environ.get("NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT")):
        return True
    if environment in _NON_PROD_ENVS:
        return True
    return _is_loopback_url(server_url)


def _is_loopback_url(server_url: str) -> bool:
    host = (urlparse(server_url).hostname or "").strip().lower()
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _load_yaml_or_json(path: Path) -> dict:
    """
    Tenta YAML, depois JSON. Aceita ambos pra reduzir fricção de deploy.
    """
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-not-found]

        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("config raiz precisa ser dict")
        return data
    except ImportError:
        # Sem PyYAML: tenta interpretar como JSON. O config.yaml de
        # exemplo é compatível só se o usuário usar formato chave: valor
        # simples; pra layouts complexos, precisa instalar yaml.
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError(
                "PyYAML não instalado e config não é JSON válido. "
                "Instale pyyaml (pip install pyyaml) ou converta para JSON."
            )


def _find_config_file(explicit: str | None = None) -> Path | None:
    explicit = explicit or (os.environ.get("NETGUARD_AGENT_CONFIG") or "").strip()
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None

    # Procura no cwd, no pacote e ao lado do executavel congelado. Em Windows
    # Service, cwd pode ser System32; sys.executable aponta para agent.exe.
    here = Path(__file__).resolve().parent
    executable = Path(getattr(sys, "executable", "") or "")
    roots = [Path.cwd()]
    if executable.name:
        roots.append(executable.resolve().parent)
    roots.append(here)
    roots = list(dict.fromkeys(roots))

    candidates = []
    for name in _DEFAULT_CONFIG_FILES:
        for root in roots:
            candidates.append(root / name)
    for c in candidates:
        if c.exists():
            return c
    return None


def _apply_env_overrides(cfg: AgentConfig) -> AgentConfig:
    """
    Env wins over file. NETGUARD_AGENT_<UPPER_FIELD>=value.
    """
    mapping = {
        "SERVER_URL": ("server_url", str),
        "API_KEY": ("api_key", str),
        "INTERVAL_SECONDS": ("interval_seconds", int),
        "VERIFY_TLS": ("verify_tls", bool),
        "REQUEST_TIMEOUT": ("request_timeout", int),
        "BATCH_MAX_EVENTS": ("batch_max_events", int),
        "OFFLINE_BUFFER_MAX": ("offline_buffer_max", int),
        "LOG_PATH": ("log_path", str),
        "CREDENTIAL_PATH": ("credential_path", str),
        "ENABLE_RESPONSE_ACTIONS": ("enable_response_actions", bool),
        "ACTION_POLL_INTERVAL_SECONDS": ("action_poll_interval_seconds", int),
        "ALLOW_DESTRUCTIVE_RESPONSE_ACTIONS": ("allow_destructive_response_actions", bool),
        "RESPONSE_POLICY_SECRET": ("response_policy_secret", str),
        "TENANT_ID": ("tenant_id", str),
    }
    for env_suffix, (attr, kind) in mapping.items():
        val = os.environ.get(_ENV_PREFIX + env_suffix)
        if val is None or val == "":
            continue
        if kind is bool:
            setattr(cfg, attr, _coerce_bool(val))
        elif kind is int:
            setattr(cfg, attr, _coerce_int(val, getattr(cfg, attr)))
        else:
            setattr(cfg, attr, val)
    return cfg


def load_config(path: str | None = None) -> AgentConfig:
    """
    Carrega config do arquivo (se houver) e aplica overrides de env.
    Não chama validate() — chamador decide se é fatal ou degraded.
    """
    cfg = AgentConfig()
    cfg_path = _find_config_file(path)
    if cfg_path:
        try:
            data = _load_yaml_or_json(cfg_path)
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
            logger.info("Config carregado de %s", cfg_path)
        except Exception as exc:
            logger.error("Falha ao ler %s: %s — usando defaults", cfg_path, exc)
    else:
        logger.info("Nenhum config.yaml encontrado — usando defaults + env")

    cfg = _apply_env_overrides(cfg)
    return cfg


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    c = load_config()
    print(c)
