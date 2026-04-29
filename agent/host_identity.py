"""
Host identity — gera e persiste o host_id de forma estável entre reboots.

Decisões de design:

- UUID v4 (não derivar de MAC/hostname): MAC pode mudar (NIC trocada,
  VPN, dock). Hostname pode duplicar (clones de VM). UUID v4 é
  estável e único por instalação.

- Persistência em ProgramData (Windows) ou /var/lib (Linux): sobrevive
  a reboot, atualização do agente e logoff de usuário. Não cabe em
  AppData (escopo do user) porque o agente roda como SYSTEM/service.

- Fallback "in-memory" só pra dev: se nem ProgramData nem ~/.netguard
  forem graváveis, gera UUID em memória e segue. O server vai tratar
  cada execução como host novo, mas pelo menos o agente roda.

- Não usa hostname como host_id por questões de privacidade
  (hostname vazado em log público é PII baixa, mas vazado).
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import sys
import uuid
from pathlib import Path

logger = logging.getLogger("netguard.agent.host_identity")

_HOST_ID_FILE = "host_id"
_DEFAULT_DIRS_WINDOWS = [
    # ProgramData é o lugar canônico pra estado de serviço Windows.
    r"C:\ProgramData\NetGuard",
]
_DEFAULT_DIRS_POSIX = [
    "/var/lib/netguard",
    str(Path.home() / ".netguard"),
]


def _candidate_dirs() -> list[Path]:
    """
    Diretórios candidatos pra gravar host_id, em ordem de preferência.
    NETGUARD_AGENT_HOME (env) sobrescreve tudo — útil pra docker/CI.
    """
    override = os.environ.get("NETGUARD_AGENT_HOME")
    if override:
        return [Path(override)]
    if sys.platform.startswith("win"):
        return [Path(d) for d in _DEFAULT_DIRS_WINDOWS]
    return [Path(d) for d in _DEFAULT_DIRS_POSIX]


def _try_read(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
        # Sanity: parsea como UUID. Se vier corrompido, descarta e regenera.
        uuid.UUID(text)
        return text
    except (OSError, ValueError):
        return None


def _try_write(path: Path, value: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="utf-8")
        # Em POSIX, restringe leitura a root pra não vazar pra usuários
        # comuns (em Windows o ACL default já é razoável).
        if not sys.platform.startswith("win"):
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return True
    except OSError as exc:
        logger.debug("host_id write falhou em %s: %s", path, exc)
        return False


def get_host_id() -> str:
    """
    Retorna o host_id persistente. Cria na primeira execução.
    Idempotente: chamadas subsequentes devolvem o mesmo valor.
    """
    for d in _candidate_dirs():
        path = d / _HOST_ID_FILE
        existing = _try_read(path)
        if existing:
            return existing

    # Não achou. Gera e tenta persistir no primeiro candidato gravável.
    new_id = str(uuid.uuid4())
    for d in _candidate_dirs():
        path = d / _HOST_ID_FILE
        if _try_write(path, new_id):
            logger.info("host_id novo gerado e gravado em %s", path)
            return new_id

    # Último recurso: in-memory. Server vai ver cada run como host novo.
    logger.warning(
        "host_id em memória — nenhum diretório gravável. "
        "Server vai tratar cada execução como host novo."
    )
    return new_id


def get_host_facts() -> dict:
    """
    Coleta hostname, OS, user, IP — usado no envelope do POST inicial
    pro server preencher display_name e platform corretamente.
    """
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"

    try:
        # IP "primário" — não é 100% confiável (interfaces múltiplas),
        # mas server usa só pra display, não como identificador.
        local_ip = socket.gethostbyname(hostname)
    except OSError:
        local_ip = ""

    user = (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or ""
    )

    return {
        "hostname": hostname,
        "platform": platform.system().lower() or "unknown",
        "platform_version": platform.release() or "",
        "user": user,
        "local_ip": local_ip,
        "machine": platform.machine() or "",
    }


if __name__ == "__main__":
    # Smoke test manual: python -m agent.host_identity
    logging.basicConfig(level=logging.INFO)
    hid = get_host_id()
    facts = get_host_facts()
    print(f"host_id: {hid}")
    for k, v in facts.items():
        print(f"  {k}: {v}")
