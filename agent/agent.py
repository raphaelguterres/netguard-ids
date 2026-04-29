"""
Orquestrador principal do NetGuard Agent.

Fluxo:
  1. Carrega config (yaml + env)
  2. Resolve host_id persistente
  3. Inicia drain loop em background (esvazia buffer offline)
  4. Loop principal: collector.collect_events() → sender.send_batch()
  5. SIGTERM/SIGINT: stop graceful (drena buffer uma última vez)

Decisões de design:

- Sem threading.Thread daemon=False pra collector: deixar o loop
  no main thread torna shutdown previsível (Ctrl+C funciona). Drain
  rodando em daemon thread morre junto com o processo, e isso é OK
  porque o buffer SQLite tá persistido.

- Presence ping: o agente manda um envelope vazio no bootstrap e, em
  hosts silenciosos, renova last_seen de tempos em tempos sem encher o
  buffer offline com heartbeats vazios quando o servidor cai.

- Logging: arquivo (rotate diário) + stdout. Log path vem do config;
  default é %ProgramData%\\NetGuard\\agent.log no Windows e
  /var/log/netguard/agent.log no Linux.
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
from pathlib import Path

from agent import __version__
from agent.actions import AgentActionClient, AgentActionExecutor
from agent.collector import TelemetryCollector, snapshot_summary
from agent.config import AgentConfig, load_config
from agent.credentials import CredentialStore
from agent.host_identity import get_host_facts, get_host_id
from agent.sender import EventSender

logger = logging.getLogger("netguard.agent")


def _default_log_path() -> Path:
    if sys.platform.startswith("win"):
        return Path(r"C:\ProgramData\NetGuard\agent.log")
    return Path("/var/log/netguard/agent.log")


def _default_state_dir() -> Path:
    override = (os.environ.get("NETGUARD_AGENT_HOME") or "").strip()
    if override:
        return Path(override)
    return _default_log_path().parent


def _default_credential_path() -> Path:
    return _default_state_dir() / "credentials.json"


def _setup_logging(log_path: str = "") -> Path | None:
    """Configura root logger pra arquivo + stdout. Retorna o path real."""
    target = Path(log_path) if log_path else _default_log_path()
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger("netguard")
    # Evita duplicar handlers em re-inits (test runner, hot-reload).
    if any(getattr(h, "_netguard_owned", False) for h in root.handlers):
        return target
    root.setLevel(logging.INFO)

    # Stdout sempre.
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh._netguard_owned = True  # type: ignore[attr-defined]
    root.addHandler(sh)

    # File handler (rotativo, 5 MB x 5).
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            target, maxBytes=5_000_000, backupCount=5, encoding="utf-8",
        )
        fh.setFormatter(fmt)
        fh._netguard_owned = True  # type: ignore[attr-defined]
        root.addHandler(fh)
        return target
    except OSError as exc:
        # Sem permissão pra log file — segue só com stdout.
        logger.warning("Falha ao abrir log file %s: %s", target, exc)
        return None


class NetGuardAgent:
    """
    Agente NetGuard. Não faz I/O no __init__; chame run() pra iniciar.
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or load_config()
        self.host_id = ""
        self.host_facts: dict = {}
        self.sender: EventSender | None = None
        self.collector: TelemetryCollector | None = None
        self.action_client: AgentActionClient | None = None
        self.action_executor: AgentActionExecutor | None = None
        self._stop = threading.Event()
        self._drain_thread: threading.Thread | None = None
        self._last_presence_post = 0.0
        self._last_action_poll = 0.0

    # ──────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        """Resolve identity, valida config, instancia componentes."""
        self.host_id = get_host_id()
        self.host_facts = get_host_facts()
        self._load_or_store_api_key()
        self.config.validate()  # pode lançar ValueError

        buffer_dir = Path(self.config.log_path).parent if self.config.log_path else _default_state_dir()
        buffer_path = buffer_dir / "agent_buffer.db"

        self.sender = EventSender(
            server_url=self.config.server_url,
            api_key=self.config.api_key,
            verify_tls=self.config.verify_tls,
            timeout=self.config.request_timeout,
            buffer_path=buffer_path,
            offline_buffer_max=self.config.offline_buffer_max,
        )
        self.collector = TelemetryCollector(
            host_id=self.host_id,
            host_facts=self.host_facts,
            agent_version=__version__,
            collect_processes=self.config.collect_processes,
            collect_connections=self.config.collect_connections,
            collect_security=self.config.collect_security_indicators,
        )
        self.action_client = AgentActionClient(self.sender)
        self.action_executor = AgentActionExecutor(
            host_id=self.host_id,
            host_facts=self.host_facts,
            sender=self.sender,
            allow_destructive=self.config.allow_destructive_response_actions,
        )

        logger.info(
            "Agent inicializado | host_id=%s | hostname=%s | platform=%s | v=%s",
            self.host_id, self.host_facts.get("hostname"),
            self.host_facts.get("platform"), __version__,
        )

    def _credential_store(self) -> CredentialStore:
        path = Path(self.config.credential_path) if self.config.credential_path else _default_credential_path()
        return CredentialStore(path)

    def _load_or_store_api_key(self) -> None:
        store = self._credential_store()
        if self.config.api_key in ("", "CHANGE_ME"):
            saved = store.load()
            if saved.api_key:
                self.config.api_key = saved.api_key
                logger.info("Agent API key loaded from local credential store")
        elif self.config.api_key:
            store.save(api_key=self.config.api_key, host_id=self.host_id)

    def _build_envelope(self, events: list[dict]) -> dict:
        """
        Envelope para POST /api/events.
        Mantemos campos legados (`display_name`, `platform`, `metadata`)
        para compatibilidade com o ingest antigo, mas o server modular
        usa `hostname`, `agent_version` e `events`.
        """
        envelope = {
            "host_id": self.host_id,
            "hostname": self.host_facts.get("hostname", self.host_id),
            "display_name": self.host_facts.get("hostname", self.host_id),
            "platform": self.host_facts.get("platform", ""),
            "agent_version": __version__,
            "metadata": {
                "user": self.host_facts.get("user", ""),
                "machine": self.host_facts.get("machine", ""),
                "platform_version": self.host_facts.get("platform_version", ""),
                "local_ip": self.host_facts.get("local_ip", ""),
                "tags": self.config.tags,
                "snapshot_summary": snapshot_summary(events),
            },
            "events": events,
        }
        if self.config.tenant_id:
            envelope["tenant_id"] = self.config.tenant_id
        return envelope

    def _start_drain_thread(self) -> None:
        if self.sender is None:
            return
        t = threading.Thread(
            target=self.sender.run_drain_loop,
            args=(max(15.0, float(self.config.interval_seconds)),),
            daemon=True,
            name="netguard-drain",
        )
        t.start()
        self._drain_thread = t

    def _install_signal_handlers(self) -> None:
        if not threading.current_thread() is threading.main_thread():
            return  # service mode tem seu próprio shutdown
        try:
            signal.signal(signal.SIGINT, lambda *_: self.stop())
            signal.signal(signal.SIGTERM, lambda *_: self.stop())
        except (ValueError, OSError):
            pass

    def stop(self) -> None:
        logger.info("Stop solicitado — desligando agent.")
        self._stop.set()
        if self.sender:
            self.sender.stop_drain()

    def _presence_interval_seconds(self) -> int:
        return max(60, int(self.config.interval_seconds) * 3)

    def _send_presence_ping(self) -> None:
        if not self.sender:
            return
        envelope = self._build_envelope([])
        self.sender.send_batch(envelope, buffer_on_failure=False)
        self._last_presence_post = time.time()

    def _poll_and_execute_actions(self) -> int:
        if not self.config.enable_response_actions:
            return 0
        if not self.action_client or not self.action_executor:
            return 0
        now = time.time()
        interval = max(10, int(self.config.action_poll_interval_seconds))
        if (now - self._last_action_poll) < interval:
            return 0
        self._last_action_poll = now
        completed = 0
        for action in self.action_client.poll(limit=10, lease_seconds=max(interval * 2, 60)):
            action_id = str(action.get("action_id") or "")
            if not action_id:
                continue
            outcome = self.action_executor.execute(action)
            if self.action_client.ack(
                action_id,
                status=outcome.status,
                result=outcome.result,
            ):
                completed += 1
            logger.info(
                "Response action processed | id=%s | type=%s | status=%s",
                action_id,
                action.get("action_type"),
                outcome.status,
            )
        return completed

    def run(self) -> int:
        """Loop principal — bloqueia até stop(). Retorna exit code."""
        try:
            self.setup()
        except ValueError as exc:
            logger.error("Config inválido: %s", exc)
            return 2

        self._install_signal_handlers()
        self._start_drain_thread()

        # Primeira coleta = baseline (zero eventos do delta).
        # Mandamos um envelope vazio pra o servidor registrar o host e
        # marcar last_seen, mas sem enfileirar heartbeat em disco caso
        # o server esteja offline.
        assert self.collector and self.sender
        self.collector.collect_events()  # baseline
        self._send_presence_ping()
        logger.info("Baseline enviado — entrando em loop")

        interval = max(5, int(self.config.interval_seconds))
        while not self._stop.is_set():
            t0 = time.time()
            try:
                events = self.collector.collect_events()
                if events:
                    # Cap por batch — se um host pirar e gerar 10k processos
                    # de uma vez, fatiamos pra não estourar batch_too_large
                    # do servidor (limite hard de 500).
                    cap = max(1, min(int(self.config.batch_max_events), 500))
                    for i in range(0, len(events), cap):
                        chunk = events[i:i + cap]
                        envelope = self._build_envelope(chunk)
                        self.sender.send_batch(envelope)
                    self._last_presence_post = time.time()
                elif (time.time() - self._last_presence_post) >= self._presence_interval_seconds():
                    self._send_presence_ping()
                actions_done = self._poll_and_execute_actions()
                logger.info(
                    "Ciclo: %d eventos | actions=%d | buffer pendente=%d",
                    len(events), actions_done, self.sender.buffer.size(),
                )
            except Exception as exc:
                # Erro não fatal: loga e segue. Deixar o agent crashar
                # numa exceção transitória (psutil hiccup) é pior do
                # que pular um ciclo.
                logger.exception("Erro no ciclo: %s", exc)

            elapsed = time.time() - t0
            self._stop.wait(max(0.0, interval - elapsed))

        # Drain final antes de sair.
        if self.sender:
            try:
                self.sender.drain_once(max_batches=20)
            except Exception:
                pass
        logger.info("Agent finalizado.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NetGuard Endpoint Agent")
    parser.add_argument("--config", help="Caminho explícito do config.yaml")
    parser.add_argument(
        "--service",
        choices=["install", "start", "stop", "remove", "restart", "debug"],
        help="Encaminha comando para o wrapper Windows Service",
    )
    args = parser.parse_args()

    if args.service:
        from agent import service as service_mod

        return service_mod.main([args.service])

    config = load_config(args.config)
    log_target = _setup_logging(config.log_path)
    if log_target:
        logger.info("Log file: %s", log_target)
    agent = NetGuardAgent(config)
    return agent.run()


if __name__ == "__main__":
    sys.exit(main())
