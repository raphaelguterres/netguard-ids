"""
NetGuard — Baseline Engine
Rastreia o que é "normal" no host: processos, IPs, portas.
Detecta quando algo novo aparece pela primeira vez.

Arquitetura:
- In-memory por padrão (rápido, zero deps)
- Hook para storage/ persistente via BaselineStore interface
- Thread-safe para uso em ambiente multi-thread
"""

import threading
import logging
from datetime import datetime, timezone
from typing import Optional, Protocol

logger = logging.getLogger("netguard.baseline")


# ── Interface para storage persistente (opcional) ────────────────
class BaselineStore(Protocol):
    """
    Interface que qualquer storage persistente deve implementar.
    Permite integração futura com SQLite, Redis, PostgreSQL, etc.
    """
    def get(self, host_id: str, btype: str) -> set[str]: ...
    def add(self, host_id: str, btype: str, value: str) -> None: ...


# ── Baseline types ───────────────────────────────────────────────
class BaselineType:
    PROCESS  = "process"
    IP       = "ip"
    PORT     = "port"
    UA       = "user_agent"
    DOMAIN   = "domain"


class BaselineEngine:
    """
    Motor de baseline in-memory com suporte a persistência futura.

    Uso:
        baseline = BaselineEngine(host_id="webserver-01")
        if not baseline.is_known_process("malware.exe"):
            # novo processo — gera alerta
    """

    def __init__(
        self,
        host_id: str = "local",
        store: Optional[BaselineStore] = None,
        seed_processes: Optional[set[str]] = None,
        seed_ports:     Optional[set[int]] = None,
    ):
        self.host_id = host_id
        self._store  = store  # storage persistente opcional
        self._lock   = threading.RLock()

        # Sets in-memory por tipo
        self._data: dict[str, set[str]] = {
            BaselineType.PROCESS: set(),
            BaselineType.IP:      set(),
            BaselineType.PORT:    set(),
            BaselineType.UA:      set(),
            BaselineType.DOMAIN:  set(),
        }

        # Metadados: quando cada valor foi visto pela primeira vez
        self._first_seen: dict[tuple[str, str], str] = {}

        # Seed inicial: processos e portas conhecidos como "normais"
        if seed_processes:
            self._data[BaselineType.PROCESS].update(
                p.lower().strip() for p in seed_processes
            )
        if seed_ports:
            self._data[BaselineType.PORT].update(str(p) for p in seed_ports)

        # Carrega do storage persistente se disponível
        if self._store:
            self._load_from_store()

        logger.debug("BaselineEngine iniciado | host=%s", host_id)

    # ── Public API ────────────────────────────────────────────────

    def is_known_process(self, process_name: str) -> bool:
        """Retorna True se o processo já foi visto antes."""
        return self._is_known(BaselineType.PROCESS, process_name.lower().strip())

    def is_known_ip(self, ip: str) -> bool:
        """Retorna True se o IP já foi visto antes."""
        return self._is_known(BaselineType.IP, ip.strip())

    def is_known_port(self, port: int | str) -> bool:
        """Retorna True se a porta já foi vista antes."""
        return self._is_known(BaselineType.PORT, str(port))

    def is_known_domain(self, domain: str) -> bool:
        return self._is_known(BaselineType.DOMAIN, domain.lower().strip())

    def is_known_ua(self, ua: str) -> bool:
        return self._is_known(BaselineType.UA, ua.strip())

    def learn_process(self, process_name: str) -> bool:
        """
        Adiciona processo ao baseline.
        Retorna True se era novo (não estava antes).
        """
        return self._learn(BaselineType.PROCESS, process_name.lower().strip())

    def learn_ip(self, ip: str) -> bool:
        return self._learn(BaselineType.IP, ip.strip())

    def learn_port(self, port: int | str) -> bool:
        return self._learn(BaselineType.PORT, str(port))

    def learn_domain(self, domain: str) -> bool:
        return self._learn(BaselineType.DOMAIN, domain.lower().strip())

    def learn_processes_batch(self, names: list[str]) -> list[str]:
        """
        Aprende múltiplos processos.
        Retorna lista dos que eram novos.
        """
        return [n for n in names if self._learn(BaselineType.PROCESS, n.lower().strip())]

    def learn_ips_batch(self, ips: list[str]) -> list[str]:
        return [ip for ip in ips if self._learn(BaselineType.IP, ip.strip())]

    def check_and_learn_process(self, name: str) -> tuple[bool, bool]:
        """
        Verifica e aprende em uma operação atômica.
        Retorna (was_known, is_new_learned).
        """
        with self._lock:
            name = name.lower().strip()
            known = self._is_known(BaselineType.PROCESS, name)
            learned = self._learn(BaselineType.PROCESS, name) if not known else False
            return known, learned

    def check_and_learn_ip(self, ip: str) -> tuple[bool, bool]:
        with self._lock:
            ip = ip.strip()
            known = self._is_known(BaselineType.IP, ip)
            learned = self._learn(BaselineType.IP, ip) if not known else False
            return known, learned

    def check_and_learn_port(self, port: int | str) -> tuple[bool, bool]:
        with self._lock:
            p = str(port)
            known = self._is_known(BaselineType.PORT, p)
            learned = self._learn(BaselineType.PORT, p) if not known else False
            return known, learned

    def get_baseline_size(self, btype: str = None) -> dict | int:
        """Retorna tamanho do baseline por tipo ou total."""
        with self._lock:
            if btype:
                return len(self._data.get(btype, set()))
            return {k: len(v) for k, v in self._data.items()}

    def first_seen(self, btype: str, value: str) -> Optional[str]:
        """Retorna timestamp ISO de quando o valor foi visto pela primeira vez."""
        return self._first_seen.get((btype, value))

    def snapshot(self) -> dict:
        """Retorna snapshot do baseline atual (para debug/export)."""
        with self._lock:
            return {
                "host_id":  self.host_id,
                "sizes":    {k: len(v) for k, v in self._data.items()},
                "processes": list(self._data[BaselineType.PROCESS])[:50],
                "ports":     sorted(self._data[BaselineType.PORT]),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ── Storage integration ───────────────────────────────────────

    def attach_store(self, store: BaselineStore) -> None:
        """Conecta um storage persistente em runtime."""
        self._store = store
        self._load_from_store()

    def flush_to_store(self) -> None:
        """Persiste baseline atual no storage."""
        if not self._store:
            return
        with self._lock:
            for btype, values in self._data.items():
                for v in values:
                    try:
                        self._store.add(self.host_id, btype, v)
                    except Exception as e:
                        logger.warning("Baseline flush error: %s", e)

    # ── Private ───────────────────────────────────────────────────

    def _is_known(self, btype: str, value: str) -> bool:
        with self._lock:
            return value in self._data.get(btype, set())

    def _learn(self, btype: str, value: str) -> bool:
        """
        Adiciona ao baseline. Retorna True se era novo.
        Side effect: persiste no store se disponível.
        """
        with self._lock:
            if btype not in self._data:
                self._data[btype] = set()
            if value in self._data[btype]:
                return False
            # Novo valor
            self._data[btype].add(value)
            self._first_seen[(btype, value)] = datetime.now(timezone.utc).isoformat()
            if self._store:
                try:
                    self._store.add(self.host_id, btype, value)
                except Exception as e:
                    logger.warning("Baseline store error: %s", e)
            return True

    def _load_from_store(self) -> None:
        """Carrega baseline do storage persistente."""
        if not self._store:
            return
        with self._lock:
            for btype in self._data:
                try:
                    values = self._store.get(self.host_id, btype)
                    self._data[btype].update(values)
                except Exception as e:
                    logger.warning("Baseline load error [%s]: %s", btype, e)


# ── Instância global padrão ───────────────────────────────────────
# Importada pelos módulos que precisam de baseline sem DI explícita.
_default_baseline: Optional[BaselineEngine] = None


def get_default_baseline(host_id: str = "local") -> BaselineEngine:
    """Retorna ou cria a instância global de baseline."""
    global _default_baseline
    if _default_baseline is None:
        _default_baseline = BaselineEngine(host_id=host_id)
    return _default_baseline
