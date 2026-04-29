"""
Wrapper Windows Service via pywin32.

Decisões:

- pywin32 é dependência opcional: o módulo importa com try/except pra
  o agente continuar rodável em modo "console" (foreground) mesmo sem
  pywin32 instalado. Empacotamos pywin32 só quando build_agent.ps1
  detecta que vai gerar binário com `--service` flag.

- Stop assíncrono: SvcStop sinaliza o NetGuardAgent.stop() e espera
  até 30s pelo loop principal terminar. SCM aguarda esse retorno;
  acima disso, Windows mata forçado.

- Comandos:
    python -m agent.service install    # registra o serviço
    python -m agent.service start      # inicia
    python -m agent.service stop       # para
    python -m agent.service remove     # desinstala
    python -m agent.service debug      # roda em foreground (sem SCM)

  ou no .exe empacotado:
    agent.exe --service install
    agent.exe --service start
    ...
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time

logger = logging.getLogger("netguard.agent.service")

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False


SERVICE_NAME = "NetGuardAgent"
SERVICE_DISPLAY_NAME = "NetGuard Endpoint Agent"
SERVICE_DESCRIPTION = (
    "Coleta telemetria de endpoint (processos, conexões, indicadores "
    "de segurança) e envia ao servidor central NetGuard."
)


if _PYWIN32_AVAILABLE:

    class NetGuardService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._agent = None
            self._thread = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            try:
                if self._agent:
                    self._agent.stop()
            except Exception:
                logger.exception("Erro ao sinalizar stop")
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            from agent.agent import NetGuardAgent, _setup_logging
            from agent.config import load_config

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )

            config = load_config()
            _setup_logging(config.log_path)
            self._agent = NetGuardAgent(config)

            # Roda agent em thread dedicada pra não bloquear o
            # SCM. Quando hWaitStop sinaliza, o agent.stop() já foi
            # chamado em SvcStop e o loop sai sozinho.
            def _run():
                try:
                    self._agent.run()
                except Exception:
                    logger.exception("Agent thread crashed")

            self._thread = threading.Thread(target=_run, daemon=True,
                                             name="netguard-agent-svc")
            self._thread.start()

            # Espera SCM pedir stop.
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            # Aguarda graceful shutdown (até 30s).
            if self._thread:
                self._thread.join(timeout=30.0)


def _no_pywin32_message():
    print(
        "ERRO: pywin32 não instalado. "
        "Instale com `pip install pywin32` ou rode em modo console:\n"
        "  python -m agent.agent",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not _PYWIN32_AVAILABLE:
        _no_pywin32_message()
        return 1

    # win32serviceutil.HandleCommandLine espera sys.argv[0] = nome do script.
    # Reconstroi argv como `python service.py <cmd>`.
    sys.argv = [sys.argv[0], *argv]
    win32serviceutil.HandleCommandLine(NetGuardService)
    return 0


if __name__ == "__main__":
    sys.exit(main())
