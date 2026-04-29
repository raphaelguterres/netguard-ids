"""
NetGuard Endpoint Agent (T18).

Pacote do agente Windows / Linux. Empacotável em agent.exe via PyInstaller.
Conversa com o servidor central por POST /api/events autenticado por
API key (`X-API-Key`, com `X-NetGuard-Agent-Key` mantido por compatibilidade).

Módulos públicos:
  - host_identity : geração/persistência do host_id
  - config        : carregamento de config.yaml
  - collector     : coleta de telemetria (host, processos, conexões, segurança)
  - sender        : transporte HTTPS com retry + buffer offline
  - agent         : orquestrador do loop principal
  - service       : wrapper Windows service (pywin32)
"""

__version__ = "1.0.0"

# Backward compatibility: older scripts/tests imported the legacy snapshot
# runtime with `from agent import NetGuardAgent` when `agent.py` was a module.
# The new endpoint runtime lives in `agent.agent.NetGuardAgent`.
try:
    from netguard_agent import NetGuardAgent, main
except Exception:  # pragma: no cover - optional compatibility surface
    NetGuardAgent = None  # type: ignore[assignment]
    main = None  # type: ignore[assignment]

__all__ = [
    "__version__",
    "NetGuardAgent",
    "main",
]
