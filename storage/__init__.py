# NetGuard Storage
"""
Storage layer for the NetGuard EDR/SOC platform.

Public surface:

    from storage import Repository, Host, Event, Alert, get_repository

    repo = get_repository("sqlite", db_path="/tmp/edr.db")
    repo.init_schema()

The legacy event_repository / host_repository / incident_repository
modules under this package back the existing app.py and remain
importable as before.
"""

from .repository import (
    Alert,
    Event,
    Host,
    Repository,
    get_repository,
)
from .action_repository import AgentActionRepository

__all__ = [
    "AgentActionRepository",
    "Alert",
    "Event",
    "Host",
    "Repository",
    "get_repository",
]
