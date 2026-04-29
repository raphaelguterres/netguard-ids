"""Schema migration metadata for the modular EDR repository."""

from __future__ import annotations

SCHEMA_VERSION = 1

MIGRATIONS = [
    {
        "version": 1,
        "name": "initial_edr_schema",
        "description": "hosts, events, alerts, and indexes for the modular EDR/SOC repository",
    },
]


def latest_migration() -> dict:
    return MIGRATIONS[-1]
