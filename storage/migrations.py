"""Schema migration metadata for the modular EDR repository."""

from __future__ import annotations

import hashlib

MIGRATIONS = [
    {
        "version": 1,
        "name": "initial_edr_schema",
        "description": "hosts, events, alerts, and indexes for the modular EDR/SOC repository",
    },
    {
        "version": 2,
        "name": "migration_metadata_checksums",
        "description": "add migration descriptions and deterministic checksums for safer upgrades",
    },
    {
        "version": 3,
        "name": "host_network_metadata",
        "description": "persist endpoint network identity metadata for SOC host inventory",
    },
]

SCHEMA_VERSION = max(item["version"] for item in MIGRATIONS)


def migration_checksum(item: dict) -> str:
    seed = "|".join([
        str(item["version"]),
        str(item["name"]),
        str(item.get("description") or ""),
    ])
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


for _item in MIGRATIONS:
    _item["checksum"] = migration_checksum(_item)


def latest_migration() -> dict:
    return MIGRATIONS[-1]


def expected_migration_map() -> dict[int, dict]:
    return {int(item["version"]): dict(item) for item in MIGRATIONS}
