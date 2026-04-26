"""Disk-backed local buffering for lightweight agents."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class LocalEventBuffer:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def load(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []
            items: list[dict[str, Any]] = []
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return items

    def replace(self, records: list[dict[str, Any]]) -> None:
        with self._lock:
            if not records:
                self.path.unlink(missing_ok=True)
                return
            with self.path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    def append_many(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._lock:
            current = self.load()
            current.extend(records)
            self.replace(current[-500:])

    def clear(self) -> None:
        with self._lock:
            self.path.unlink(missing_ok=True)

    def enqueue(self, event: dict) -> None:
        self.append_many([event])

    def drain(self, limit: int = 100) -> list[dict]:
        with self._lock:
            if not self.path.exists():
                return []
            lines = self.path.read_text(encoding="utf-8").splitlines()
            head = lines[:limit]
            tail = lines[limit:]
            if tail:
                self.path.write_text("\n".join(tail) + "\n", encoding="utf-8")
            else:
                self.path.unlink(missing_ok=True)
        return [json.loads(line) for line in head if line.strip()]
