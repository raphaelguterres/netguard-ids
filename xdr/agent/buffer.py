"""Disk-backed local buffering for lightweight agents."""

from __future__ import annotations

import json
import threading
from pathlib import Path


class LocalEventBuffer:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def enqueue(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

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
