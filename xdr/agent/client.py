"""Minimal HTTP client for structured XDR event ingestion."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class XDRIngestionClient:
    def __init__(self, base_url: str, token: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def send_events(self, events: list[dict]) -> tuple[bool, dict]:
        payload = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/xdr/events",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "NetGuard-XDR-Agent/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return True, json.loads(body or "{}")
        except urllib.error.HTTPError as exc:
            return False, {"error": f"http_{exc.code}"}
        except urllib.error.URLError as exc:
            return False, {"error": f"url_{exc.reason}"}
