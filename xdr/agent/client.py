"""HTTP client for agent enrollment, heartbeat and XDR event ingestion."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("netguard.xdr.agent")


class XDRIngestionClient:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        timeout: int = 10,
        agent_key: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.bootstrap_token = token
        self.timeout = timeout
        self.agent_key = agent_key

    def register_host(
        self,
        *,
        host_id: str,
        display_name: str = "",
        platform: str = "",
        agent_version: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._post(
            "/api/agent/register",
            {
                "host_id": host_id,
                "display_name": display_name or host_id,
                "platform": platform,
                "agent_version": agent_version,
                "metadata": metadata or {},
            },
            use_bootstrap=True,
        )
        issued_key = str(response.get("api_key") or "").strip()
        if issued_key:
            self.agent_key = issued_key
        return response

    def heartbeat(
        self,
        *,
        host_id: str,
        display_name: str = "",
        platform: str = "",
        agent_version: str = "",
        snapshot_summary: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/api/agent/heartbeat",
            {
                "host_id": host_id,
                "display_name": display_name or host_id,
                "platform": platform,
                "agent_version": agent_version,
                "snapshot_summary": snapshot_summary or {},
                "metadata": metadata or {},
            },
        )

    def post_events(
        self,
        *,
        host_id: str,
        events: list[dict[str, Any]],
        snapshot_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/api/agent/events",
            {
                "host_id": host_id,
                "events": events,
                "snapshot_summary": snapshot_summary or {},
            },
        )

    def send_events(self, events: list[dict]) -> tuple[bool, dict]:
        host_id = str((events[0] if events else {}).get("host_id") or "unknown-host")
        try:
            return True, self.post_events(host_id=host_id, events=events)
        except RuntimeError as exc:
            return False, {"error": str(exc)}

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        use_bootstrap: bool = False,
    ) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "NetGuard-Agent/2.0",
        }
        if not use_bootstrap and self.agent_key:
            headers["X-NetGuard-Agent-Key"] = self.agent_key
        elif self.bootstrap_token:
            headers["Authorization"] = f"Bearer {self.bootstrap_token}"
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body or "{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            logger.warning(
                "XDR client HTTP error | path=%s | status=%s",
                path,
                exc.code,
            )
            raise RuntimeError(detail or f"http_{exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc
