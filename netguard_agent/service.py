"""Main agent runtime with legacy and XDR transport support."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

from .collector import collect_snapshot, current_platform

try:
    from xdr.agent import LocalEventBuffer, SnapshotAgentService, XDRIngestionClient

    XDR_AGENT_OK = True
except Exception:  # pragma: no cover - graceful degradation
    LocalEventBuffer = None
    SnapshotAgentService = None
    XDRIngestionClient = None
    XDR_AGENT_OK = False

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("netguard.agent")


class NetGuardAgent:
    """Lightweight endpoint agent with legacy snapshot and XDR modes."""

    def __init__(
        self,
        hub_url: str,
        token: str = "",
        interval: int = 30,
        host_id: str = "",
        mode: str = "",
        buffer_path: str = "",
        timeout: int = 10,
        agent_key: str = "",
    ):
        normalized_mode = (mode or os.environ.get("NETGUARD_MODE", "legacy")).strip().lower()
        if normalized_mode not in {"legacy", "xdr", "both"}:
            normalized_mode = "legacy"

        self.hub_url = hub_url.rstrip("/")
        self.token = token
        self.interval = max(5, int(interval))
        self.host_id = host_id or socket.gethostname()
        self.mode = normalized_mode
        self.platform = current_platform()
        self.timeout = timeout
        self.agent_key = agent_key or os.environ.get("NETGUARD_AGENT_KEY", "").strip()
        self.buffer_path = Path(
            buffer_path
            or os.environ.get("NETGUARD_AGENT_BUFFER")
            or f".netguard-agent-buffer-{self.host_id}.jsonl"
        )
        self._running = False
        self._cycle = 0
        self._errors = 0
        self._sent = 0
        self._xdr_service = self._build_xdr_service()

        logger.info(
            "Agent initialized | host=%s | hub=%s | interval=%ds | mode=%s",
            self.host_id,
            self.hub_url,
            self.interval,
            self.mode,
        )

    def _build_xdr_service(self):
        if self.mode not in {"xdr", "both"} or not XDR_AGENT_OK:
            return None
        client = XDRIngestionClient(
            base_url=self.hub_url,
            token=self.token,
            timeout=self.timeout,
            agent_key=self.agent_key,
        )
        buffer = LocalEventBuffer(self.buffer_path)
        return SnapshotAgentService(client=client, buffer=buffer)

    def collect(self) -> dict:
        return collect_snapshot(host_id=self.host_id, platform_name=self.platform)

    def _send_legacy(self, snapshot: dict) -> bool:
        url = f"{self.hub_url}/api/agent/push"
        data = json.dumps(snapshot).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"NetGuard-Agent/2.0 ({self.host_id})",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            request = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
            self._sent += 1
            return True
        except urllib.error.HTTPError as exc:
            logger.warning("Legacy hub HTTP error: %s %s", exc.code, exc.reason)
        except urllib.error.URLError as exc:
            logger.warning("Legacy hub unreachable: %s", exc.reason)
        except Exception as exc:
            logger.error("Legacy send error: %s", exc)

        self._errors += 1
        return False

    def _send_xdr(self, snapshot: dict) -> bool:
        if not self._xdr_service:
            logger.warning("XDR mode unavailable; falling back to legacy transport")
            return self._send_legacy(snapshot)

        try:
            result = self._xdr_service.ship_snapshot(snapshot)
            client = getattr(self._xdr_service, "client", None)
            if client and getattr(client, "agent_key", ""):
                self.agent_key = client.agent_key
            if result.get("ok"):
                self._sent += 1
                return True
            logger.warning(
                "XDR ingest failed | queued=%d | detail=%s",
                result.get("queued", 0),
                result.get("response", {}),
            )
        except Exception as exc:
            logger.error("XDR send error: %s", exc)

        self._errors += 1
        return False

    def send(self, snapshot: dict) -> bool:
        if self.mode == "legacy":
            return self._send_legacy(snapshot)
        if self.mode == "xdr":
            return self._send_xdr(snapshot)
        return self._send_xdr(snapshot) and self._send_legacy(snapshot)

    def run_once(self) -> bool:
        snapshot = self.collect()
        self._cycle += 1
        return self.send(snapshot)

    def run(self) -> None:
        self._running = True
        while self._running:
            self.run_once()
            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetGuard endpoint agent")
    parser.add_argument("--hub", required=True, help="Server base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--token", default="", help="Bootstrap tenant/admin API token")
    parser.add_argument("--agent-key", default="", help="Previously issued host API key")
    parser.add_argument("--interval", type=int, default=30, help="Collection interval in seconds")
    parser.add_argument("--host-id", default="", help="Custom host identifier")
    parser.add_argument("--mode", default="legacy", choices=("legacy", "xdr", "both"))
    parser.add_argument("--buffer-path", default="", help="Offline buffer path for XDR events")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    agent = NetGuardAgent(
        hub_url=args.hub,
        token=args.token,
        interval=args.interval,
        host_id=args.host_id,
        mode=args.mode,
        buffer_path=args.buffer_path,
        timeout=args.timeout,
        agent_key=args.agent_key,
    )
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent interrupted by operator")
    return 0
