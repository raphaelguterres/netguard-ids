"""Focused tests for the agent's XDR transport path."""

import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.argv = ["agent.py"]
from agent import NetGuardAgent


class TestAgentXdrMode:
    def test_agent_defaults_to_legacy_mode(self):
        agent = NetGuardAgent(hub_url="http://127.0.0.1:5000", host_id="host-01")
        assert agent.mode == "legacy"

    def test_collect_includes_platform(self):
        agent = NetGuardAgent(hub_url="http://127.0.0.1:5000", host_id="host-01")
        snapshot = agent.collect()
        assert snapshot["platform"] != ""

    def test_send_xdr_uses_snapshot_service(self):
        agent = NetGuardAgent(
            hub_url="http://127.0.0.1:5000",
            host_id="host-01",
            mode="xdr",
        )
        agent._xdr_service = MagicMock()
        agent._xdr_service.ship_snapshot.return_value = {
            "ok": True,
            "queued": 0,
            "response": {"processed": 2},
        }

        ok = agent.send({"host_id": "host-01", "processes": [], "connections": [], "ports": []})

        assert ok is True
        assert agent._sent == 1
        agent._xdr_service.ship_snapshot.assert_called_once()

    def test_send_xdr_falls_back_to_legacy_when_service_missing(self):
        agent = NetGuardAgent(
            hub_url="http://127.0.0.1:5000",
            host_id="host-01",
            mode="xdr",
        )
        agent._xdr_service = None

        with patch.object(agent, "_send_legacy", return_value=True) as send_legacy:
            ok = agent.send({"host_id": "host-01"})

        assert ok is True
        send_legacy.assert_called_once()

    def test_invalid_mode_is_normalized_to_legacy(self):
        agent = NetGuardAgent(
            hub_url="http://127.0.0.1:5000",
            host_id="host-01",
            mode="wat",
        )
        assert agent.mode == "legacy"
