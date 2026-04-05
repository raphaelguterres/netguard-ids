"""Tests — NetGuardAgent (sem chamadas de rede reais)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import pytest
from unittest.mock import patch, MagicMock

# Import sem executar main()
sys.argv = ["agent.py"]
from agent import NetGuardAgent


@pytest.fixture
def agent():
    return NetGuardAgent(
        hub_url  = "http://127.0.0.1:5000",
        token    = "",
        interval = 30,
        host_id  = "test-host",
    )

@pytest.fixture
def agent_with_token():
    return NetGuardAgent(
        hub_url  = "http://127.0.0.1:5000",
        token    = "my_secret_token",
        interval = 30,
        host_id  = "test-host",
    )


class TestInit:
    def test_host_id_set_correctly(self, agent):
        assert agent.host_id == "test-host"

    def test_hub_url_strips_trailing_slash(self):
        a = NetGuardAgent(hub_url="http://192.168.1.1:5000/", host_id="h")
        assert not a.hub_url.endswith("/")

    def test_interval_set(self, agent):
        assert agent.interval == 30

    def test_initial_counters_zero(self, agent):
        assert agent._cycle  == 0
        assert agent._errors == 0
        assert agent._sent   == 0


class TestCollect:
    def test_collect_returns_dict(self, agent):
        snap = agent.collect()
        assert isinstance(snap, dict)

    def test_collect_has_required_keys(self, agent):
        snap = agent.collect()
        for key in ("timestamp","host_id","processes","connections","ports","system"):
            assert key in snap

    def test_collect_host_id_matches(self, agent):
        snap = agent.collect()
        assert snap["host_id"] == "test-host"

    def test_collect_timestamp_is_iso(self, agent):
        snap = agent.collect()
        ts = snap["timestamp"]
        # Python 3.13 uses +00:00 instead of Z — both are valid ISO 8601
        assert "T" in ts and ("Z" in ts or "+00:00" in ts)

    def test_collect_processes_is_list(self, agent):
        snap = agent.collect()
        assert isinstance(snap["processes"], list)

    def test_collect_connections_is_list(self, agent):
        snap = agent.collect()
        assert isinstance(snap["connections"], list)

    def test_collect_ports_is_list(self, agent):
        snap = agent.collect()
        assert isinstance(snap["ports"], list)

    def test_collect_system_has_cpu(self, agent):
        snap = agent.collect()
        sys_info = snap.get("system", {})
        assert "cpu_percent" in sys_info or sys_info == {}

    def test_process_entry_has_expected_keys(self, agent):
        snap = agent.collect()
        if snap["processes"]:
            p = snap["processes"][0]
            for key in ("pid","name","cpu","mem"):
                assert key in p


class TestSend:
    def test_send_success_increments_sent(self, agent):
        import urllib.request  # noqa: F401
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"status":"ok"}).encode()
        mock_cm = MagicMock()
        mock_cm.__enter__ = lambda s: mock_resp
        mock_cm.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_cm):
            ok = agent.send({"host_id":"test","processes":[],"connections":[],"ports":[]})

        assert ok is True
        assert agent._sent == 1
        assert agent._errors == 0

    def test_send_failure_increments_errors(self, agent):
        import urllib.error
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("connection refused")):
            ok = agent.send({"host_id":"test"})

        assert ok is False
        assert agent._errors == 1

    def test_send_includes_auth_header(self, agent_with_token):
        captured = {}
        def capture_request(req, timeout=10):
            captured["headers"] = dict(req.headers)
            raise Exception("stop")

        with patch("urllib.request.urlopen", side_effect=capture_request):
            agent_with_token.send({"host_id":"test"})

        auth = captured.get("headers",{}).get("Authorization","")
        assert "Bearer my_secret_token" in auth

    def test_send_without_token_no_auth_header(self, agent):
        captured = {}
        def capture_request(req, timeout=10):
            captured["headers"] = dict(req.headers)
            raise Exception("stop")

        with patch("urllib.request.urlopen", side_effect=capture_request):
            agent.send({"host_id":"test"})

        auth = captured.get("headers",{}).get("Authorization","")
        assert auth == ""

    def test_send_content_type_json(self, agent):
        captured = {}
        def capture_request(req, timeout=10):
            captured["headers"] = dict(req.headers)
            raise Exception("stop")

        with patch("urllib.request.urlopen", side_effect=capture_request):
            agent.send({"host_id":"test"})

        ct = captured.get("headers",{}).get("Content-type","")
        assert "application/json" in ct


class TestRunOnce:
    def test_run_once_increments_cycle(self, agent):
        snap = {"host_id":"test","processes":[],"connections":[],"ports":[],"system":{},"timestamp":"","agent_v":"1.0"}
        with patch.object(agent, "collect", return_value=snap), \
             patch.object(agent, "send",    return_value=True):
            agent.run_once()
        assert agent._cycle == 1

    def test_run_once_calls_collect_and_send(self, agent):
        snap = {"host_id":"test","processes":[],"connections":[],"ports":[],"system":{},"timestamp":"","agent_v":"1.0"}
        with patch.object(agent, "collect", return_value=snap) as mc, \
             patch.object(agent, "send",    return_value=True) as ms:
            agent.run_once()
        mc.assert_called_once()
        ms.assert_called_once_with(snap)

    def test_run_once_multiple_cycles(self, agent):
        snap = {"host_id":"test","processes":[],"connections":[],"ports":[],"system":{},"timestamp":"","agent_v":"1.0"}
        with patch.object(agent, "collect", return_value=snap), \
             patch.object(agent, "send",    return_value=True):
            for _ in range(5):
                agent.run_once()
        assert agent._cycle == 5


class TestGetHostId:
    def test_host_id_not_empty(self, agent):
        assert agent.host_id != ""
        assert len(agent.host_id) > 0

    def test_custom_host_id_used(self):
        a = NetGuardAgent(hub_url="http://x.x", host_id="custom-server-01")
        assert a.host_id == "custom-server-01"

    def test_auto_host_id_when_empty(self):
        a = NetGuardAgent(hub_url="http://x.x", host_id="")
        assert len(a.host_id) > 0
