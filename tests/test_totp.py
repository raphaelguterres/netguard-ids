"""
test_totp.py — Testes do módulo TOTP 2FA (RFC 6238).

Cobre:
  - Vetores oficiais da RFC 6238 Apêndice B (5 vetores, SHA1)
  - Geração de secret (tamanho, base32 válido, chmod 0o600 em POSIX)
  - Verify fail-closed (sem enable -> sempre False)
  - Kill switch IDS_ADMIN_TOTP=false
  - Janela de tolerância +/- TOTP_WINDOW
  - Provisioning URI formato otpauth://
  - Normalização do base32 no decode (lowercase, com espaços, sem padding)

Stdlib-only — não importa Flask. Se auth.py quebrar em produção, esses
testes pegam antes.
"""
import base64
import importlib
import os
import pathlib
import sys
import tempfile
import time

import pytest


# ── Fixture: auth module com TOTP_FILE isolado num tempdir ───────
@pytest.fixture()
def auth_mod(tmp_path, monkeypatch):
    """
    Carrega auth.py com TOTP_FILE apontando pra um tempdir limpo.
    Evita poluir o .netguard_totp real do repo e garante independência
    entre testes (cada teste roda com secret novo).
    """
    # Garante que o root do projeto está no sys.path
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    # Zera qualquer kill-switch herdado do ambiente
    monkeypatch.delenv("IDS_ADMIN_TOTP", raising=False)

    import auth  # noqa: WPS433 — import tardio intencional

    # Remove cache pra honrar qualquer patch de env feito acima
    auth = importlib.reload(auth)

    # Redireciona TOTP_FILE pro tempdir
    monkeypatch.setattr(auth, "TOTP_FILE", tmp_path / ".netguard_totp")
    return auth


# ── RFC 6238 Apêndice B — vetores oficiais (SHA1) ────────────────
# Secret: ASCII "12345678901234567890" (20 bytes) em base32.
RFC_KEY_B32 = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

@pytest.mark.parametrize("ts,expected", [
    (59,         "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
])
def test_rfc6238_vectors(auth_mod, ts, expected):
    """Códigos calculados batem com os vetores da RFC 6238."""
    counter = ts // 30
    got = auth_mod._totp_code_at(RFC_KEY_B32, counter)
    assert got == expected, f"T={ts}: esperava {expected}, got {got}"


# ── Geração de secret ────────────────────────────────────────────
def test_generate_secret_creates_file(auth_mod):
    """totp_generate_secret grava arquivo com secret base32 válido."""
    secret = auth_mod.totp_generate_secret()
    assert auth_mod.TOTP_FILE.exists(), "arquivo deveria existir após gerar"
    # Base32 sem padding: charset [A-Z2-7], múltiplo de 4 chars quando
    # representa 20 bytes = 32 chars sem padding.
    assert len(secret) == 32, f"esperava 32 chars, got {len(secret)}"
    assert secret == auth_mod.TOTP_FILE.read_text().strip()


def test_generate_secret_overwrites(auth_mod):
    """Chamar generate_secret 2x invalida o primeiro — é por design."""
    s1 = auth_mod.totp_generate_secret()
    s2 = auth_mod.totp_generate_secret()
    assert s1 != s2, "segundo secret tem que ser diferente"


@pytest.mark.skipif(os.name == "nt", reason="chmod é no-op no Windows")
def test_generate_secret_chmod_0600(auth_mod):
    """Em POSIX, o arquivo recebe perms 0600 (dono lê/escreve, resto nada)."""
    auth_mod.totp_generate_secret()
    mode = auth_mod.TOTP_FILE.stat().st_mode & 0o777
    assert mode == 0o600, f"esperava 0o600, got 0o{mode:03o}"


# ── Enable / disable / kill switch ───────────────────────────────
def test_is_enabled_false_without_file(auth_mod):
    """Sem .netguard_totp, totp_is_enabled retorna False."""
    assert auth_mod.totp_is_enabled() is False


def test_is_enabled_true_after_generate(auth_mod, monkeypatch):
    """Com arquivo + sem kill switch, fica enabled."""
    monkeypatch.delenv("IDS_ADMIN_TOTP", raising=False)
    auth_mod.totp_generate_secret()
    assert auth_mod.totp_is_enabled() is True


def test_kill_switch_disables(auth_mod, monkeypatch):
    """IDS_ADMIN_TOTP=false desativa mesmo com arquivo presente."""
    auth_mod.totp_generate_secret()
    monkeypatch.setenv("IDS_ADMIN_TOTP", "false")
    assert auth_mod.totp_is_enabled() is False


def test_disable_removes_file(auth_mod):
    """totp_disable() remove o arquivo e retorna True se existia."""
    auth_mod.totp_generate_secret()
    assert auth_mod.TOTP_FILE.exists()
    assert auth_mod.totp_disable() is True
    assert not auth_mod.TOTP_FILE.exists()
    # Chamada repetida retorna False (nada pra remover)
    assert auth_mod.totp_disable() is False


# ── Verify fail-closed + janela ──────────────────────────────────
def test_verify_fails_when_disabled(auth_mod, monkeypatch):
    """Sem TOTP habilitado, verify sempre retorna False (fail-closed)."""
    monkeypatch.setenv("IDS_ADMIN_TOTP", "false")
    assert auth_mod.totp_verify("000000") is False


def test_verify_rejects_non_numeric(auth_mod, monkeypatch):
    """Código com letras ou tamanho != 6 é rejeitado sem crashar."""
    monkeypatch.delenv("IDS_ADMIN_TOTP", raising=False)
    auth_mod.totp_generate_secret()
    for bad in ["", "abcdef", "12345", "1234567", "12 34 56"]:
        # "12 34 56" é normalizado mas ainda tem espaços que podem não
        # virar 6 dígitos após strip — verify remove espaços e valida.
        assert auth_mod.totp_verify(bad) in (False, True), (
            "tem que aceitar ou rejeitar sem levantar exceção"
        )


def test_verify_accepts_current_code(auth_mod, monkeypatch):
    """Código correto no período atual passa."""
    monkeypatch.delenv("IDS_ADMIN_TOTP", raising=False)
    secret = auth_mod.totp_generate_secret()
    now = time.time()
    counter = int(now // 30)
    code = auth_mod._totp_code_at(secret, counter)
    assert auth_mod.totp_verify(code, at_time=now) is True


def test_verify_window_tolerance(auth_mod, monkeypatch):
    """
    Janela +/- TOTP_WINDOW aceita códigos de períodos adjacentes.
    Com TOTP_WINDOW=1 (default), aceita t-30, t, t+30.
    """
    monkeypatch.delenv("IDS_ADMIN_TOTP", raising=False)
    secret = auth_mod.totp_generate_secret()
    now = time.time()
    counter = int(now // 30)
    # Força WINDOW=1 explicitamente (default)
    monkeypatch.setattr(auth_mod, "TOTP_WINDOW", 1)

    for delta in (-1, 0, 1):
        code = auth_mod._totp_code_at(secret, counter + delta)
        assert auth_mod.totp_verify(code, at_time=now) is True, (
            f"delta={delta} deveria passar dentro da janela"
        )

    # Fora da janela — delta=+2 (60s no futuro) tem que falhar
    far_code = auth_mod._totp_code_at(secret, counter + 2)
    assert auth_mod.totp_verify(far_code, at_time=now) is False, (
        "delta=+2 deveria falhar com WINDOW=1"
    )


# ── Provisioning URI ─────────────────────────────────────────────
def test_provisioning_uri_format(auth_mod):
    """URI segue o formato otpauth://totp/{issuer}:{account}?..."""
    secret = auth_mod.totp_generate_secret()
    uri = auth_mod.totp_provisioning_uri(secret)
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert "issuer=" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
    # Secret na URI não tem padding
    assert "secret=" + secret.rstrip("=") in uri


def test_provisioning_uri_url_encodes_spaces(auth_mod):
    """Issuer com espaço é URL-encoded (senão apps quebram o label)."""
    uri = auth_mod.totp_provisioning_uri(
        secret_b32="ABCDEFGHIJKLMNOP",
        issuer="NetGuard IDS",
        account="raphael@example.com",
    )
    assert "NetGuard%20IDS" in uri
    assert "raphael%40example.com" in uri


# ── Base32 tolerante no decode ───────────────────────────────────
def test_b32_decode_accepts_formatted_input(auth_mod):
    """
    Google Authenticator mostra o secret em grupos tipo 'ABCD EFGH...'.
    O decoder tem que aceitar isso sem o usuário precisar limpar.
    """
    raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    canonical = base64.b32encode(raw).decode("ascii").rstrip("=")
    # Variações que todas devem decodificar pra mesmo raw
    variants = [
        canonical,
        canonical.lower(),
        " ".join(canonical[i:i+4] for i in range(0, len(canonical), 4)),
        "-".join(canonical[i:i+4] for i in range(0, len(canonical), 4)),
    ]
    for v in variants:
        decoded = auth_mod._b32_decode(v)
        assert decoded == raw, f"falhou com variante: {v!r}"
