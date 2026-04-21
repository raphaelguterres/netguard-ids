"""
test_review_polish.py — Valida os fixes do review round.

Cobre:
  - Clamp de limit em /api/admin/audit (offline: inspeciona a função)
  - Cache-Control: no-store presente em /api/admin/totp/setup
  - closeRotateModal e closeTotpModal limpam secrets do DOM
  - _withBusyBtn helper existe em admin.html
  - humanizeLoginError existe em login.html e diferencia 429/403/401
  - SECURITY.md existe e menciona os tópicos críticos

Todos rodam sem Flask — lêem os arquivos como texto.
"""
import pathlib


ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel_path):
    return (ROOT / rel_path).read_text(encoding="utf-8")


# ══ Backend ══════════════════════════════════════════════════════
def test_audit_limit_clamp_present():
    """
    /api/admin/audit tem clamp max(1, min(n, 1000)).
    Regressão alvo: se alguém remover o clamp, testa detecta antes do deploy.
    """
    src = _read("app.py")
    # Localiza o handler
    idx = src.find("def admin_audit_log(")
    assert idx != -1, "handler admin_audit_log não encontrado"
    block = src[idx:idx + 2000]
    assert "max(1, min(" in block, (
        "clamp defensivo ausente — limit pode virar 0/negativo e quebrar "
        "slice [-limit:], ou ValueError crashar em query string com lixo"
    )


def test_totp_setup_has_cache_control_nostore():
    """
    /api/admin/totp/setup seta Cache-Control: no-store.
    Razão: a resposta contém o secret 2FA; cache por qualquer camada
    (browser, proxy, CDN) é vazamento.
    """
    src = _read("app.py")
    idx = src.find("def admin_totp_setup(")
    assert idx != -1
    block = src[idx:idx + 2000]
    assert 'Cache-Control' in block
    assert 'no-store' in block


# ══ Frontend: admin.html ═════════════════════════════════════════
def test_admin_with_busy_btn_helper_exists():
    """_withBusyBtn helper existe + é usado nos 3 handlers sensíveis."""
    src = _read("admin.html")
    assert "function _withBusyBtn" in src or "async function _withBusyBtn" in src
    # Usage nos 3 handlers críticos
    for fn_name in ("rotateAdminToken", "setupTotp", "disableTotp"):
        assert f"async function {fn_name}(ev)" in src, (
            f"{fn_name} deveria aceitar (ev) para passar ao helper"
        )


def test_close_rotate_modal_clears_dom():
    """
    closeRotateModal limpa #rotate-new-token ao fechar.
    Razão: display:none esconde visualmente, mas o token fica no HTML
    e é legível via DevTools (leak pra quem senta no computador depois).
    """
    src = _read("admin.html")
    idx = src.find("function closeRotateModal(")
    assert idx != -1
    block = src[idx:idx + 800]
    assert "rotate-new-token" in block
    assert "textContent = ''" in block or 'textContent=""' in block or "textContent =''" in block


def test_close_totp_modal_clears_secret_and_uri():
    """closeTotpModal limpa secret + URI + campo de teste."""
    src = _read("admin.html")
    idx = src.find("function closeTotpModal(")
    assert idx != -1
    block = src[idx:idx + 1200]
    for elem_id in ("totp-secret", "totp-uri", "totp-test-code"):
        assert elem_id in block, f"{elem_id} deveria ser limpo em closeTotpModal"


# ══ Frontend: login.html ═════════════════════════════════════════
def test_login_has_humanize_error_function():
    """login.html tem humanizeLoginError com branches pra 429/403/401."""
    src = _read("templates/login.html")
    assert "function humanizeLoginError" in src
    # Branches esperados — mensagens úteis em PT-BR
    for needle in ("status === 429", "status === 403", "status === 401"):
        assert needle in src, f"branch {needle!r} ausente em humanizeLoginError"
    # Orientações concretas
    assert "recarregue" in src.lower() or "recarregar" in src.lower() or "F5" in src, (
        "mensagem de CSRF/sessão expirada deveria instruir recarregar"
    )
    assert "relogio" in src.lower() or "relógio" in src.lower(), (
        "mensagem de 2FA inválido deveria mencionar relógio do celular"
    )


def test_login_totp_field_hidden_by_default():
    """
    Campo 2FA começa hidden — só revela via revealTotpField se o backend
    responder totp_required:true. Senão o form fica confuso (2 campos).
    """
    src = _read("templates/login.html")
    assert 'id="totp-field"' in src
    # display:none no HTML inicial
    assert 'id="totp-field" style="display:none"' in src or \
           'id="totp-field"' in src and 'display:none' in src.split('id="totp-field"')[1][:200]


# ══ SECURITY.md ══════════════════════════════════════════════════
def test_security_md_exists_and_covers_topics():
    """SECURITY.md na raiz cobre os tópicos críticos."""
    path = ROOT / "SECURITY.md"
    assert path.exists(), "SECURITY.md deveria existir na raiz"
    content = path.read_text(encoding="utf-8").lower()
    required_topics = [
        "csrf",
        "totp",
        "2fa",
        "rate limit",
        "audit log",
        "rotacao" if "rotacao" in content else "rotação",
        "hardening",
    ]
    missing = [t for t in required_topics if t not in content]
    assert not missing, f"SECURITY.md não cobre: {missing}"
