from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_netguard_design_tokens_are_centralized():
    css = _read("static/css/netguard.css")
    for token in (
        "--bg",
        "--panel",
        "--panel-soft",
        "--border",
        "--text",
        "--muted",
        "--critical",
        "--high",
        "--medium",
        "--low",
        "--accent",
        "--success",
    ):
        assert token in css


def test_shared_ui_assets_exist_and_are_referenced():
    assert (ROOT / "static/css/netguard.css").is_file()
    assert (ROOT / "static/js/netguard-ui.js").is_file()

    pages = [
        "admin.html",
        "dashboard.html",
        "dashboard/templates_html.py",
        "templates/admin_dashboard.html",
        "templates/host_triage.html",
        "templates/landing.html",
        "templates/login.html",
        "templates/operator_inbox.html",
        "templates/pricing.html",
        "templates/welcome.html",
        "templates/soc/base.html",
    ]
    for page in pages:
        assert "netguard.css" in _read(page), page


def test_soc_sidebar_has_product_workspace_sections():
    sidebar = _read("templates/soc/partials/sidebar.html")
    for label in (
        "Monitoring",
        "Investigation",
        "Management",
        "System",
        "Overview",
        "Operator Inbox",
        "Incidents",
        "Host Triage",
        "Agents",
        "Tenants",
        "Rules",
        "Settings",
    ):
        assert label in sidebar


def test_guided_soc_recommendation_assets_are_wired():
    app_src = _read("app.py")
    service_src = _read("services/recommendation_service.py")
    js = _read("static/js/netguard-ui.js")
    overview = _read("templates/soc/overview.html")

    assert "get_recommended_route" in app_src
    assert '@app.route("/api/recommended-route")' in app_src
    assert "SAFE_ROUTE_PREFIXES" in service_src
    assert "/api/recommended-route" in js
    assert "Recommended Next Action" in overview
    assert "Overview -> Inbox -> Host Triage -> Incident -> Resolution" in _read("templates/soc/partials/topbar.html")


def test_apple_enterprise_ui_layer_exists():
    css = _read("static/css/netguard.css")
    for marker in (
        "Apple/enterprise product layer",
        "#f5f5f7",
        "ngFadeIn",
        "ngSlideUp",
        ".soc-guided-action",
        ".ng-recommendation",
        ".soc-sidebar-status",
    ):
        assert marker in css


def test_dark_enterprise_layer_and_local_login_are_wired():
    css = _read("static/css/netguard.css")
    login = _read("templates/login.html")
    app_src = _read("app.py")

    for marker in (
        "Executive dark product layer",
        "#070a0f",
        ".local-session-card",
        "Entrar em modo local",
        "api/auth/local-session",
    ):
        assert marker in css or marker in login or marker in app_src


def test_primary_ui_routes_are_wired_to_existing_surfaces():
    app_src = _read("app.py")
    soc_src = _read("routes/soc.py")

    for route in ('@app.route("/admin")', '@app.route("/dashboard")', '@app.route("/pricing")'):
        assert route in app_src
    for route in ('@bp.route("/soc")', '@bp.route("/soc/hosts")', '@bp.route("/soc/incidents")'):
        assert route in soc_src

    for path in (
        "admin.html",
        "dashboard.html",
        "templates/operator_inbox.html",
        "templates/host_triage.html",
        "templates/soc/overview.html",
        "templates/soc/hosts.html",
        "templates/soc/incidents.html",
    ):
        assert (ROOT / path).is_file()


def test_security_sensitive_soc_actions_keep_csrf_headers():
    host_detail = _read("templates/soc/host_detail.html")
    incidents = _read("templates/soc/incidents.html")

    assert "X-CSRFToken" in host_detail
    assert "X-CSRFToken" in incidents
    assert "/soc/hosts/${encodeURIComponent(hostId)}/actions" in host_detail
    assert "`/soc/incidents/${incidentId}/status`" in incidents


def test_enterprise_ui_assets_do_not_embed_secrets():
    combined = "\n".join(
        _read(path)
        for path in (
            "static/css/netguard.css",
            "static/js/netguard-ui.js",
            "templates/landing.html",
            "templates/operator_inbox.html",
        )
    ).lower()
    forbidden = (
        "token_signing_secret",
        "netguard-insecure-dev-key-change-in-prod",
        "sk_live_",
        "sk_test_",
        "api_key=",
    )
    for marker in forbidden:
        assert marker not in combined
