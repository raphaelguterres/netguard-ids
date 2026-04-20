"""
test_csrf_coverage.py — Garante que endpoints admin mutativos estão protegidos.

Por que AST (e não cliente HTTP real):
  Teste rodado cedo no ciclo, não depende de subir Flask app. Pega regressão
  no momento em que alguém adiciona endpoint novo sem @csrf_protect ou sem
  gate de admin. Complementa os testes de integração (que testam runtime).

Cobertura exigida pra TODO endpoint /api/admin/* com método mutativo
(POST/PUT/PATCH/DELETE):
  - @csrf_protect presente
  - Gate de admin presente: @_admin_only OU @require_role("admin")
"""
import ast
import pathlib

import pytest


MUTATIVE = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_GUARDS = {"_admin_only", "require_role"}  # require_role("admin") conta


def _collect_admin_endpoints():
    """
    Walk AST de app.py retornando (path, methods, decorators, function_name)
    pra cada handler registrado em /api/admin/*.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    tree = ast.parse((root / "app.py").read_text(encoding="utf-8"))
    endpoints = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec_names = []
        routes = []
        methods = set()
        for d in node.decorator_list:
            # @app.route("/path", methods=[...])
            if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr == "route"):
                path = ""
                if d.args and isinstance(d.args[0], ast.Constant):
                    path = d.args[0].value
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, ast.List):
                        methods |= {
                            e.value for e in kw.value.elts
                            if isinstance(e, ast.Constant)
                        }
                routes.append(path)
            # @decorator_name
            elif isinstance(d, ast.Name):
                dec_names.append(d.id)
            # @decorator_name(...)
            elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name):
                dec_names.append(d.func.id)
        for path in routes:
            if path.startswith("/api/admin/"):
                endpoints.append({
                    "path": path,
                    "methods": methods,
                    "decorators": dec_names,
                    "fn": node.name,
                })
    return endpoints


ALL_ENDPOINTS = _collect_admin_endpoints()
MUTATIVE_ENDPOINTS = [
    e for e in ALL_ENDPOINTS if e["methods"] & MUTATIVE
]


def test_there_are_mutative_admin_endpoints():
    """Sanity check: a coleta encontrou pelo menos os 10 endpoints conhecidos."""
    assert len(MUTATIVE_ENDPOINTS) >= 10, (
        f"Só achei {len(MUTATIVE_ENDPOINTS)} endpoints — AST walker quebrou?"
    )


@pytest.mark.parametrize("ep", MUTATIVE_ENDPOINTS, ids=lambda e: f"{e['fn']}({e['path']})")
def test_mutative_admin_endpoint_has_csrf_protect(ep):
    """Todo POST/PUT/PATCH/DELETE em /api/admin/* tem @csrf_protect."""
    assert "csrf_protect" in ep["decorators"], (
        f"{ep['fn']} ({ep['path']}) NÃO tem @csrf_protect — "
        "adicione ou o endpoint fica vulnerável a CSRF"
    )


@pytest.mark.parametrize("ep", MUTATIVE_ENDPOINTS, ids=lambda e: f"{e['fn']}({e['path']})")
def test_mutative_admin_endpoint_has_admin_gate(ep):
    """Todo endpoint admin tem gate de admin (_admin_only ou require_role)."""
    has_gate = any(d in ADMIN_GUARDS for d in ep["decorators"])
    assert has_gate, (
        f"{ep['fn']} ({ep['path']}) NÃO tem gate de admin "
        f"(_admin_only OU require_role). Decorators: {ep['decorators']}"
    )
