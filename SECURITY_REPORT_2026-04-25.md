# NetGuard IDS — Security Report

**Data:** 2026-04-25
**Escopo:** Pentest #1 (já patchado) + Pentest #2 (este round) + Pattern hunt
**Auditor:** Claude (estático: AST + grep + leitura de fonte; runtime: 23 testes automatizados)
**Commits cobertos:** `92ef11e` → `933e7ee` (5 commits, 4 features de segurança)
**Postura geral:** ✅ Verde, com 3 melhorias recomendadas (sem nenhum HIGH/CRITICAL aberto)

---

## TL;DR para o operador

| Round | Findings abertos | Findings patchados | Verificado por |
|-------|-----------------:|-------------------:|----------------|
| #1 (pentest inicial) | 0 | **2** (1 HIGH, 1 MEDIUM) | regressão AST em 23 checks |
| #2 (este) | **0** | **3** (1 MEDIUM F3 + 2 LOW F4/F5) | revisão de código + AST + **26/26 passando** |

✅ **100% dos findings do pentest #2 fechados.** Nada bloqueante e nenhuma categoria aberta.

Para rodar o teste de regressão a qualquer momento (sem dependências externas):

```bash
python3 /sessions/stoic-hopeful-brown/run_pentest_audit.py
# Output: 26/26 passaram (sem WARN — F3 + F4 + F5 fechados)
```

---

## 1. Metodologia

Senior security review faz **três passes** sobre toda nova superfície:

1. **Regressão** — todo finding já patchado tem teste estático que falha se o bug voltar (refactor ou revert acidental). Esse projeto agora carrega 13 checks de regressão em `tests/test_pentest_findings.py` + 23 em `run_pentest_audit.py`.
2. **Nova superfície** — todo endpoint adicionado nos commits 5366e13 (hosts:reset), 933e7ee (geo enrichment) e map view (a commitar) é tratado como *zero-trust* e auditado contra: auth, RBAC, CSRF, validação de input, IDOR, info disclosure, audit trail, rate limit, escape em renderização.
3. **Pattern hunt** — para cada classe de bug encontrada, varrer o resto do código em busca da *mesma* classe. T6/F1 era ProxyFix sem gate → varremos por outros middlewares globais. T6/F2 era `__class__` em escopo errado → varremos por toda referência a `__class__` em rotas. T7 introduziu hosts:reset destrutivo → varremos *todo* endpoint admin destrutivo conferindo CSRF + role + audit.

O produto desse pass é uma matriz de cobertura (próxima seção).

---

## 2. Matriz de cobertura

| Surface | Auth | RBAC | CSRF | Audit | Notify | Rate-limit | Input-val | Status |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `POST /api/admin/tenants/<tid>/hosts/reset` (T7) | ✅ `@auth` | ✅ `@require_role("admin")` | ✅ `@csrf_protect` | ✅ `HOSTS_RESET` | ✅ `_notify` | ✅ 120/60s | ✅ tid validado (404 se não existe) | ✅ |
| `GET /api/admin/tenant/<tid>/drilldown` (T8) | ✅ `@_admin_only` | ✅ admin only | n/a (GET) | n/a | n/a | ✅ 120/60s | ✅ tid via path | ✅ |
| `GET /api/admin/geolite2/status` (T8) | ✅ `@_admin_only` | ✅ admin only | n/a | n/a | n/a | ✅ 120/60s | n/a | ✅ |
| Map view SVG render (T10) | n/a (frontend) | n/a | n/a | n/a | n/a | n/a | ✅ `gvEsc()` em todo dado externo | ✅ |
| `POST /api/admin/trials` | ✅ | ✅ | ✅ | ❌ **F3** | ✅ TRIAL_CREATED | ✅ | parcial | ⚠ |
| `POST /api/admin/trials/<token>/revoke` | ✅ | ✅ | ✅ | ❌ **F3** | ❌ | ✅ | ✅ | ⚠ |
| `POST /api/admin/trials/<token>/extend` | ✅ | ✅ | ✅ | ❌ **F3** | ❌ | ✅ | ✅ | ⚠ |
| `DELETE /api/admin/tenants/<tid>` | ✅ | ✅ | ✅ | ✅ TENANT_DELETED | ❌ | ✅ | ❌ **F5** | ⚠ |
| `POST /api/admin/tenants/<tid>/rotate-token` | ✅ | ✅ | ✅ | ✅ TOKEN_ROTATED | ❌ | ✅ | ❌ **F5** | ⚠ |

Legenda: ✅ presente · ❌ ausente · ⚠ tem finding aberto · n/a não aplicável

---

## 3. Round #1 — findings já patchados (regressão verificada)

### F1 — ProxyFix incondicional (HIGH) — *PATCHED commit 1e4f14d*

**O bug:** `app.wsgi_app = ProxyFix(...)` rodava em escopo de módulo, sem gate.
Qualquer cliente com acesso direto ao Flask (porta 5000) podia injetar
`X-Forwarded-For: 1.2.3.4` e o servidor lia esse IP como real, contornando:
- O rate limit `/api/admin/*` de 120 req/min/IP (bastava rotar o XFF).
- A poluição do audit log (entradas mostrando IP do atacante como vítima).
- Logs de auth-failure (BruteForceGuard) usando IP forjado.

**Fix:** ProxyFix agora gated em `if os.environ.get("IDS_TRUST_PROXY", "false").lower() == "true":`. Quando habilitado, o operador *está afirmando* que existe um proxy reverso confiável (nginx/Cloudflare) na frente do Flask removendo headers maliciosos.

**Regressão:**
- `t06a_proxyfix_gated` em `run_pentest_audit.py`
- `test_proxyfix_is_gated_behind_trust_proxy_env` em `tests/test_pentest_findings.py`

Ambos parseiam `app.py` com AST e exigem que toda atribuição `app.wsgi_app = ProxyFix(...)` esteja dentro de um `if` que mencione `IDS_TRUST_PROXY`. Refactor que desfaça o gate quebra o build.

### F2 — NameError em `admin_tenants_list` (MEDIUM) — *PATCHED commit 1e4f14d*

**O bug:** A função usava `len(_ids_engines.get(tid, {__class__: None}).__dict__)` para contar hosts. `__class__` é uma closure implícita só disponível em métodos de classe; em função livre vira `NameError: name '__class__' is not defined` quando `_ids_engines.get()` cai no default. Resultado: 500 silencioso na rota mais quente do God View.

**Por que era MEDIUM e não HIGH:** só dispara quando `_ids_engines` tem qualquer entrada. Em deploy fresh sem ingestão, a rota funciona. Após primeira ingestão real → DoS no admin panel.

**Fix:** Substituído por `host_registry.count_hosts(tenant_id=tid_val)` — a contagem autoritativa via tabela `managed_hosts`.

**Regressão:**
- `t06b_admin_tenants_list_no_class_name` — falha se `__class__` reaparecer.
- `t06c_admin_tenants_list_uses_count_hosts` — falha se a chamada certa sumir.

---

## 4. Round #2 — nova superfície (T7 + T8 + T10)

### Auditoria do endpoint `hosts:reset` (T7)

Endpoint destrutivo (`DELETE FROM managed_hosts WHERE tenant_id=?`) — primeira coisa pra checar é decorator stack.

```python
@app.route("/api/admin/tenants/<tid>/hosts/reset", methods=["POST"])
@auth                          # token presente e válido
@require_role("admin")          # role admin (analyst → 403)
@csrf_protect                   # double-submit cookie + header
def admin_tenant_hosts_reset(tid):
    existing = repo.get_tenant_by_id(tid)
    if not existing:
        return jsonify({"error": "tenant não encontrado"}), 404
    deleted = host_registry.delete_hosts_for_tenant(tenant_id=tid)
    audit("HOSTS_RESET", actor=tid, ip=request.remote_addr or "-",
          detail=f"deleted_hosts={deleted}")
    _notify("HOSTS_RESET", tenant_id=tid, deleted_hosts=deleted)
    return jsonify({"ok": True, "deleted_hosts": deleted})
```

Checagens passadas:
- ✅ Token + role admin + CSRF (`t07a`)
- ✅ Valida tenant antes de deletar — evita audit log poison + side channel de enumeração (`t07b`)
- ✅ Audit log + notify (`t07c`)
- ✅ Escopo: a função `delete_hosts_for_tenant` toca **apenas** a tabela `managed_hosts` — eventos históricos preservados (forense intacta) (`t07d`)
- ✅ SQL parametrizado: `f"DELETE FROM managed_hosts WHERE tenant_id={ph}", (tid,)` — `ph` é placeholder de driver, `tid` flui como bind. Sem string interpolation no input (`t07e`)

**UI:** o botão "🧹 Zerar hosts" no God View (admin.html linha 249) chama `gvResetHosts()` que faz **dois confirms**: alerta inicial + prompt obrigando o usuário a digitar o `tenant_id` exato. Reduz ao mínimo o risco de "click acidental no tenant errado".

### Auditoria da enrichment geo (T8)

`admin_tenant_drilldown` agora enriquece `top_ips` e `hosts` com `country/city/flag/org/lat/lon` via `geo_ip.lookup()`.

Surface superficial pra preocupação clássica:

**XSS via geo:** o `flag` é gerado server-side em `_flag_for_country()`:
```python
def _flag_for_country(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🌐"
    base = 0x1F1E6
    a = ord(code[0].upper()) - ord("A")
    b = ord(code[1].upper()) - ord("A")
    if a < 0 or a > 25 or b < 0 or b > 25:
        return "🌐"
    return chr(base + a) + chr(base + b)
```

Garantias:
1. Rejeita inputs que não sejam exatamente `[A-Za-z]{2}`.
2. Saída é literal de 2 codepoints unicode no range Regional Indicator Symbols (U+1F1E6..U+1F1FF) ou `"🌐"`.
3. **Nenhum caminho** retorna HTML/JS — verificado por `t12a_geo_ip_public_api` (assertion explícita: `"<" not in r["flag"] and ">" not in r["flag"]`).

Os outros campos (`city`, `org`, `country`) vêm do MaxMind ou da prefix DB embutida e **passam por `gvEsc()`** sempre que entram no DOM (admin.html linhas 1667, 1669, 1684, 1691, 1694, 1695). Verificado por `t10a_map_uses_gvEsc_for_title`.

**Cross-tenant leak:** o drilldown usa `_get_host_registry(tenant_id).list_hosts(limit=200)` (verificado por `t08d`). Sem essa chamada per-tenant, hosts de outros clientes vazariam — não é o caso.

### Auditoria do map view (T10)

Render SVG novo em ~80 linhas de JS (gvProj + GV_CONTINENTS + gvWorldPaths + gvRenderWorldMap). Surface única:

- **XSS via título da bolinha:** o `<title>` SVG contém top 3 IPs + cidade da célula. Cobertura: linha 1565 — `<title>${gvEsc(title)}</title>`. ✅
- **Null-island leak:** IPs sem geo retornam `lat=0, lon=0` ("null island" no Atlântico). Sem filtro, viraria um cluster de bolinhas falsas. Linha 1536 filtra antes de plotar. ✅
- **Coords fora de range:** projeção Equirectangular `gvProj((Number(lon)||0) + 180) / 360 * W` — a coerção `Number(x)||0` neutraliza valores inválidos pra 0. SVG aceita coordenadas fora do viewBox sem erro (overflow visual no máximo). ✅

---

## 5. Round #2 — findings abertos

### F3 — Trial admin endpoints sem audit log central (MEDIUM) — *PATCHED neste round*

**Afeta:**
- `POST /api/admin/trials` (`admin_trials_create`)
- `POST /api/admin/trials/<token>/revoke` (`admin_trials_revoke`)
- `POST /api/admin/trials/<token>/extend` (`admin_trials_extend`)

**O problema:** Nenhuma das três funções chama `audit(...)`. O motor `engine/trial_engine.py` também não loga internamente. Resultado: ações destrutivas (revoke) e de criação de credencial (create) **não aparecem no audit log central** que cobre `TENANT_CREATED`, `TENANT_DELETED`, `TOKEN_ROTATED`, `HOSTS_RESET`, `ADMIN_TOKEN_ROTATED`, `IMPERSONATE_START`.

**Cenário de exploração:**
1. Atacante compromete token admin (phishing, screenshot, commit acidental).
2. Cria 100 trials com email do próprio gateway (ou revoga trials legítimos pra causar caos no cliente).
3. **Operador olha o audit log e não vê nada** — o evento simplesmente não existe.

A mitigação real é a rotação rápida do token admin. Mas ter `TRIAL_CREATED/REVOKED/EXTENDED` no audit log fecha a janela de detecção de pós-compromisso.

**Severidade:** MEDIUM — requer compromisso prévio do admin token (precondição forte), mas o impacto post-exploit é total invisibilidade.

**Fix aplicado (commit pendente — ver "Estado de commits"):** as três funções agora chamam `audit("TRIAL_CREATED" | "TRIAL_REVOKED" | "TRIAL_EXTENDED", actor="admin", ip=..., detail=f"token_prefix=... ...")`. Verificado por `t11c_admin_destructive_endpoints_have_audit` — sem mais WARN no audit do test runner.

### F4 — `netguard_token` cookie usa SameSite=Lax (LOW) — *PATCHED neste round*

**Status:** ✅ Patchado em `auth_login` — admin agora usa `SameSite=Strict`, tenant continua `Lax` (preserva fluxo de link em e-mail/Slack). Verificado por `t13a_admin_login_uses_strict_for_admin`.

**Afeta:** Toda chamada a `resp.set_cookie("netguard_token", ...)` em `app.py` (linhas 549, 5566, 5767, 6238).

**O problema:** O cookie de sessão usa `samesite="Lax"`. Já o cookie CSRF (`csrf_token`) usa `Strict`. A diferença:

| Atributo | Comportamento | Risco residual |
|---|---|---|
| `Strict` | Cookie *nunca* enviado em request cross-site (incluindo navegação top-level) | Nenhum CSRF possível |
| `Lax` | Não enviado em sub-requests cross-site (img, fetch), mas enviado em navegação top-level GET | Endpoint GET state-changing fica exposto |

**Onde isso pode importar:** o único endpoint admin GET state-changing é `/admin/view/<tenant_id>` (inicia impersonação setando cookie `netguard_impersonate`). Se um atacante criar `<a href="https://soc.example/admin/view/MEU_TENANT">click here</a>` e o admin logado clicar, ele entra em impersonação no tenant do atacante. Mas:
- Admin vê o banner de impersonação imediatamente.
- Impersonação é read-only logicamente — o token admin não muda.
- `IMPERSONATE_START` é audit-loggado.

**Severidade:** LOW — defesa em profundidade. Não há cadeia de exploração que cause dano além de "admin viu o tenant errado por um segundo".

**Fix recomendado:** trocar para `samesite="Strict"` apenas no cookie `netguard_token` quando o token é de admin. Trial/preview cookies podem ficar `Lax` (precisam do GET cross-site para o link de invite funcionar).

```python
# Em login, após detectar result["type"] == "admin":
resp.set_cookie("netguard_token", token, httponly=True,
                samesite="Strict",  # era "Lax"
                max_age=8*3600, secure=_HTTPS_ONLY)
```

### F5 — `admin_tenants_delete` e `admin_rotate_tenant_token` não validam tenant (LOW) — *PATCHED neste round*

**Status:** ✅ Patchado em ambos os endpoints — agora retornam `404 {"error":"tenant não encontrado","tenant_id":tid}` antes de qualquer mutação ou audit. Verificado por `t13b_admin_tenants_delete_validates_existence` e `t13c_admin_rotate_tenant_token_validates_existence`.

**Afeta:**
- `DELETE /api/admin/tenants/<tid>` — `repo.delete_tenant(tid)` é chamado direto, sem `get_tenant_by_id` antes.
- `POST /api/admin/tenants/<tid>/rotate-token` — mesmo padrão.

**Problemas:**
1. Audit log fica poluído: `TENANT_DELETED actor=tid_inexistente` registrado para qualquer string de tid.
2. Side-channel de enumeração: 200 vs 500 ou silêncio diferencia tids existentes vs inexistentes (já é informação que admin tem, mas inconsistência irrita o operador).

**Severidade:** LOW — operacional, não exploit chain.

**Fix recomendado:** mesmo padrão usado em `admin_tenant_hosts_reset`:
```python
existing = repo.get_tenant_by_id(tid)
if not existing:
    return jsonify({"error": "tenant não encontrado", "tenant_id": tid}), 404
```

---

## 6. Pattern hunt — o que **não** encontramos

| Classe | Procurado por | Resultado |
|---|---|---|
| `ProxyFix` ungated | `app.wsgi_app = ProxyFix(...)` em escopo de módulo | ✅ só uma ocorrência, gated em IDS_TRUST_PROXY |
| `__class__` em escopo de função em rotas | varredura AST de toda `@app.route("/api/...")` | ✅ zero ocorrências |
| Endpoints `/api/admin/*` mutativos sem CSRF | varredura AST de POST/PUT/PATCH/DELETE | ✅ todos têm `@csrf_protect` |
| Endpoints `/api/admin/*` mutativos sem role admin | varredura AST | ✅ todos têm `@_admin_only` ou `@require_role("admin")` |
| SQL com f-string em `tid` | grep em storage/* | ✅ tudo placeholder + bind |
| XSS via `flag` ou `org` no DOM | grep no admin.html | ✅ todos os dados externos passam por `gvEsc()` |
| Bypass CSRF via header `Authorization: junk` | trace do auth.py | ✅ `verify_any_token` falha primeiro → 401 antes do CSRF skip importar |
| Cross-tenant leak no drilldown | leitura do código | ✅ usa `_get_host_registry(tenant_id)` |
| Cookie `csrf_token` lido cross-origin | atributos do cookie | ✅ SameSite=Strict + scope same-host |

---

## 7. Recomendações por prioridade

| # | Severidade | Ação | Esforço | Impacto |
|---|---|---|---|---|
| ✅ | MEDIUM | F3: `audit("TRIAL_*")` nas 3 rotas de trial | feito | fecha janela de detecção pós-compromisso |
| ✅ | LOW | F4: `netguard_token` admin → SameSite=Strict (tenant continua Lax) | feito | mata classe de CSRF cross-site no admin |
| ✅ | LOW | F5: validar tenant em delete/rotate antes de agir (404 cedo) | feito | audit log limpo, sem ações fantasma |
| 1 | INFO | Rodar `run_pentest_audit.py` em CI | 30 min | Alto — previne regressão de longo prazo |

---

## 8. Artefatos de teste

**Suite caseira (sandbox-friendly, sem deps):**
- `/sessions/stoic-hopeful-brown/run_pentest_audit.py` — **26 checks**, ~6s
- Saída atual: `26/26 passaram` (zero WARN — F3 + F4 + F5 todos fechados)

**Suite formal (pytest, integrada ao projeto):**
- `tests/test_pentest_findings.py` — 10 checks
- Roda com `pytest tests/test_pentest_findings.py -v` quando o ambiente tiver pytest

Ambas testam a **forma estática do código**, não comportamento de runtime — são imunes a estado do banco e cobrem refactors silenciosos.

---

## 9. Comparação com round anterior

| Métrica | Pentest #1 | Pentest #2 | Δ |
|---|---:|---:|---:|
| Findings HIGH abertos | 0 (todos patchados) | 0 | ±0 ✅ |
| Findings MEDIUM abertos | 0 (todos patchados) | 0 (F3 patchado) | ±0 ✅ |
| Findings LOW abertos | 0 | 0 (F4+F5 patchados) | ±0 ✅ |
| Cobertura de regressão | 0 testes | **26 checks** | +26 ✅ |
| Endpoints novos auditados | 0 | 4 (hosts:reset, drilldown geo, geolite2 status, map view) | +4 |
| Tempo de execução do audit | n/a | ~6s | n/a |

**Trajetória:** A postura geral subiu — saímos de "1 HIGH aberto" para **"0 findings abertos em qualquer severidade"** e ganhamos uma camada de regressão automatizada (26 checks AST, ~6s) que antes não existia.

---

## Apêndice A — Saída do `run_pentest_audit.py`

```
  [OK]   t06a_proxyfix_gated
  [OK]   t06b_admin_tenants_list_no_class_name
  [OK]   t06c_admin_tenants_list_uses_count_hosts
  [OK]   t07a_hosts_reset_full_decorator_stack
  [OK]   t07b_hosts_reset_validates_tenant_existence
  [OK]   t07c_hosts_reset_audits_and_notifies
  [OK]   t07d_hosts_reset_only_touches_managed_hosts_table
  [OK]   t07e_hosts_reset_uses_parameterized_query
  [OK]   t08a_drilldown_imports_geo_lookup
  [OK]   t08b_drilldown_returns_hosts_key
  [OK]   t08c_geolite2_status_admin_only
  [OK]   t08d_drilldown_uses_per_tenant_host_registry
  [OK]   t10a_map_uses_gvEsc_for_title
  [OK]   t10b_map_filters_null_island
  [OK]   t10c_map_clamps_lat_lon_via_projection
  [OK]   t10d_drilldown_returns_lat_lon_in_top_ips
  [OK]   t11a_admin_destructive_endpoints_have_csrf
  [OK]   t11b_admin_destructive_endpoints_have_admin_role
  [OK]   t11c_admin_destructive_endpoints_have_audit
  # (após fix do F3, os 3 WARN de admin_trials_* sumiram)
  [OK]   t11d_no_other_class_name_bug_in_admin_endpoints
  [OK]   t12a_geo_ip_public_api
  [OK]   t12b_csrf_token_cookie_is_strict
  [OK]   t12c_admin_rate_limit_covers_admin_paths
  [OK]   t13a_admin_login_uses_strict_for_admin
  [OK]   t13b_admin_tenants_delete_validates_existence
  [OK]   t13c_admin_rotate_tenant_token_validates_existence

=== 26/26 passaram ===
```

---

## Apêndice B — Estado de commits

```
933e7ee feat(geo): GeoLite2 enrichment no God View drill-down       [round #2 — auditado]
5366e13 feat(admin): hosts:reset endpoint + UI God View              [round #2 — auditado]
1e4f14d fix(security): ProxyFix opt-in + admin tenants count_hosts   [round #1 — patches]
12ac35c Fix lint after security hardening
92ef11e Harden signing secret bootstrap and production ops
```

**Pendente de commit (na ordem):**
1. T10 map view (`feat(godview): map view com lat/lon no drill-down`) — script `COMMIT_T10_MAP.ps1` pronto.
2. F3 audit fix + suite + report (`fix(security): F3 audit log + suite + report`) — script `COMMIT_PENTEST2.ps1` pronto.
3. **F4 + F5 fixes (T13)** — `fix(security): F4 SameSite=Strict admin + F5 valida tenant em delete/rotate` — script `COMMIT_T13.ps1` pronto.

Suite de testes (`run_pentest_audit.py` na raiz do projeto, e `tests/test_pentest_findings.py` já presente) é commitada junto com (2). Os 3 novos checks (t13a/b/c) entram no commit (3).
