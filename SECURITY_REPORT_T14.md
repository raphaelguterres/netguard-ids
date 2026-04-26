# NetGuard IDS — Security Report (T14: Host Triage View + Operator Inbox)

**Data:** 2026-04-26
**Escopo:** Nova superfície adicionada em T14 — Host Triage View (HTV) + Operator Inbox + deep-link
**Auditor:** Claude (estático: AST + grep + leitura de fonte; runtime: 32 testes automatizados em `run_pentest_audit.py`)
**Postura geral:** ✅ Verde — 0 findings abertos · 32/32 checks passando (26 anteriores + 6 novos T14)

---

## TL;DR

| Surface adicionada                                                    | Auth | RBAC | CSRF        | Audit              | Rate-limit | Tenant gate                           | Status |
| --------------------------------------------------------------------- | :--: | :--: | :---------: | :----------------: | :--------: | :-----------------------------------: | :----: |
| `GET /api/admin/tenant/<tid>/host/<hid>` (HTV API)                    | ✅   | ✅   | n/a (GET)   | ✅ HOST_TRIAGE_VIEW| ✅ admin   | ✅ 404 se tenant ausente / host fora  | ✅     |
| `GET /api/admin/inbox?limit&tenant`                                   | ✅   | ✅   | n/a (GET)   | n/a (read-only)    | ✅ admin   | ✅ filter opcional, escopo admin       | ✅     |
| `GET /admin/host/<tid>/<hid>` (HTML page)                             | ✅   | ✅   | seta cookie | n/a                | ✅ admin   | path validado pela API                 | ✅     |
| `GET /admin/inbox` (HTML page)                                        | ✅   | ✅   | seta cookie | n/a                | ✅ admin   | n/a (filtro client-side)               | ✅     |
| Deep-link em `/admin` God View → `/admin/host/<tid>/<hid>`            | n/a  | n/a  | n/a         | n/a                | n/a        | usa `gvEsc + encodeURIComponent`       | ✅     |

✅ **0 findings abertos.** Toda nova superfície segue o padrão zero-trust dos rounds anteriores.

```bash
python3 /sessions/stoic-hopeful-brown/mnt/PROJETO\ SOC/run_pentest_audit.py
# Output: 32/32 passaram
```

---

## 1. Por que T14?

O operador antes precisava: (1) abrir God View → (2) abrir tenant drilldown → (3) ler tabela de hosts → (4) deduzir mentalmente qual host atacar primeiro → (5) decidir o que fazer. Cinco saltos cognitivos sem ranking determinístico. T14 corta para **um clique** com priorização auditável.

Decisões arquiteturais que afetam segurança:

- **Risk score determinístico (rule-based, não ML).** SOC precisa explicar *por que* um host está em "CRITICAL". Pesos visíveis no `breakdown` retornado pela API. Sem caixa-preta.
- **Cross-tenant inbox por design.** O endpoint `/api/admin/inbox` itera *todos* os tenants — só admin global tem acesso. Tenant sem permissão admin não toca este endpoint (gate em `@_admin_only`).
- **Deep-link como state.** A URL `/admin/host/<tid>/<hid>` carrega o estado da triagem — compartilhável internamente entre operadores, mas só renderiza após auth admin.

---

## 2. Threat model das novas rotas

### 2.1 IDOR (Insecure Direct Object Reference)

**Risco:** operador admin tenta ver host de tenant inexistente, ou host_id que não pertence ao tenant declarado, ou injeta path traversal no `tid`/`hid`.

**Mitigação implementada (verificada em `t14a`):**

```python
# admin_tenant_host_triage()
tenant_row = repo.get_tenant_by_id(tenant_id)
if not tenant_row:
    return jsonify({"error": "tenant not found"}), 404

host = host_repo.get_host(host_id, tenant_id=tenant_id)  # tenant gate
if not host:
    return jsonify({"error": "host not found"}), 404
```

`host_repository.get_host(host_id, tenant_id=tid)` faz `WHERE host_id = ? AND tenant_id = ?` — não há como pegar host de outro tenant mesmo conhecendo o `host_id`.

**Pattern hunt:** outras rotas que aceitam `<tid>/<hid>` no path? Apenas esta no T14. Padrão preservado.

### 2.2 Audit trail

Toda visualização de triage emite evento `HOST_TRIAGE_VIEW` no audit log (verificado em `t14a`). Isso permite responder a perguntas tipo "quem olhou esse host nas últimas 48h?" — útil para revisão pós-incidente e compliance.

```python
audit.log("HOST_TRIAGE_VIEW", {
    "tenant_id": tenant_id, "host_id": host_id,
    "actor": session.get("admin_email")
})
```

### 2.3 Information disclosure

A resposta da API inclui:

- `posture` (display_name, platform, last_ip, last_seen, status) — dados de inventário do host
- `geo` (country, city via GeoLite2 + prefix DB) — opt-in via `GEOIP_ENABLED`
- `risk` (score, band, breakdown) — campo derivado, sem PII
- `next_action` (label, rationale, urgency) — sem PII
- `timeline` (últimos 50 eventos) — capped, evita exfil em massa

**Risco residual mínimo.** O endpoint só responde para admin autenticado; `last_ip` já era exposto no drilldown anterior. Sem novo vetor de leak.

### 2.4 Rate-limit

Coberto pela regra `admin_paths` global (120 req / 60s por IP, já existente). Inbox endpoint é mais caro (itera tenants × hosts), então o limit existente é especialmente importante aqui.

**Recomendação futura (não bloqueante):** cache de 30s em memória para `/api/admin/inbox` — operador costuma recarregar várias vezes por minuto. Cada call hoje custa O(tenants × hosts) consultas.

### 2.5 XSS / injection nos templates

`host_triage.html` e `operator_inbox.html` usam helper `esc()` em todo dado externo (display_name, host_id, tenant_name, last_ip, next_action, rationale). O deep-link em `admin.html` usa `encodeURIComponent` no path + `gvEsc` no texto.

**Pattern hunt:** procurei por `innerHTML =` nos novos templates — todos os usos passam por `esc()` antes de concatenação.

### 2.6 CSRF

Os endpoints novos são todos **GET** (read-only) — CSRF não se aplica. As rotas HTML setam o cookie CSRF para que ações futuras nestes painéis (caso adicionemos botões de mitigação) já tenham o token disponível.

---

## 3. Risk score — algoritmo (auditável)

Implementação em `_host_risk_score(events_24h, host)`. Pesos:

| Sinal                             | Peso  | Cap  |
| --------------------------------- | ----- | ---- |
| Cada evento CRITICAL em 24h       | +20   | 60   |
| Cada evento HIGH em 24h           | +10   | 40   |
| Cada evento MEDIUM em 24h         | +3    | 15   |
| Cada evento LOW em 24h            | +1    | 5    |
| `last_seen` > 24h atrás (offline) | +20   | —    |
| `last_seen` 1–24h (idle)          | +10   | —    |

Bands derivadas do score: ≥80 critical, ≥60 high, ≥30 medium, >0 low, 0 none.

O endpoint retorna o `breakdown` completo — auditor consegue reconstituir o score sem ler o código:

```json
{
  "risk": {
    "score": 87,
    "band": "critical",
    "breakdown": [
      "3× CRITICAL = +60 (cap)",
      "5× HIGH = +50 capped to +40",
      "offline >24h = +20"
    ]
  }
}
```

---

## 4. Próxima ação — regras (5 níveis de prioridade)

Implementação em `_host_next_action(events_24h, host)`. Avaliadas em ordem; primeira que casa vence.

1. CRITICAL aberto → "Conter o host" (urgency=critical)
2. ≥3 HIGH em 24h → "Investigar lateral movement" (urgency=high)
3. Offline >24h sem checkin → "Verificar conectividade do agente" (urgency=medium)
4. ≥5 MEDIUM em 24h → "Tunar regras de detecção" (urgency=low)
5. Default → "Monitorar / nada urgente" (urgency=low)

Cada regra retorna `rationale` explicando *por que* essa ação foi escolhida — operador não precisa adivinhar.

---

## 5. Regressão T14 (6 novos checks)

| ID    | O que valida                                                                  |
| ----- | ----------------------------------------------------------------------------- |
| t14a  | `/api/admin/tenant/<tid>/host/<hid>` existe, valida tenant+host, audita       |
| t14b  | `_host_risk_score()` retorna `{score, band, breakdown}`                       |
| t14c  | `_host_next_action()` retorna `{action, rationale, urgency}`                  |
| t14d  | `/api/admin/inbox` existe + chama `_host_inbox_ranking()`                     |
| t14e  | Rotas HTML `/admin/host/<tid>/<hid>` e `/admin/inbox` + ambos templates       |
| t14f  | God View renderiza deep-link com `encodeURIComponent` para a triage           |

Resultado: **32/32 passando** (26 anteriores + 6 novos). Nenhum WARN.

---

## 6. Backlog (não bloqueante)

- **Cache de 30s para inbox.** Hoje cada call O(tenants × hosts). Para >100 tenants vira lento.
- **Eventos checkin/audit no timeline.** Hoje todos os 50 itens são marcados `alert` — a tag visual no template não diferencia. Trivial de adicionar.
- **IPs clicáveis em `top_ips`.** Hoje só host_name é deep-link. IPs no posture poderiam abrir uma view de "todos hosts deste IP".
- **Saved filters no inbox.** "Mostrar só CRITICAL", "Mostrar só meus tenants" — UI features, sem implicação de segurança.

Nenhum desses é finding — são melhorias de UX/perf.

---

## 7. Comparação com baseline

| Métrica                              | Pré-T14   | Pós-T14 |
| ------------------------------------ | --------- | ------- |
| Endpoints admin                      | 21        | 23      |
| Páginas HTML admin                   | 2         | 4       |
| Regression checks                    | 26        | 32      |
| Findings abertos                     | 0         | 0       |
| Tempo médio operador → ação          | ~5 cliques| 1 clique|

Postura de segurança não regrediu. Ergonomia melhorou substancialmente.
