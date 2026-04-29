# NetGuard IDS — Security Model

Documento de referência da postura de segurança do NetGuard IDS. Leia antes de
expor a instância em rede não-confiável ou subir pra produção.

---

## 1. Modos de autenticação

O servidor tem dois níveis de acesso mutuamente exclusivos:

| Nível       | Quem acessa                | Prefixo de rota         | Identificação                 |
|-------------|----------------------------|-------------------------|-------------------------------|
| **Admin**   | Operador do NetGuard       | `/admin`, `/api/admin/*`| Bearer token em `.netguard_token` |
| **Tenant**  | Cliente SaaS (isolado)     | `/api/tenant/*`         | Bearer token per-tenant            |

Um token tenant **não consegue** acessar endpoints admin (decorator
`@_admin_only`). Um token admin acessa ambos.

### Kill switch de autenticação

`IDS_AUTH=false` desativa **toda** a autenticação. Uso **somente em dev local**
(ambiente isolado, sem rede pública). O bootstrap bloqueia bind fora de
loopback quando `IDS_AUTH=false`, a menos que `IDS_ALLOW_INSECURE_DEV=true`
seja definido explicitamente. A UI exibe banner "DEV MODE" quando o modo está
ativo — se o banner aparecer em prod, algo está errado.

---

## 2. Rotação manual do token admin

O token admin não expira automaticamente. Rotacione quando:

- Suspeita de vazamento (screenshot, commit acidental, log compartilhado)
- Mudança de operador
- Intervalo regular (recomendado: 90 dias)

**Pelo painel:** Admin → Overview → "Rotacionar token admin" (botão perigo).
O token atual é invalidado **imediatamente** no backend. O novo aparece em
modal que limpa o conteúdo do DOM ao fechar — copie e cole no gerenciador de
senhas antes de fechar.

**Por shell:** delete `.netguard_token`, reinicie o servidor. Ele loga o novo
token no stdout (equivalente ao primeiro boot).

Todas as rotações aparecem no audit log (`ADMIN_TOKEN_ROTATED`).

---

## 3. Proteção CSRF (double-submit cookie)

### O problema

A sessão admin usa cookie. Sem CSRF, um site malicioso aberto no mesmo
browser pode disparar um POST pra `/api/admin/tenants/<id>/delete` — o
navegador anexa o cookie automaticamente e o servidor trata como ação
legítima do operador.

### A defesa

Pattern **double-submit cookie**:

1. Servidor gera token aleatório e coloca em cookie `csrf_token` (não
   HttpOnly — JS precisa ler pra enviar no header).
2. Client lê o cookie e envia em `X-CSRFToken` em toda request mutativa
   (POST/PUT/PATCH/DELETE).
3. Servidor compara cookie vs header com `secrets.compare_digest`. Falha → 403.

### Por que funciona

Um site cross-origin malicioso **não consegue ler** o cookie
(Same-Origin Policy). O navegador envia o cookie automaticamente mas sem
saber o valor não consegue preencher o header → comparação falha → 403.

### Defesa em profundidade

O cookie tem `SameSite=Strict` — o browser não envia em navegação cross-site
nem que o atacante quisesse. Os dois juntos cobrem browsers legados.

### Bypass intencional

Clientes que autenticam via header explícito (`Authorization: Bearer`,
`X-API-Token`) pulam o CSRF — esses fluxos não dependem de cookie de sessão,
logo não sofrem o ataque. Automação server-to-server continua funcionando.

### Desabilitar

`IDS_CSRF_DISABLED=true` — **apenas dev**. Em prod, perda imediata da proteção.

### Cobertura atual

10/10 endpoints admin mutativos têm `@csrf_protect`:
- `/api/admin/trials/*` (create, revoke, extend)
- `/api/admin/tenants/*` (create, delete, rotate)
- `/api/admin/rotate-admin-token`
- `/api/admin/totp/*` (setup, disable, verify)

---

## 4. TOTP 2FA (RFC 6238) — opt-in

### Por que

Se o token admin vaza, o atacante entra direto. TOTP exige um fator adicional
fora do servidor: o secret fica no celular do operador. Mesmo com o token em
mãos, sem o código de 6 dígitos o login falha.

### Ativação

Admin → Overview → painel "Segurança - 2FA (TOTP)" → "Gerar/regerar secret".
O modal mostra:
- **Secret base32** — pra apps que pedem entrada manual
- **otpauth:// URI** — pra QR code (cole em gerador ou configure no app
  do celular diretamente)
- **Campo de teste** — valide o código antes de fazer logout (evita
  trancar-se fora se o relógio do celular estiver fora de sync)

Apps compatíveis: Google Authenticator, 1Password, Authy, Microsoft
Authenticator (SHA1, 6 dígitos, 30s — default de todos).

### Ativation gate (dupla)

2FA só é exigido quando **ambos** são verdadeiros:

1. `.netguard_totp` existe com secret ≥16 chars
2. `IDS_ADMIN_TOTP != 'false'` (kill switch)

Remover qualquer um dos dois desativa.

### Janela de tolerância

`IDS_TOTP_WINDOW=1` (default). Aceita códigos do período anterior + atual +
posterior (3 janelas de 30s = 90s total). Tolera drift de relógio do celular.
Não aumente pra >2 em prod — cada incremento dobra a superfície de brute-force.

### Recuperação (perdeu o celular)

Duas opções, ambas exigem acesso ao host:

- Delete `.netguard_totp` — login volta a aceitar só o token
- Set `IDS_ADMIN_TOTP=false` — desativa sem apagar o secret

Sem acesso ao host, não há recuperação remota por design — isso é a essência
do 2FA. Mantenha **pelo menos um backup** (print do QR, secret no
gerenciador de senhas) num local seguro.

### Por que stdlib-only

Implementação usa `hmac`, `hashlib`, `struct`, `secrets` — todos stdlib.
Sem pyotp nem nenhuma lib externa. Cada dep a menos é uma CVE a menos pra
auditar. Vetores RFC 6238 Apêndice B verificados nos testes.

---

## 5. Rate limit em /api/admin/*

### Por que

Defesa em profundidade. Se um token vaza, limitar req/min/IP faz o ataque
ficar **observável** (`ADMIN_RATE_LIMITED` no audit log) antes de ser efetivo.
Também protege contra loops acidentais no frontend.

### Config (defaults generosos)

| Env                       | Default | Significado                    |
|---------------------------|---------|--------------------------------|
| `IDS_ADMIN_RL_LIMIT`      | 120     | Requests por janela por IP     |
| `IDS_ADMIN_RL_WINDOW`     | 60      | Janela em segundos             |

120/min = 2/s cobre uso humano + auto-refresh + drill-downs sem falso
positivo. Exceção: `/api/admin/stream` (SSE long-lived) não conta.

### Limitações conhecidas

- **Compartilhado por host, não por cluster** — o backend atual usa SQLite
  (`IDS_ADMIN_RL_DB`) e funciona bem para múltiplos workers no mesmo host.
  Em ambiente multi-node, migre para storage compartilhado externo.
- **Por IP** — atacante com pool de IPs contorna. Contra quem já tem o
  token, rate limit é retardador, não bloqueador. A defesa primária é
  a rotação + audit log.

---

## 6. Audit log

### O que é registrado

Arquivo: `netguard_audit.log` (JSON-lines).

Eventos principais:
- `LOGIN_OK` / `LOGIN_FAIL` / `LOGIN_BLOCKED` (bruteforce guard)
- `ADMIN_TOKEN_ROTATED`
- `ADMIN_TOTP_ENABLED` / `ADMIN_TOTP_DISABLED`
- `ADMIN_RATE_LIMITED`
- `TENANT_CREATED` / `TENANT_DELETED` / `TOKEN_ROTATED`
- `TRIAL_CREATED` / `TRIAL_REVOKED` / `TRIAL_EXTENDED`
- `IMPERSONATE_START` / `IMPERSONATE_FAIL`
- `INCIDENT_CREATED` / `INCIDENT_DEDUPLICATED`
- `INCIDENT_STATUS` / `INCIDENT_SEVERITY` / `INCIDENT_ASSIGN`

Schema por linha: `{ts, event_type: "audit", msg, actor, source_ip, detail}`.

### UI

Admin → aba **Audit** → filtros por action, busca textual, `since` (ISO
datetime). Retorna as 200 mais recentes por default (clamp em [1, 1000]).

### Retenção

Há rotação automática embutida. Em produção, complemente com coleta
centralizada/retention externa se precisar de retenção longa ou compliance.

---

## 7. Proteção anti-bruteforce no login

`BruteForceGuard` (auth.py): após N tentativas falhas num janela, bloqueia
o IP por um período progressivo. Cada `LOGIN_BLOCKED` aparece no audit
log. Desacoplado do rate limit geral — atua **antes** da verificação
de credencial.

---

## 8. Hardening checklist (prod)

Antes de expor a instância em rede:

- [ ] `IDS_AUTH=true` explicitamente em produção
- [ ] `IDS_CSRF_DISABLED` **não** setado ou `false`
- [ ] HTTPS via reverse proxy (nginx/Caddy/Cloudflare) — cookies exigem
      `Secure` em prod
- [ ] Rotacionar token admin após deploy (o primeiro boot loga em stdout)
- [ ] 2FA TOTP ativado no painel admin
- [ ] Retenção do audit log validada (`IDS_AUDIT_LOG_RETENTION`) e/ou coletor externo configurado
- [ ] Background jobs revisados: autostart só onde houver processo dedicado/controlado
- [ ] `.netguard_token` e `.netguard_totp` fora do backup público
      (já estão no `.gitignore`, confira o destino do backup)
- [ ] Banner "DEV MODE" **ausente** no painel admin

---

## 9. Reportar vulnerabilidade

Canal privado antes de abrir issue pública — detalhes no `README.md`.
Incluir: versão (`git rev-parse HEAD`), passos mínimos de reprodução,
impacto observado.

---

## 10. Atualizações recentes de hardening

### TOKEN_SIGNING_SECRET (fail-closed)

TOKEN_SIGNING_SECRET assina e verifica tokens persistidos no banco. O boot
agora falha fechado fora de dev/test se essa variável não estiver
configurada.

- Produção: TOKEN_SIGNING_SECRET é obrigatório e deve ser exclusivo.
- Dev/test: fallback só é aceito quando IDS_ENV/NETGUARD_ENV/FLASK_ENV
  indicam ambiente de desenvolvimento/teste, ou em execução de testes.
- Valores fracos/legados como netguard-insecure-dev-key-change-in-prod
  não são aceitos em produção.
- Gere com python -c "import secrets; print(secrets.token_hex(32))" e não
  reutilize SECRET_KEY.

### Rate limit admin

- Implementação atual: SQLite compartilhado por host (IDS_ADMIN_RL_DB)
- Compatível com múltiplos workers no mesmo host
- Limitação remanescente: multi-node ainda pede backend compartilhado externo

### Audit log

- Rotação automática embutida via TimedRotatingFileHandler
- Env vars: IDS_AUDIT_LOG_ROTATE_WHEN, IDS_AUDIT_LOG_ROTATE_INTERVAL,
  IDS_AUDIT_LOG_RETENTION
- /api/admin/audit e os stats de segurança leem o arquivo ativo e os rotacionados

### Background jobs

- Importar app.py não inicia mais monitoramento/schedulers por padrão
- O autostart fica restrito ao python app.py, salvo opt-in explícito
- Em WSGI/Gunicorn, mantenha os jobs desabilitados por padrão para evitar side effects
