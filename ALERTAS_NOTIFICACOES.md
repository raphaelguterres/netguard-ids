# 🔔 NetGuard IDS — Alertas & Notificações

Guia completo para configurar cada canal de alerta suportado.
Todos os canais são configurados via **Webhooks** — sem necessidade de reiniciar o servidor.

---

## Índice

- [Como funciona](#como-funciona)
- [Severidades e filtros](#severidades-e-filtros)
- [Canal: Telegram](#canal-telegram)
- [Canal: WhatsApp (Z-API)](#canal-whatsapp-z-api)
- [Canal: WhatsApp (Twilio)](#canal-whatsapp-twilio)
- [Canal: Slack](#canal-slack)
- [Canal: Discord](#canal-discord)
- [Canal: Microsoft Teams](#canal-microsoft-teams)
- [Canal: HTTP Genérico](#canal-http-genérico)
- [API de Webhooks](#api-de-webhooks)
- [Testando a integração](#testando-a-integração)
- [Solução de problemas](#solução-de-problemas)

---

## Como funciona

O NetGuard IDS dispara alertas em background (sem bloquear a detecção) para cada webhook cadastrado que atenda os critérios de severidade e tipo de evento.

```
Detecção de ameaça
       │
       ▼
  _qualifies()  ← verifica severidade mínima + tipos de evento
       │ sim
       ▼
 Thread background → _send_with_retry() → 3 tentativas (2s, 4s, 8s)
       │
       ▼
  Log de entrega (sucesso/falha) salvo em webhook_logs
```

---

## Severidades e filtros

Ao cadastrar um webhook você define:

| Campo | Descrição | Valores aceitos |
|-------|-----------|-----------------|
| `min_severity` | Severidade mínima para disparar | `critical`, `high`, `medium`, `low`, `info` |
| `event_types` | Lista de tipos de evento (vazio = todos) | `port_scan`, `brute_force`, `ransomware`, `lateral_movement`, etc. |

**Exemplo:** `min_severity=high` e `event_types=[]` → dispara para HIGH e CRITICAL de qualquer tipo.

---

## Canal: Telegram

### 1. Criar o Bot

1. Abra o Telegram e pesquise `@BotFather`
2. Envie `/newbot` e siga as instruções
3. Copie o **token** gerado (formato: `1234567890:ABCdef...`)

### 2. Obter o Chat ID

**Para grupos/canais:**
1. Adicione o bot ao grupo
2. Envie qualquer mensagem no grupo
3. Acesse no navegador:
   ```
   https://api.telegram.org/bot{SEU_TOKEN}/getUpdates
   ```
4. Procure `"chat":{"id":` — esse é o `chat_id` (grupos têm valor negativo, ex: `-1001234567890`)

**Para mensagem direta:**
1. Inicie uma conversa com seu bot
2. Acesse o mesmo URL acima e pegue o `id` dentro de `"chat"`

### 3. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alertas Telegram SOC",
    "type": "telegram",
    "url": "https://api.telegram.org/bot1234567890:ABCdef.../sendMessage",
    "secret": "-1001234567890",
    "min_severity": "high",
    "event_types": []
  }'
```

> **`url`** → substitua pelo token do seu bot
> **`secret`** → coloque o `chat_id` (com o `-` se for grupo)

### Exemplo de alerta recebido

```
🟠 [HIGH] Port Scan Detected

📡 IP Origem: `45.33.32.156`
🖥️ Host: `netguard-servidor`
🎯 Tipo: `port_scan_suspected`
🕐 Horário: `2026-04-05T21:30:00Z`

📝 Varredura de portas detectada a partir de IP externo suspeito
```

---

## Canal: WhatsApp (Z-API)

> Recomendado para uso no Brasil. Plano gratuito disponível em [z-api.io](https://z-api.io).

### 1. Criar conta na Z-API

1. Acesse [z-api.io](https://z-api.io) e crie uma conta
2. Crie uma instância e escaneie o QR Code com seu WhatsApp
3. Copie o **Instance ID** e o **Token** do painel

### 2. Descobrir o número de destino

O número destino vai no endpoint da URL. Formato: `5511999999999` (DDI + DDD + número, sem `+` ou espaços).

### 3. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "WhatsApp SOC",
    "type": "whatsapp",
    "url": "https://api.z-api.io/instances/SEU_INSTANCE_ID/token/SEU_TOKEN/send-text",
    "secret": "",
    "min_severity": "critical",
    "event_types": []
  }'
```

> **`url`** → substitua `SEU_INSTANCE_ID` e `SEU_TOKEN` pelos dados da Z-API
> **`secret`** → deixe vazio (o número de destino fica configurado na instância Z-API)

**Payload enviado:**
```json
{
  "message": "🔴 [CRITICAL] Ransomware Behavior Detected\nIP: 10.0.0.5 | Host: srv-01\n..."
}
```

---

## Canal: WhatsApp (Twilio)

> Opção para quem já usa Twilio. Requer conta com WhatsApp Business aprovado.

### 1. Configurar no Twilio

1. Acesse [console.twilio.com](https://console.twilio.com)
2. Ative o **WhatsApp Sandbox** (ou número aprovado)
3. Copie: **Account SID** e **Auth Token**
4. Note o número Twilio no formato `whatsapp:+14155238886`

### 2. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "WhatsApp Twilio",
    "type": "whatsapp",
    "url": "https://api.twilio.com/2010-04-01/Accounts/SEU_SID/Messages.json?To=whatsapp:+5511999999999&From=whatsapp:+14155238886",
    "secret": "twilio:SEU_ACCOUNT_SID:SEU_AUTH_TOKEN",
    "min_severity": "critical",
    "event_types": []
  }'
```

> **`url`** → inclua `To` (seu número) e `From` (número Twilio) como query params
> **`secret`** → formato exato: `twilio:SID:AUTH_TOKEN`

---

## Canal: Slack

### 1. Criar Incoming Webhook no Slack

1. Acesse [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
2. Vá em **Incoming Webhooks** → ative → **Add New Webhook to Workspace**
3. Selecione o canal e copie a URL gerada

### 2. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slack #security-alerts",
    "type": "slack",
    "url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "secret": "",
    "min_severity": "medium",
    "event_types": []
  }'
```

---

## Canal: Discord

### 1. Criar Webhook no Discord

1. No servidor Discord, clique no canal → **Editar Canal** → **Integrações** → **Webhooks**
2. Clique em **Novo Webhook**, defina nome e ícone
3. Copie a **URL do Webhook**

### 2. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Discord #alertas",
    "type": "discord",
    "url": "https://discord.com/api/webhooks/000000000000000000/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "secret": "",
    "min_severity": "high",
    "event_types": ["ransomware", "lateral_movement", "brute_force"]
  }'
```

---

## Canal: Microsoft Teams

### 1. Criar Incoming Webhook no Teams

1. No canal desejado, clique em `···` → **Conectores**
2. Pesquise **Incoming Webhook** → **Configurar**
3. Dê um nome, faça upload de ícone (opcional) e copie a URL

### 2. Cadastrar no NetGuard

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Teams Canal SOC",
    "type": "teams",
    "url": "https://outlook.office.com/webhook/XXXXXXXX/IncomingWebhook/YYYYYYYY/ZZZZZZZZ",
    "secret": "",
    "min_severity": "high",
    "event_types": []
  }'
```

---

## Canal: HTTP Genérico

Para integrar com qualquer sistema que aceite um POST JSON (JIRA, ServiceNow, PagerDuty, sistemas internos, etc.).

```bash
curl -X POST http://localhost:5000/api/webhooks \
  -H "X-API-Key: SUA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Meu Sistema Interno",
    "type": "generic",
    "url": "https://meu-sistema.com/api/security-alert",
    "secret": "minha-chave-secreta",
    "min_severity": "medium",
    "event_types": []
  }'
```

**Payload enviado:**
```json
{
  "source":     "netguard-ids",
  "severity":   "high",
  "threat":     "Port Scan Detected",
  "event_type": "port_scan_suspected",
  "source_ip":  "45.33.32.156",
  "hostname":   "netguard-host",
  "timestamp":  "2026-04-05T21:30:00Z",
  "details": {
    "description": "Varredura de portas detectada..."
  }
}
```

O `secret` é enviado no header `X-NetGuard-Secret` para autenticação no seu sistema.

---

## API de Webhooks

Todos os endpoints exigem autenticação via `X-API-Key` ou `?api_key=`.

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET`    | `/api/webhooks`              | Lista todos os webhooks |
| `POST`   | `/api/webhooks`              | Cria novo webhook |
| `PUT`    | `/api/webhooks/{id}`         | Atualiza webhook |
| `DELETE` | `/api/webhooks/{id}`         | Remove webhook |
| `POST`   | `/api/webhooks/{id}/toggle`  | Ativa/desativa |
| `POST`   | `/api/webhooks/{id}/test`    | Envia evento de teste |
| `GET`    | `/api/webhooks/{id}/logs`    | Histórico de envios |
| `GET`    | `/api/webhooks/types`        | Lista tipos suportados com exemplos |

### Listar tipos suportados

```bash
curl http://localhost:5000/api/webhooks/types \
  -H "X-API-Key: SUA_API_KEY"
```

Retorna URL de exemplo e dica de configuração para cada canal.

---

## Testando a integração

Depois de cadastrar, teste sem precisar de um ataque real:

```bash
# Substitua {id} pelo ID retornado no cadastro
curl -X POST http://localhost:5000/api/webhooks/1/test \
  -H "X-API-Key: SUA_API_KEY"
```

Resposta de sucesso:
```json
{
  "ok": true,
  "status_code": 200,
  "error": null
}
```

Verifique o log de entregas:
```bash
curl http://localhost:5000/api/webhooks/1/logs \
  -H "X-API-Key: SUA_API_KEY"
```

---

## Solução de problemas

| Problema | Causa provável | Solução |
|----------|---------------|---------|
| `ok: false, status_code: 401` | API Key inválida no serviço externo | Verifique token/secret no cadastro |
| `ok: false, status_code: 404` | URL errada | Confira a URL, especialmente o token do bot |
| `ok: false, error: timeout` | Serviço externo lento ou bloqueado | Verifique firewall de saída; Telegram exige acesso à internet |
| Telegram: `Bad Request: chat not found` | chat_id errado | Use `/getUpdates` para confirmar o chat_id |
| WhatsApp Z-API: `instance not connected` | QR Code expirou | Re-escaneie o QR Code no painel Z-API |
| Nenhum alerta chega | Severidade abaixo do `min_severity` | Baixe o `min_severity` ou gere um evento de teste |
| Alerta duplicado | Múltiplos webhooks do mesmo tipo | Verifique a lista `/api/webhooks` |

### Verificar logs em tempo real

```bash
# Acompanhe o log do servidor (JSON estruturado)
docker logs -f netguard-ids | python3 -m json.tool

# Ou filtre só erros de webhook
docker logs -f netguard-ids | grep '"logger":"netguard.webhook"'
```

---

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `IDS_AUDIT_LOG` | `netguard_audit.log` | Caminho do arquivo de audit log |
| `IDS_DB_PATH` | `ids_detections.db` | Banco de detecções (DetectionStore) |
| `IDS_API_KEY` | *(obrigatório)* | Chave de autenticação da API |

---

> **Dica:** Configure ao menos um webhook Telegram ou WhatsApp logo no setup inicial.
> É o canal mais rápido para receber alertas críticos — latência típica < 2 segundos.
