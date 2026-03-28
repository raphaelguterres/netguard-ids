# 📑 Índice do Projeto IDS

## 📂 Estrutura de Arquivos

```
projeto-ids/
├── 📄 README.md                    # Visão geral e Quick Start
├── 📄 MANUAL_TECNICO.md           # Documentação técnica aprofundada
├── 📄 GUIA_INSTALACAO.md          # Guia prático de instalação
├── 📄 ANALISE_ATAQUES.md          # 7 Casos de ataque analisados
├── 📄 INDEX.md                    # Este arquivo
│
├── 🐍 CÓDIGO PYTHON
├── ids_engine.py                  # Motor de detecção (IDS Engine)
├── app.py                         # Servidor Flask + Dashboard
├── test_ids.py                    # Script de demonstração
│
├── 📋 CONFIGURAÇÃO
├── requirements.txt               # Dependências Python
│
└── 📊 DADOS (gerados em tempo real)
    ├── detections.json            # Histórico de detecções (salvo)
    └── detections.csv             # Detecções em CSV (exportado)
```

---

## 📚 Documentação

### 1. **README.md** ⭐ COMECE AQUI
- Visão geral do projeto
- Arquitetura SOC
- Tipos de ataques detectados
- Quick Start (5 minutos)
- Endpoints da API

**Para quem**: Pessoas que querem entender rapidamente o que é o IDS

---

### 2. **GUIA_INSTALACAO.md** 🚀 INSTALAÇÃO
- Requisitos de sistema
- Passo-a-passo instalação (5 min)
- Como usar o Dashboard
- Testando o IDS
- Troubleshooting

**Para quem**: Pessoas que querem rodar o projeto

---

### 3. **MANUAL_TECNICO.md** 🔧 INTERNALS
- Arquitetura de 4 camadas
- Detalhes de cada componente (IDSEngine, LogProcessor, etc.)
- Algoritmos de detecção
- Detalhes da API REST
- Performance e tuning
- Integração com SIEM

**Para quem**: Pessoas que querem entender como funciona internamente

---

### 4. **ANALISE_ATAQUES.md** 🎓 CASOS PRÁTICOS
- 7 casos completos de ataque:
  1. SQL Injection
  2. XSS (Cross-Site Scripting)
  3. Brute Force SSH
  4. Command Injection
  5. Privilege Escalation
  6. DDoS Attack
  7. Reverse Shell

Cada caso inclui:
- O que é
- Como funciona
- Impacto potencial
- Exemplo real
- Detecção pelo IDS
- Contexto em SOC
- Defesas/Mitigação

**Para quem**: Estudantes, pesquisadores, profissionais de segurança

---

## 🐍 Código Python

### **ids_engine.py** - Motor de Detecção
Componentes principais:

```python
class ThreatSignature:
    # Define uma assinatura de ameaça
    name: str
    pattern: str  # Regex
    severity: str
    description: str

class IDSEngine:
    # Engine principal
    analyze_log(log_entry, source_ip)      # Detecta ameaças
    detect_anomalies(logs, baseline)       # Detecta anomalias
    get_statistics()                        # Retorna stats
    export_detections(format)              # Exporta dados

class LogProcessor:
    # Parse de diferentes formatos
    parse_syslog()        # RFC 3164
    parse_apache_access() # Apache logs
    parse_firewall_log()  # iptables format
```

**10 Assinaturas Implementadas:**
1. SQL Injection
2. XSS Attack
3. Brute Force SSH
4. Path Traversal
5. Command Injection
6. Port Scanning
7. DDoS Pattern
8. Privilege Escalation
9. Reverse Shell
10. Suspicious Binary

---

### **app.py** - Servidor Flask + Dashboard
Componentes:

```python
# API REST Endpoints
GET  /api/detections            # Lista detecções
POST /api/detections/<id>/update  # Atualiza status
POST /api/analyze               # Analisa log manual
GET  /api/statistics            # Retorna stats
POST /api/simulator/start       # Inicia simulador
POST /api/simulator/stop        # Para simulador
GET  /api/export                # Exporta dados

# Frontend
GET  /                          # Dashboard HTML
     - Stats cards (KPIs)
     - Detections list
     - Manual analyzer
     - Statistics panel
```

**Tecnologias:**
- Flask 2.3.3
- Flask-CORS (Cross-Origin)
- HTML5 + CSS3 + Vanilla JS
- WebSockets (via polling)

---

### **test_ids.py** - Script de Demonstração
Testa o IDS sem servidor web:

```bash
python test_ids.py

Testes inclusos:
✓ SQL Injection (3 exemplos)
✓ XSS (3 exemplos)
✓ Brute Force SSH (4 exemplos)
✓ Command Injection (3 exemplos)
✓ Privilege Escalation (3 exemplos)
✓ Anomaly Detection (simulado)
✓ Estatísticas
✓ Teste interativo (input do usuário)
```

---

## 🚀 Como Usar Este Projeto

### Cenário 1: Entender Conceitos
```
1. Ler: README.md
2. Ler: ANALISE_ATAQUES.md (escolha um caso)
3. Ler: MANUAL_TECNICO.md (aprofunde)
```

### Cenário 2: Rodar Demonstração Rápida
```
1. python -m venv venv
2. source venv/bin/activate (ou venv\Scripts\activate)
3. pip install -r requirements.txt
4. python test_ids.py
```

### Cenário 3: Dashboard Web Completo
```
1. python -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt
4. python app.py
5. Abrir: http://localhost:5000
6. Iniciar simulador
7. Ver detecções em tempo real
```

### Cenário 4: Análise Acadêmica
```
1. Preparar apresentação sobre arquitetura SOC
2. Mostrar diagrama do README
3. Executar test_ids.py (demonstração)
4. Rodar app.py para dashboard ao vivo
5. Apresentar código fonte (ids_engine.py)
6. Distribuir documentação (MANUAL_TECNICO.md)
```

---

## 🎯 Objetivos Educacionais

Este projeto demonstra:

### ✅ Conceitos de SOC
- Arquitetura de operações de segurança
- Detecção vs. Prevenção
- Resposta a incidentes

### ✅ Técnicas de Detecção
- Signature-based detection
- Anomaly-based detection
- Estatística e baseline

### ✅ Tipos de Ataques
- Injection attacks (SQL, Command)
- XSS (Cross-Site Scripting)
- Brute Force
- DDoS
- Privilege Escalation

### ✅ Tecnologias
- Python (idioma de scripting de segurança)
- Regex (pattern matching)
- REST API (integração)
- Frontend web (UX)
- Logs e SIEM

---

## 📊 Tamanho do Projeto

| Componente | Linhas | Tamanho |
|-----------|--------|--------|
| ids_engine.py | 350 | ~12 KB |
| app.py | 480 | ~18 KB |
| test_ids.py | 300 | ~11 KB |
| README.md | 350 | ~15 KB |
| MANUAL_TECNICO.md | 600 | ~28 KB |
| GUIA_INSTALACAO.md | 400 | ~18 KB |
| ANALISE_ATAQUES.md | 800 | ~35 KB |
| **TOTAL** | **3.280** | **~137 KB** |

---

## 🔗 Fluxo de Aprendizado Recomendado

```
INICIANTE:
├─ README.md (visão geral)
├─ GUIA_INSTALACAO.md (instalar)
├─ Rodar test_ids.py
└─ Explorar Dashboard

INTERMEDIÁRIO:
├─ ANALISE_ATAQUES.md (estudar casos)
├─ Modificar assinaturas em ids_engine.py
├─ Criar testes personalizados
└─ Analisar código fonte

AVANÇADO:
├─ MANUAL_TECNICO.md (deep dive)
├─ Estender com BD (PostgreSQL)
├─ Integrar com SIEM
├─ Machine Learning
└─ Deploy em produção
```

---

## 📋 Checklist Pré-Apresentação

- [ ] Ambiente Python 3.8+ instalado
- [ ] Projeto clonado/extraído
- [ ] requirements.txt instalado
- [ ] test_ids.py executado com sucesso
- [ ] app.py rodando sem erros
- [ ] Dashboard acessível em localhost:5000
- [ ] Simulador funcionando (eventos aparecem)
- [ ] Documentação revisada
- [ ] Código-fonte compreendido
- [ ] Exemplos de ataque testados

---

## 🎓 Sugestões de Apresentação

### Estrutura (30-45 min)

1. **Introdução (5 min)**
   - O que é SOC?
   - Por que IDS é importante?

2. **Arquitetura (10 min)**
   - Mostrar diagrama
   - Explicar 4 camadas
   - Fluxo de detecção

3. **Demonstração (15 min)**
   - Executar test_ids.py
   - Mostrar detecções
   - Rodar Dashboard
   - Analisar logs manualmente

4. **Análise de Caso (10 min)**
   - Escolher um ataque (ex: SQL Injection)
   - Mostrar exemplo real
   - Explicar defesa

5. **Código (5 min)**
   - Mostrar ids_engine.py
   - Explicar assinatura de regex
   - Mostrar API

6. **Q&A (5 min)**
   - Perguntas da plateia

---

## 📞 Referências Rápidas

**Definições:**
- IDS = Intrusion Detection System
- SOC = Security Operations Center
- SIEM = Security Information & Event Management
- CVSS = Common Vulnerability Scoring System
- MTTD = Mean Time To Detect
- MTTR = Mean Time To Respond

**Padrões Detectados:**
- Assinaturas: 10 implementadas
- Formatos de log: 3 (Syslog, Apache, Firewall)
- Endpoints API: 8
- Taxa de falso positivo: 2-15% (configurável)

---

## 🚀 Próximos Passos Sugeridos

Para transformar este IDS acadêmico em produção:

1. **Banco de Dados**: PostgreSQL para persistência
2. **Machine Learning**: Detecção comportamental avançada
3. **Clustering**: Múltiplas instâncias de IDS
4. **Autenticação**: JWT / OAuth2
5. **HTTPS/TLS**: Criptografar comunicação
6. **Webhooks**: Integração com Slack/Teams
7. **Rate Limiting**: Proteção contra DoS
8. **Forensics**: Armazenamento de evidências

---

## 📝 Notas Finais

Este projeto foi desenvolvido com foco em:
- ✅ **Educação**: Conceitos claros e bem explicados
- ✅ **Simplicidade**: Código limpo e fácil de entender
- ✅ **Prática**: Exemplos reais de ataques
- ✅ **Extensibilidade**: Fácil adicionar novas assinaturas
- ✅ **Documentação**: Completa e estruturada

**Bom aprendizado!** 🎓

---

**Versão**: 1.0.0  
**Status**: ✅ Pronto para Apresentação  
**Última Atualização**: Janeiro 2024
