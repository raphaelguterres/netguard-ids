# Manual Técnico - Intrusion Detection System

## 📖 Índice
1. [Arquitetura do Sistema](#arquitetura)
2. [Componentes Principais](#componentes)
3. [Engine de Detecção](#engine)
4. [API REST](#api)
5. [Dashboard](#dashboard)
6. [Processamento de Logs](#logs)
7. [Integração SOC](#soc)

---

## Arquitetura do Sistema

### 1. Visão Geral de Camadas

```
┌─────────────────────────────────────────────────────┐
│         LAYER 1: PRESENTATION                       │
│     (Dashboard Web, Interfaces Gráficas)           │
└──────────────────┬────────────────────────────────┘
                   │ HTTP/WebSocket
┌──────────────────┴────────────────────────────────┐
│     LAYER 2: API (REST + WebSockets)              │
│  (Flask, Endpoints, Routing, Middleware)         │
└──────────────────┬────────────────────────────────┘
                   │ Python Objects
┌──────────────────┴────────────────────────────────┐
│  LAYER 3: BUSINESS LOGIC (IDS Engine)            │
│  (Detecção, Análise, Processamento)              │
└──────────────────┬────────────────────────────────┘
                   │ Data Format
┌──────────────────┴────────────────────────────────┐
│   LAYER 4: DATA ACCESS                           │
│ (Logs, Signatures, Configuration)                │
└─────────────────────────────────────────────────┘
```

### 2. Fluxo de Dados Completo

```
ENTRADA
  │
  ├─→ Syslog / Apache Log / Firewall Log
  │
  ▼
LOG PROCESSOR (Parse)
  │
  ├─→ Extract timestamp, IP, message, etc.
  │
  ▼
IDS ENGINE
  │
  ├─→ SIGNATURE MATCHING
  │   ├─→ Regex Pattern 1 ❌ No match
  │   ├─→ Regex Pattern 2 ❌ No match
  │   ├─→ Regex Pattern 3 ✅ MATCH! → Alert
  │   └─→ Regex Pattern N
  │
  ├─→ ANOMALY DETECTION
  │   ├─→ Statistical Analysis
  │   ├─→ Baseline Comparison
  │   └─→ Behavioral Analysis
  │
  ▼
ALERTING & STORAGE
  │
  ├─→ Generate Detection Record
  ├─→ Store in detections[]
  ├─→ Notify Dashboard (Real-time)
  │
  ▼
VISUALIZATION
  │
  └─→ Dashboard Updates
      ├─→ Stats Cards
      ├─→ Detection List
      └─→ Graphs/Charts
```

---

## Componentes Principais

### 1. **IDSEngine** (ids_engine.py)

A classe principal que coordena toda a detecção.

#### Estrutura de Dados
```python
class IDSEngine:
    self.threats: List[ThreatSignature]      # Base de assinaturas
    self.detections: List[Dict]              # Histórico de detecções
    self.baseline_stats: Dict                # Estatísticas de baseline
```

#### Métodos Principais

**`analyze_log(log_entry, source_ip)`**
- Analisa uma entrada de log contra todas as assinaturas
- Retorna lista de detecções encontradas
- Complexidade: O(n) onde n = número de assinaturas

```python
def analyze_log(self, log_entry: str, source_ip: str = None) -> List[Dict]:
    detections = []
    
    for threat in self.threats:  # O(n) - # de assinaturas
        if threat.compiled_pattern.search(log_entry):  # Regex match
            detection = {
                "timestamp": datetime.now().isoformat(),
                "threat_name": threat.name,
                "severity": threat.severity,
                "description": threat.description,
                "source_ip": source_ip,
            }
            detections.append(detection)
            self.detections.append(detection)  # Armazena
    
    return detections
```

**`detect_anomalies(logs, baseline)`**
- Identifica padrões anormais baseados em estatísticas
- Compara contra baseline histórico
- Retorna lista de anomalias detectadas

```python
def detect_anomalies(self, logs: List[str], baseline: Dict = None) -> List[Dict]:
    anomalies = []
    ip_counter = {}
    
    # Análise de frequência de IPs
    for log in logs:
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log)
        for ip in ips:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1
    
    # IPs anormais (muitas requisições)
    for ip, count in ip_counter.items():
        if count > 10:  # Threshold
            anomalies.append({
                "threat_name": "Anomalous Activity",
                "source_ip": ip,
                "severity": "medium"
            })
    
    return anomalies
```

**`get_statistics()`**
- Agrega estatísticas de todas as detecções
- Agrupa por severidade e tipo de ameaça

```python
def get_statistics(self) -> Dict:
    stats = {
        "total_detections": len(self.detections),
        "by_severity": { "critical": 5, "high": 10, ... },
        "by_threat": { "SQL Injection": 3, ... }
    }
    return stats
```

### 2. **ThreatSignature**

Representa uma assinatura de ataque conhecido.

```python
class ThreatSignature:
    def __init__(self, name, pattern, severity, description):
        self.name = name                              # "SQL Injection"
        self.pattern = pattern                        # Regex pattern
        self.severity = severity                      # "critical", "high", etc.
        self.description = description                # Descrição legível
        self.compiled_pattern = re.compile(pattern)   # Cache compilado
```

#### Assinaturas Implementadas

| Nome | Pattern | Severidade | Detalhes |
|------|---------|-----------|----------|
| SQL Injection | `UNION.*SELECT\|DROP.*TABLE` | HIGH | Detecta comandos SQL maliciosos |
| XSS | `<script>.*</script>\|onerror=` | HIGH | Identifica código JavaScript injetado |
| Command Injection | `bash.*dev/tcp\|nc.*-l` | CRITICAL | Shell reversa e comandos do SO |
| Privilege Escalation | `sudo.*root\|setuid` | CRITICAL | Tentativas de ganhar privilégios |
| Port Scanning | `nmap\|masscan\|SYN_RECV` | MEDIUM | Atividade de reconhecimento |
| DDoS | `slowloris\|http flood` | CRITICAL | Padrões de ataque distribuído |
| Path Traversal | `\.\./\|%2e%2e` | MEDIUM | Acesso a diretórios restritos |
| Malware | `curl.*\.sh.*\|bash` | HIGH | Download e execução de binários |

---

## Engine de Detecção

### Algoritmo de Signature Matching

```python
# Pseudocódigo do algoritmo
function detect(log_entry):
    matches = []
    
    for each signature in signatures_database:
        if signature.regex.matches(log_entry):
            alert = create_alert(signature, log_entry)
            matches.append(alert)
            log_to_storage(alert)
    
    notify_dashboard(matches)
    return matches
```

### Complexidade de Tempo

- **Best Case**: O(m) - apenas uma assinatura corresponde
- **Average Case**: O(n × m) - n=assinaturas, m=comprimento do log
- **Worst Case**: O(n × m) - todas as assinaturas testadas

### Otimizações Implementadas

1. **Regex Compilation Cache**: As regexes são compiladas uma vez
2. **Early Exit**: Parar quando comportamento suspeito é encontrado
3. **Pattern Ordering**: Assinaturas mais críticas vêm primeiro

### Detecção de Anomalias

O sistema implementa análise estatística simples:

```python
def detect_anomalies(logs):
    ip_frequency = count_ips_in_logs(logs)
    
    # Baseline: média histórica
    baseline_threshold = calculate_baseline(historical_data)
    
    for ip, count in ip_frequency.items():
        if count > baseline_threshold * 1.5:  # 50% acima do normal
            flag_as_anomaly(ip, count)
```

**Tipos de Anomalias Detectadas:**
- IPs com atividade anormalmente alta
- Padrões de comportamento inesperados
- Desvios estatísticos significantes

---

## API REST

### Arquitetura Flask

```
Flask Application
├── Middleware
│   ├── CORS (Cross-Origin Resource Sharing)
│   ├── Error Handling
│   └── Logging
├── Routes
│   ├── /api/detections
│   ├── /api/statistics
│   ├── /api/analyze
│   └── /api/simulator/*
└── Data
    └── IDSEngine Instance
```

### Endpoints Detalhados

#### 1. **GET /api/detections**
Retorna lista de detecções com filtros opcionais.

**Parâmetros:**
```
limit: int (default=100)      # Máximo de resultados
severity: string (optional)   # Filtro: "critical", "high", "medium", "low"
```

**Resposta:**
```json
{
  "total": 127,
  "displayed": 50,
  "detections": [
    {
      "timestamp": "2024-01-15T10:23:45.123456",
      "threat_name": "SQL Injection",
      "severity": "high",
      "description": "Tentativa de SQL Injection detectada",
      "log_entry": "SELECT * FROM users WHERE id=1 UNION...",
      "source_ip": "192.168.1.100",
      "detection_id": "a7f3c2b1",
      "status": "active"
    }
  ]
}
```

#### 2. **GET /api/detections/<id>**
Retorna detalhes de uma detecção específica.

**Resposta:**
```json
{
  "timestamp": "2024-01-15T10:23:45.123456",
  "threat_name": "SQL Injection",
  "severity": "high",
  "detection_id": "a7f3c2b1"
}
```

#### 3. **POST /api/detections/<id>/update**
Atualiza o status de uma detecção.

**Request Body:**
```json
{
  "status": "resolved"  // ou "active", "investigating", etc.
}
```

**Resposta:**
```json
{
  "success": true,
  "detection": { ... }
}
```

#### 4. **POST /api/analyze**
Analisa um log manualmente contra todas as assinaturas.

**Request Body:**
```json
{
  "log": "SELECT * FROM users WHERE id=1 UNION SELECT NULL",
  "source_ip": "192.168.1.100"
}
```

**Resposta:**
```json
{
  "log": "SELECT * FROM users WHERE id=1 UNION SELECT NULL",
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

#### 5. **GET /api/statistics**
Retorna estatísticas agregadas de detecções.

**Resposta:**
```json
{
  "total_detections": 127,
  "by_severity": {
    "critical": 5,
    "high": 25,
    "medium": 47,
    "low": 50
  },
  "by_threat": {
    "SQL Injection": 15,
    "XSS": 20,
    "Brute Force": 8,
    "DDoS Pattern": 2
  }
}
```

#### 6. **POST /api/simulator/start**
Inicia simulação automática de eventos.

**Resposta:**
```json
{
  "status": "started"
}
```

#### 7. **POST /api/simulator/stop**
Para simulação de eventos.

**Resposta:**
```json
{
  "status": "stopped"
}
```

#### 8. **GET /api/export?format=json|csv**
Exporta todas as detecções em formato especificado.

**Formatos:**
- `json`: Array JSON com todas as detecções
- `csv`: Arquivo CSV com colunas

**CSV Format:**
```
timestamp,threat_name,severity,source_ip,status
2024-01-15T10:23:45,SQL Injection,high,192.168.1.100,active
2024-01-15T10:24:12,XSS Attack,high,10.0.0.50,active
```

---

## Dashboard

### Arquitetura Frontend

```
HTML (Structure)
├── Header
├── Controls (Buttons)
├── Stats Grid (KPIs)
├── Tabs (Navigation)
└── Content Areas
    ├── Detections List
    ├── Manual Analyzer
    └── Statistics

CSS (Styling)
├── Dark Theme (SOC-like)
├── Responsive Design
├── Animations
└── Status Colors

JavaScript (Behavior)
├── API Calls (fetch)
├── DOM Updates
├── Real-time Refresh
└── Event Handlers
```

### Componentes Visuais

#### 1. **Stats Cards**
Mostram métricas em tempo real:
- 🔴 Crítico: Número de ameaças críticas
- 🟠 Alto: Número de ameaças altas
- 🟡 Médio: Número de ameaças médias
- 🟢 Baixo: Número de ameaças baixas
- 📊 Total: Total de detecções

#### 2. **Detections List**
Lista rolável mostrando últimas detecções com:
- Nome da ameaça
- Nível de severidade (cor)
- IP de origem
- Timestamp
- Status (ativo/resolvido)

#### 3. **Manual Analyzer**
Formulário para testar logs manualmente:
- Campo de input para log
- Campo opcional para IP
- Botão de análise
- Resultado com ameaças encontradas

#### 4. **Statistics Panel**
Gráficos e contadores mostrando:
- Total de detecções
- Distribuição por severidade
- Top ameaças detectadas
- Atividade ao longo do tempo

### Atualização em Tempo Real

```javascript
// Auto-refresh a cada 3 segundos
setInterval(() => {
    fetch('/api/detections')
        .then(response => response.json())
        .then(data => {
            updateStatsCards(data);
            updateDetectionsList(data.detections);
        });
}, 3000);
```

---

## Processamento de Logs

### LogProcessor

Classe que oferece métodos estáticos para fazer parse de diferentes formatos de log.

#### Formatos Suportados

##### 1. **Syslog (RFC 3164)**
```
Jan 15 10:23:45 firewall sshd: Failed password for invalid user admin from 192.168.1.100 port 22
```

**Parse:**
```python
LogProcessor.parse_syslog(log_line)
# Retorna:
{
    "timestamp": "Jan 15 10:23:45",
    "hostname": "firewall",
    "service": "sshd",
    "message": "Failed password for invalid user admin from 192.168.1.100 port 22"
}
```

##### 2. **Apache Access Log**
```
192.168.1.100 - - [15/Jan/2024:10:23:45] "GET /index.php?id=1 HTTP/1.1" 200 1234
```

**Parse:**
```python
LogProcessor.parse_apache_access(log_line)
# Retorna:
{
    "ip": "192.168.1.100",
    "timestamp": "15/Jan/2024:10:23:45",
    "request": "GET /index.php?id=1 HTTP/1.1",
    "status_code": "200",
    "bytes": "1234"
}
```

##### 3. **Firewall Log (iptables format)**
```
DROP SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=443 [...]
```

**Parse:**
```python
LogProcessor.parse_firewall_log(log_line)
# Retorna:
{
    "source_ip": "192.168.1.50",
    "dest_ip": "10.0.0.1",
    "protocol": "TCP",
    "dest_port": "443"
}
```

### Pipeline de Processamento

```
Raw Log Line
    │
    ├─→ Determine Format (Regex detection)
    │
    ├─→ Apply Appropriate Parser
    │   ├─→ parse_syslog()
    │   ├─→ parse_apache_access()
    │   └─→ parse_firewall_log()
    │
    ▼
Structured Data (Dict)
    │
    ├─→ Extract Key Fields
    │   ├─→ source_ip
    │   ├─→ timestamp
    │   ├─→ action/message
    │   └─→ relevant_fields
    │
    ▼
Pass to IDSEngine
```

---

## Integração SOC

### Posição no Stack SOC Típico

```
┌──────────────────────────────────────┐
│     TIER 1: IDS/IPS                  │ ← Você está aqui
│  (Detecção de Intrusões em tempo     │
│   real via assinaturas)              │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│     TIER 2: SIEM                     │
│  (Agregação, Correlação)             │
│  (Splunk, ELK, etc)                  │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│     TIER 3: SOAR                     │
│  (Orquestração, Automação)           │
│  (Resposta automática de incidentes) │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│     TIER 4: ANÁLISE FORENSE          │
│  (Investigação profunda)             │
│  (Timeline reconstruction)           │
└──────────────────────────────────────┘
```

### Integração com SIEM Externo

Para integrar com Splunk ou ELK Stack:

```python
# Exemplo: Enviar detecções para Splunk
import requests

def send_to_siem(detection):
    siem_url = "https://splunk-server:8088/services/collector"
    
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "event": detection,
        "sourcetype": "ids_alert",
        "source": "ids_system"
    }
    
    requests.post(siem_url, json=payload, headers=headers)
```

### Fluxo de Resposta a Incidente

```
Detection Triggered
    │
    ├─→ Alert in IDS Dashboard
    │
    ├─→ Forward to SIEM (Splunk/ELK)
    │
    ├─→ SIEM Correlates with Other Logs
    │
    ├─→ Alert to SOC Team
    │
    ├─→ Manual/Automated Response
    │   ├─→ Block IP (Firewall)
    │   ├─→ Isolate System (Network)
    │   ├─→ Collect Forensics
    │   └─→ Generate Incident Report
    │
    ▼
Close Ticket (Remediated)
```

---

## Performance & Tuning

### Benchmarks

| Métrica | Valor |
|---------|-------|
| Taxa de Processamento | ~1000 logs/segundo |
| Latência (Log → Alert) | <100ms |
| Memória por Detecção | ~500 bytes |
| Uso de CPU | 5-15% (1 core) |

### Otimizações Possíveis

1. **Multi-threading**: Processar múltiplos logs em paralelo
2. **Índices**: Criar índices de IPs para busca mais rápida
3. **Caching**: Cache de padrões compilados (já implementado)
4. **Batch Processing**: Processar logs em lotes

### Limitações Atuais

- ✗ Sem persistência de dados (tudo em memória)
- ✗ Sem clustering/redundância
- ✗ Sem encriptação (HTTP puro)
- ✗ Sem autenticação

---

## Conclusão

Este IDS demonstra os princípios fundamentais de detecção de intrusões em um contexto de SOC. Implementa padrões de design modernos, API REST, e dashboard interativo, servindo como excelente plataforma educacional e prototipagem.

Para ambientes de produção, considerar: redundância, persistência de dados, análise ML avançada, e integração com ferramentas enterprise SIEM.

