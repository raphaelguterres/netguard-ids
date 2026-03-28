# ─────────────────────────────────────────────────────────────────
#  NetGuard IDS v3.0 — Dockerfile
#  Base: Python 3.11 slim (menor imagem possível)
# ─────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Metadados
LABEL maintainer="raphaelguterres"
LABEL description="NetGuard IDS — Real-time SOC/SIEM platform"
LABEL version="3.0"

# Evita prompts interativos durante apt
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Instala dependências do sistema
# libpcap-dev → Scapy packet capture
# libpcap0.8 → runtime
# net-tools  → ifconfig/netstat
# iproute2   → ip command
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libpcap0.8 \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Diretório de trabalho
WORKDIR /app

# Copia requirements primeiro (cache layer)
COPY requirements.txt requirements.docker.txt ./

# Instala dependências Python (versão Docker — sem pywebview/pyinstaller)
RUN pip install --no-cache-dir -r requirements.docker.txt

# Copia todo o projeto
COPY . .

# Cria diretório para o banco de dados persistente
RUN mkdir -p /data

# Variáveis de ambiente configuráveis
ENV IDS_PORT=5000
ENV IDS_HOST=0.0.0.0
ENV IDS_DB_PATH=/data/netguard_soc.db
ENV IDS_LOG_LEVEL=INFO
ENV IDS_ABUSEIPDB_KEY=""

# Expõe a porta do dashboard
EXPOSE 5000

# Volume para persistência do banco SQLite
VOLUME ["/data"]

# Health check — verifica se o servidor está respondendo
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" \
    || exit 1

# Ponto de entrada
CMD ["python", "app.py"]
