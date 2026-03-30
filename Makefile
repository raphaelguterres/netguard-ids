# ══════════════════════════════════════════════════════════════════
#  NetGuard IDS — Makefile
#  Uso: make <target>
# ══════════════════════════════════════════════════════════════════

PYTHON   ?= python
PIP      ?= pip
PORT     ?= 5000
DC       := docker compose
APP      := app.py

# Detecta OS para ajustar comandos
ifeq ($(OS),Windows_NT)
  OPEN    := start
  VENV    := venv\Scripts\activate
  SEP     := &&
else
  OPEN    := xdg-open 2>/dev/null || open
  VENV    := . venv/bin/activate
  SEP     := &&
endif

.DEFAULT_GOAL := help

# ── Ajuda ─────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  NetGuard IDS — Comandos disponíveis"
	@echo "  ════════════════════════════════════"
	@echo ""
	@echo "  Desenvolvimento"
	@echo "    make dev          Sobe servidor em modo dev (reload automático)"
	@echo "    make dev-auth     Sobe com autenticação ativada"
	@echo "    make open         Abre o dashboard no navegador"
	@echo ""
	@echo "  Produção (VPS / servidor)"
	@echo "    make prod         Sobe servidor em modo produção (sem debug)"
	@echo "    make prod-auth    Sobe produção + autenticação"
	@echo "    make prod-saas    Sobe produção + Stripe billing ativo"
	@echo ""
	@echo "  Docker"
	@echo "    make docker       Build + sobe container NetGuard (SQLite)"
	@echo "    make docker-saas  Sobe stack completa: NetGuard + PG + Prometheus + Grafana"
	@echo "    make docker-down  Para todos os containers"
	@echo "    make docker-logs  Mostra logs do container netguard"
	@echo "    make docker-build Apenas build da imagem"
	@echo ""
	@echo "  Instalação"
	@echo "    make install      Instala dependências Python"
	@echo "    make install-all  Instala dependências + extras (stripe, psycopg2)"
	@echo "    make venv         Cria ambiente virtual"
	@echo ""
	@echo "  Manutenção"
	@echo "    make health       Checa saúde da aplicação em execução"
	@echo "    make logs         Monitora o arquivo de log"
	@echo "    make clean        Remove arquivos temporários e cache"
	@echo "    make test         Roda testes"
	@echo ""

# ── Desenvolvimento ───────────────────────────────────────────────
.PHONY: dev
dev:
	@echo "▶ Subindo NetGuard IDS em modo desenvolvimento..."
	FLASK_ENV=development FLASK_DEBUG=1 $(PYTHON) $(APP)

.PHONY: dev-auth
dev-auth:
	@echo "▶ Subindo com autenticação ativada..."
	IDS_AUTH=true FLASK_DEBUG=1 $(PYTHON) $(APP)

.PHONY: open
open:
	@echo "▶ Abrindo dashboard..."
	$(OPEN) http://localhost:$(PORT)

# ── Produção ──────────────────────────────────────────────────────
.PHONY: prod
prod:
	@echo "▶ Subindo NetGuard IDS em modo produção..."
	IDS_LOG_LEVEL=INFO $(PYTHON) $(APP)

.PHONY: prod-auth
prod-auth:
	@echo "▶ Subindo produção + autenticação..."
	IDS_AUTH=true IDS_LOG_LEVEL=INFO $(PYTHON) $(APP)

.PHONY: prod-saas
prod-saas:
	@echo "▶ Subindo produção + billing SaaS..."
	@test -f .env && export $$(grep -v '^#' .env | xargs) || true
	IDS_AUTH=true IDS_LOG_LEVEL=INFO $(PYTHON) $(APP)

# ── Docker ────────────────────────────────────────────────────────
.PHONY: docker
docker: docker-build
	@echo "▶ Subindo container NetGuard (SQLite)..."
	$(DC) up netguard

.PHONY: docker-saas
docker-saas:
	@echo "▶ Subindo stack completa: NetGuard + PostgreSQL + Prometheus + Grafana..."
	$(DC) --profile saas up -d
	@echo ""
	@echo "  Dashboard:   http://localhost:5000"
	@echo "  Prometheus:  http://localhost:9090"
	@echo "  Grafana:     http://localhost:3000  (admin / admin_change_me)"
	@echo ""

.PHONY: docker-down
docker-down:
	@echo "▶ Parando containers..."
	$(DC) --profile saas down

.PHONY: docker-logs
docker-logs:
	$(DC) logs -f netguard

.PHONY: docker-build
docker-build:
	@echo "▶ Buildando imagem Docker..."
	$(DC) build netguard

# ── Instalação ────────────────────────────────────────────────────
.PHONY: install
install:
	@echo "▶ Instalando dependências..."
	$(PIP) install -r requirements.txt

.PHONY: install-all
install-all:
	@echo "▶ Instalando dependências + extras (stripe, psycopg2, gunicorn)..."
	$(PIP) install -r requirements.txt
	$(PIP) install stripe psycopg2-binary gunicorn

.PHONY: venv
venv:
	@echo "▶ Criando ambiente virtual..."
	$(PYTHON) -m venv venv
	@echo "  Ative com: source venv/bin/activate  (Linux/Mac)"
	@echo "             venv\\Scripts\\activate      (Windows)"

# ── Manutenção ────────────────────────────────────────────────────
.PHONY: health
health:
	@echo "▶ Checando saúde da aplicação..."
	@$(PYTHON) -c "\
import urllib.request, json, sys; \
try: \
    r = urllib.request.urlopen('http://localhost:$(PORT)/health', timeout=5); \
    d = json.loads(r.read()); \
    print('  status :', d.get('status','?')); \
    [print(f'  {k:<20}: {v}') for k,v in d.get('subsystems',{}).items()]; \
except Exception as e: \
    print('  ERRO:', e); sys.exit(1)"

.PHONY: logs
logs:
	@echo "▶ Monitorando logs (Ctrl+C para sair)..."
	tail -f netguard.log 2>/dev/null || echo "  Arquivo netguard.log não encontrado — logs sendo exibidos no console."

.PHONY: clean
clean:
	@echo "▶ Limpando arquivos temporários..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.pyo" -delete 2>/dev/null || true
	find . -name ".DS_Store" -delete 2>/dev/null || true
	@echo "  Feito."

.PHONY: test
test:
	@echo "▶ Rodando testes..."
	$(PYTHON) -m pytest tests/ -v 2>/dev/null || $(PYTHON) test_ids.py
