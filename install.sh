#!/usr/bin/env bash
# NetGuard IDS — Instalador Linux/macOS
# Uso: bash install.sh [--port 5000] [--host 0.0.0.0] [--service]
set -euo pipefail

# ── Cores ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }
step() { echo -e "\n  ${CYAN}▶${NC} $1"; }

# ── Argumentos ────────────────────────────────────────────────────
PORT=5000; HOST=127.0.0.1; AS_SERVICE=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --port)    PORT=$2;       shift 2 ;;
    --host)    HOST=$2;       shift 2 ;;
    --service) AS_SERVICE=true; shift ;;
    --force)   FORCE=true;    shift ;;
    *)         shift ;;
  esac
done
FORCE=${FORCE:-false}

clear
echo ""
echo -e "  ${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "  ${BLUE}║   NetGuard IDS — Instalação Rápida   ║${NC}"
echo -e "  ${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Detecta pasta do projeto ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/app.py" ]] || fail "app.py não encontrado em '$SCRIPT_DIR'"

# ── Python ────────────────────────────────────────────────────────
step "Verificando Python 3.9+"
PYTHON=""
for cmd in python3 python python3.11 python3.10 python3.9; do
  if command -v "$cmd" &>/dev/null; then
    VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    MAJOR=${VER%%.*}; MINOR=${VER##*.}
    if [[ $MAJOR -ge 3 && $MINOR -ge 9 ]]; then PYTHON=$cmd; break; fi
  fi
done
[[ -n "$PYTHON" ]] || fail "Python 3.9+ não encontrado. Instale com: sudo apt install python3 (Ubuntu) ou brew install python (Mac)"
ok "Python: $($PYTHON --version)"

# ── Venv ──────────────────────────────────────────────────────────
step "Criando ambiente virtual"
VENV="$SCRIPT_DIR/venv"
if [[ -d "$VENV" && "$FORCE" == "false" ]]; then
  ok "Venv já existe (use --force para recriar)"
else
  [[ -d "$VENV" ]] && rm -rf "$VENV"
  "$PYTHON" -m venv "$VENV"
  ok "Venv criado em: $VENV"
fi

PIP="$VENV/bin/pip"
PY="$VENV/bin/python"

# ── Dependências ──────────────────────────────────────────────────
step "Instalando dependências"
"$PIP" install --upgrade pip --quiet
"$PIP" install -r "$SCRIPT_DIR/requirements.txt" --quiet
# Opcionais
"$PIP" install scikit-learn numpy flask-talisman flask-limiter --quiet 2>/dev/null || true
ok "Dependências instaladas"

# ── .env ──────────────────────────────────────────────────────────
step "Configurando ambiente"
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<EOF
IDS_HOST=$HOST
IDS_PORT=$PORT
IDS_AUTH=false
IDS_DEBUG=false
EOF
  ok ".env criado"
else
  ok ".env já existe"
fi

# ── Serviço systemd (Linux) ───────────────────────────────────────
if [[ "$AS_SERVICE" == "true" ]]; then
  step "Registrando serviço systemd"
  if [[ "$(uname)" != "Linux" ]]; then
    warn "systemd apenas disponível no Linux. Pulando."
  elif [[ $EUID -ne 0 ]]; then
    warn "--service requer sudo. Pulando."
  else
    USER_OWNER=$(stat -c '%U' "$SCRIPT_DIR")
    cat > /etc/systemd/system/netguard-ids.service <<EOF
[Unit]
Description=NetGuard IDS
After=network.target

[Service]
Type=simple
User=$USER_OWNER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PY $SCRIPT_DIR/app.py
Restart=always
RestartSec=5
Environment=IDS_HOST=$HOST IDS_PORT=$PORT

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable netguard-ids
    systemctl start  netguard-ids
    ok "Serviço 'netguard-ids' registrado e iniciado"
    ok "Gerenciar: sudo systemctl status|stop|restart netguard-ids"
  fi
fi

# ── macOS LaunchAgent ─────────────────────────────────────────────
if [[ "$AS_SERVICE" == "true" && "$(uname)" == "Darwin" ]]; then
  PLIST="$HOME/Library/LaunchAgents/com.netguard.ids.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netguard.ids</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>$SCRIPT_DIR/app.py</string>
  </array>
  <key>WorkingDirectory</key><string>$SCRIPT_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
  launchctl load "$PLIST"
  ok "LaunchAgent registrado (inicia automaticamente no login)"
fi

# ── Resumo ────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "  ${GREEN}║        Instalação concluída!         ║${NC}"
echo -e "  ${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  Para iniciar:"
echo -e "    ${CYAN}cd \"$SCRIPT_DIR\"${NC}"
echo -e "    ${CYAN}source venv/bin/activate${NC}"
echo -e "    ${CYAN}python app.py${NC}"
echo ""
echo -e "  Dashboard: ${BLUE}http://${HOST}:${PORT}${NC}"
echo ""

read -rp "  Iniciar o NetGuard agora? [S/n] " RESP
if [[ "$RESP" != "n" && "$RESP" != "N" ]]; then
  echo -e "  ${GREEN}Iniciando...${NC}"
  cd "$SCRIPT_DIR"
  nohup "$PY" app.py >"$SCRIPT_DIR/netguard.log" 2>&1 &
  echo -e "  ${GREEN}✔ Rodando em background (PID $!)${NC}"
  sleep 2
  # Abre browser
  URL="http://${HOST}:${PORT}"
  command -v xdg-open &>/dev/null && xdg-open "$URL" || \
  command -v open      &>/dev/null && open      "$URL" || \
  echo -e "  Acesse: ${BLUE}$URL${NC}"
fi
