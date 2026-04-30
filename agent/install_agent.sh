#!/usr/bin/env sh
# NetGuard Agent Linux/systemd installer.
#
# Run as root from the repository's agent/ directory:
#   sudo sh ./install_agent.sh --start

set -eu

SERVICE_NAME="netguard-agent"
INSTALL_DIR="/opt/netguard"
STATE_DIR="/var/lib/netguard"
LOG_DIR="/var/log/netguard"
CONFIG_PATH=""
PYTHON_BIN="${PYTHON_BIN:-python3}"
RUN_USER="root"
START_SERVICE="false"
FORCE_INSTALL="false"

usage() {
    cat <<'EOF'
Usage: install_agent.sh [options]

Options:
  --service-name NAME   systemd service name (default: netguard-agent)
  --install-dir PATH    install root containing the agent package (default: /opt/netguard)
  --state-dir PATH      persistent state directory (default: /var/lib/netguard)
  --log-dir PATH        log directory (default: /var/log/netguard)
  --config PATH         source config.yaml to install
  --python PATH         Python interpreter for systemd ExecStart (default: python3)
  --user USER           service user (default: root; recommended for full endpoint telemetry)
  --start               enable and start the service after install
  --force               replace an existing service/package in place
  -h, --help            show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --service-name) SERVICE_NAME="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --log-dir) LOG_DIR="$2"; shift 2 ;;
        --config) CONFIG_PATH="$2"; shift 2 ;;
        --python) PYTHON_BIN="$2"; shift 2 ;;
        --user) RUN_USER="$2"; shift 2 ;;
        --start) START_SERVICE="true"; shift ;;
        --force) FORCE_INSTALL="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (sudo)." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found. This installer targets systemd Linux hosts." >&2
    exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Python interpreter not found: $PYTHON_BIN" >&2
    exit 1
fi
PYTHON_BIN=$(command -v "$PYTHON_BIN")

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_DIR="/etc/netguard"
ENV_FILE="${ENV_DIR}/agent.env"
TARGET_PACKAGE="${INSTALL_DIR}/agent"
TARGET_CONFIG="${INSTALL_DIR}/config.yaml"
TARGET_LOG="${LOG_DIR}/agent.log"

if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ] && [ "$FORCE_INSTALL" != "true" ]; then
    echo "Service ${SERVICE_NAME} already exists. Re-run with --force to upgrade in place." >&2
    exit 1
fi

if [ -z "$CONFIG_PATH" ]; then
    if [ -f "${SCRIPT_DIR}/config.yaml" ]; then
        CONFIG_PATH="${SCRIPT_DIR}/config.yaml"
    elif [ -f "$TARGET_CONFIG" ]; then
        CONFIG_PATH="$TARGET_CONFIG"
    else
        echo "config.yaml not found. Pass --config /path/to/config.yaml." >&2
        exit 1
    fi
fi

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Config file not found: $CONFIG_PATH" >&2
    exit 1
fi

"$PYTHON_BIN" -c "import psutil, requests, yaml" >/dev/null 2>&1 || {
    echo "Missing Python dependencies. Run: $PYTHON_BIN -m pip install -r ${SCRIPT_DIR}/requirements.txt" >&2
    exit 1
}

mkdir -p "$TARGET_PACKAGE" "$STATE_DIR" "$LOG_DIR" "$ENV_DIR"
cp "${SCRIPT_DIR}"/*.py "$TARGET_PACKAGE"/
cp "${SCRIPT_DIR}/requirements.txt" "$TARGET_PACKAGE"/
cp "$CONFIG_PATH" "$TARGET_CONFIG"

chmod 0755 "$INSTALL_DIR" "$TARGET_PACKAGE" "$STATE_DIR" "$LOG_DIR"
chmod 0644 "$TARGET_PACKAGE"/*.py "$TARGET_PACKAGE/requirements.txt"
chmod 0640 "$TARGET_CONFIG"
chown -R "$RUN_USER" "$TARGET_PACKAGE" "$STATE_DIR" "$LOG_DIR" "$TARGET_CONFIG" 2>/dev/null || true

cat > "$ENV_FILE" <<EOF
NETGUARD_AGENT_CONFIG=${TARGET_CONFIG}
NETGUARD_AGENT_HOME=${STATE_DIR}
NETGUARD_AGENT_LOG_PATH=${TARGET_LOG}
PYTHONUNBUFFERED=1
EOF
chmod 0640 "$ENV_FILE"

cat > "$UNIT_PATH" <<EOF
[Unit]
Description=NetGuard Endpoint Agent
Documentation=https://github.com/raphaelguterres/netguard-ids
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=${PYTHON_BIN} -m agent --config ${TARGET_CONFIG}
Restart=always
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=45
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${STATE_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_PATH"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service" >/dev/null

if [ "$START_SERVICE" = "true" ]; then
    systemctl restart "${SERVICE_NAME}.service"
fi

echo "NetGuard Agent installed."
echo "Service: ${SERVICE_NAME}.service"
echo "Package: ${TARGET_PACKAGE}"
echo "Config:  ${TARGET_CONFIG}"
echo "State:   ${STATE_DIR}"
echo "Logs:    ${TARGET_LOG}"
