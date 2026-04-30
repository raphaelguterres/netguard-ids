#!/usr/bin/env sh
# NetGuard Agent Linux/systemd uninstaller.
#
# Run as root on the endpoint:
#   sudo sh ./uninstall_agent.sh --keep-state

set -eu

SERVICE_NAME="netguard-agent"
INSTALL_DIR="/opt/netguard"
STATE_DIR="/var/lib/netguard"
LOG_DIR="/var/log/netguard"
KEEP_STATE="false"
KEEP_CONFIG="false"

usage() {
    cat <<'EOF'
Usage: uninstall_agent.sh [options]

Options:
  --service-name NAME   systemd service name (default: netguard-agent)
  --install-dir PATH    install root to remove (default: /opt/netguard)
  --state-dir PATH      state directory to remove unless --keep-state
  --log-dir PATH        log directory to remove unless --keep-state
  --keep-state          preserve host_id, credentials, buffer DB, and logs
  --keep-config         preserve config.yaml under the install directory
  -h, --help            show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --service-name) SERVICE_NAME="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --log-dir) LOG_DIR="$2"; shift 2 ;;
        --keep-state) KEEP_STATE="true"; shift ;;
        --keep-config) KEEP_CONFIG="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root (sudo)." >&2
    exit 1
fi

UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/netguard/agent.env"
TARGET_CONFIG="${INSTALL_DIR}/config.yaml"
TARGET_PACKAGE="${INSTALL_DIR}/agent"

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
        systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
fi

rm -f "$UNIT_PATH"
rm -f "$ENV_FILE"

if [ "$KEEP_CONFIG" != "true" ]; then
    rm -f "$TARGET_CONFIG"
fi

rm -rf "$TARGET_PACKAGE"

if [ "$KEEP_STATE" != "true" ]; then
    rm -rf "$STATE_DIR"
    rm -rf "$LOG_DIR"
fi

if [ -d "$INSTALL_DIR" ] && [ -z "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    rmdir "$INSTALL_DIR"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "NetGuard Agent removed."
if [ "$KEEP_STATE" = "true" ]; then
    echo "State kept: ${STATE_DIR}"
    echo "Logs kept:  ${LOG_DIR}"
fi
if [ "$KEEP_CONFIG" = "true" ]; then
    echo "Config kept: ${TARGET_CONFIG}"
fi
