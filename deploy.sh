#!/bin/bash
set -euo pipefail

# ===============================
# CONFIGURATION
# ===============================
REPO_URL="git@gitlab.example.com:mygroup/bind_exporter.git"   # <-- change to your repo URL
CLONE_DIR="/tmp/bind_exporter_deploy"
INSTALL_DIR="/opt/bind_exporter"
SERVICE_FILE="/etc/systemd/system/bind_exporter.service"
NAMED_CONF="/etc/bind/named.conf.local"
BACKUP_DIR="/etc/bind/backups"

# ===============================
# ROOT CHECK
# ===============================
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root!"
    exit 1
fi

# ===============================
# FUNCTIONS
# ===============================

install_dependencies() {
    echo "[*] Installing dependencies..."
    set +e
    apt-get update -y
    apt-get install -y git python3-pip python3-prometheus-client python3-dnspython python3-psutil ifstat
    STATUS=$?
    set -e

    if [[ $STATUS -ne 0 ]]; then
        echo "[!] Package installation failed. Attempting troubleshooting..."

        echo "[*] Cleaning up apt cache..."
        rm -rf /var/lib/apt/lists/*
        apt-get clean

        echo "[*] Updating package lists..."
        apt-get update -y || true

        echo "[*] Retrying installation..."
        apt-get install -f -y
        apt-get install -y git python3-pip python3-prometheus-client python3-dnspython python3-psutil ifstat || {
            echo "[ERROR] Failed to install dependencies after retry. Please check your apt sources or network."
            exit 1
        }
    fi
}

clone_repo() {
    echo "[*] Cloning repository..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
}

deploy_files() {
    echo "[*] Deploying exporter files..."

    # Python exporter
    mkdir -p "$INSTALL_DIR"
    cp "$CLONE_DIR/bind_exporter.py" "$INSTALL_DIR/"

    # Systemd service
    cp "$CLONE_DIR/bind_exporter.service" "$SERVICE_FILE"
    chmod 644 "$SERVICE_FILE"

    # Backup and replace BIND config
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$NAMED_CONF" ]]; then
        timestamp=$(date +"%Y%m%d_%H%M%S")
        cp "$NAMED_CONF" "$BACKUP_DIR/named.conf.local.$timestamp"
        echo "[*] Backup of named.conf.local saved to $BACKUP_DIR/named.conf.local.$timestamp"
    fi
    cp "$CLONE_DIR/named.conf.local" "$NAMED_CONF"
}

configure_systemd() {
    echo "[*] Enabling and starting systemd service..."
    systemctl daemon-reload
    systemctl enable bind_exporter.service
    systemctl restart bind_exporter.service
    systemctl status bind_exporter.service --no-pager || true
}

prompt_restart_named() {
    echo ""
    read -rp "Do you want to restart named (BIND9) now? [y/N]: " answer
    case "$answer" in
        [Yy]* )
            echo "[*] Restarting named..."
            systemctl restart named
            systemctl status named --no-pager || true
            ;;
        * )
            echo "[*] Skipping named restart."
            ;;
    esac
}

# ===============================
# MAIN
# ===============================
echo "[*] Starting bind_exporter deployment..."

install_dependencies
clone_repo
deploy_files
configure_systemd
prompt_restart_named

echo "[*] Deployment completed successfully!"
