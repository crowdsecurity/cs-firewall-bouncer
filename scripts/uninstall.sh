#!/bin/sh

#shellcheck disable=SC2312
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run $0 as root or with sudo"
    exit 1
fi

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
LOG_FILE="/var/log/crowdsec-firewall-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-firewall-bouncer.service"

uninstall() {
    systemctl stop crowdsec-firewall-bouncer
    rm -rf "$CONFIG_DIR"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    rm -f "$LOG_FILE"
}

uninstall

echo "crowdsec-firewall-bouncer uninstalled successfully"
exit 0
