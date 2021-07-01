#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/cs-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-firewall-bouncer/"
LOG_FILE="/var/log/crowdsec-firewall-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-firewall-bouncer.service"

uninstall() {
	systemctl stop cs-firewall-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "cs-firewall-bouncer uninstall successfully"