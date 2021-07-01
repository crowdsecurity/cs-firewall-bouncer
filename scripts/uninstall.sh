#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/crowdsec-firewall-bouncer/"
LOG_FILE="/var/log/crowdsec-firewall-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-firewall-bouncer.service"

uninstall() {
	systemctl stop crowdsec-firewall-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-firewall-bouncer uninstall successfully"