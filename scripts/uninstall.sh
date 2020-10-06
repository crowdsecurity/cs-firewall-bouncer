#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/firewall-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/firewall-bouncer.service"

uninstall() {
	systemctl stop firewall-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${PID_DIR}firewall-bouncer.pid"
	rm -f "${BIN_PATH_INSTALLED}"
}

uninstall

echo "firewall-bouncer uninstall successfully"