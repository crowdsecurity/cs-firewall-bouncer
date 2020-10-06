#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/netfilter-blocker"
CONFIG_DIR="/etc/crowdsec/netfilter-blocker/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/netfilter-blocker.service"

uninstall() {
	systemctl stop netfilter-blocker
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${PID_DIR}netfilter-blocker.pid"
	rm -f "${BIN_PATH_INSTALLED}"
}

uninstall