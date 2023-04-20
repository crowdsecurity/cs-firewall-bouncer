#!/bin/sh

set -eu

BOUNCER="crowdsec-firewall-bouncer"

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

uninstall() {
    systemctl stop "$SERVICE" || true
    delete_bouncer
    rm -f "$CONFIG"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    rm -f "/var/log/$BOUNCER.log"
}

uninstall
msg succ "$BOUNCER has been successfully uninstalled"
exit 0
