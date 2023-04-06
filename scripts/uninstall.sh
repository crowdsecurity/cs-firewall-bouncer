#!/bin/sh

set -e

set_colors() {
    if [ ! -t 0 ]; then
        # terminal is not interactive; no colors
        FG_RED=""
        FG_GREEN=""
        FG_YELLOW=""
        FG_CYAN=""
        RESET=""
    elif tput sgr0 >/dev/null; then
        # terminfo
        FG_RED=$(tput setaf 1)
        FG_GREEN=$(tput setaf 2)
        FG_YELLOW=$(tput setaf 3)
        FG_CYAN=$(tput setaf 6)
        RESET=$(tput sgr0)
    else
        FG_RED=$(printf '%b' '\033[31m')
        FG_GREEN=$(printf '%b' '\033[32m')
        FG_YELLOW=$(printf '%b' '\033[33m')
        FG_CYAN=$(printf '%b' '\033[36m')
        RESET=$(printf '%b' '\033[0m')
    fi
}

set_colors

msg() {
    case "$1" in
        info) echo "${FG_CYAN}$2${RESET}" >&2 ;;
        warn) echo "${FG_YELLOW}$2${RESET}" >&2 ;;
        err) echo "${FG_RED}$2${RESET}" >&2 ;;
        succ) echo "${FG_GREEN}$2${RESET}" >&2 ;;
        *) echo "$1" >&2 ;;
    esac
}

#shellcheck disable=SC2312
if [ "$(id -u)" -ne 0 ]; then
    msg warn "Please run $0 as root or with sudo"
    exit 1
fi

# --------------------------------- #

BOUNCER="crowdsec-firewall-bouncer"
SERVICE="$BOUNCER.service"
BIN_PATH_INSTALLED="/usr/local/bin/$BOUNCER"
CONFIG_DIR="/etc/crowdsec/bouncers"
CONFIG_FILE="$BOUNCER.yaml"
CONFIG="$CONFIG_DIR/$CONFIG_FILE"
LOG_FILE="/var/log/$BOUNCER.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/$SERVICE"

uninstall() {
    systemctl stop "$SERVICE"
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" || true
        rm -f "$CONFIG.id"
    fi
    rm -f "$CONFIG"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    rm -f "$LOG_FILE"
}

uninstall

msg succ "$BOUNCER has been successfully uninstalled"
exit 0
