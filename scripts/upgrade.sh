#!/bin/sh

set -e

set_colors() {
    #shellcheck disable=SC2034
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
BIN_PATH="./$BOUNCER"

upgrade_bin() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found, exiting."
        exit 1
    fi
    if [ ! -e "$BIN_PATH_INSTALLED" ]; then
        msg err "$BIN_PATH_INSTALLED is not installed, exiting."
        exit 1
    fi
    rm "$BIN_PATH_INSTALLED"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
}

systemctl stop "$SERVICE"
upgrade_bin
systemctl start "$SERVICE" || msg warn "$SERVICE failed to start, please check the systemd logs"

msg succ "$BOUNCER upgraded successfully."
exit 0
