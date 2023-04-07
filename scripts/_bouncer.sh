#!/bin/sh
#shellcheck disable=SC3043

set -eu

# shellcheck disable=SC2034
{
SERVICE="$BOUNCER.service"
BIN_PATH_INSTALLED="/usr/local/bin/$BOUNCER"
BIN_PATH="./$BOUNCER"
CONFIG_DIR="/etc/crowdsec/bouncers"
CONFIG_FILE="$BOUNCER.yaml"
CONFIG="$CONFIG_DIR/$CONFIG_FILE"
SYSTEMD_PATH_FILE="/etc/systemd/system/$SERVICE"
}

assert_root() {
    #shellcheck disable=SC2312
    if [ "$(id -u)" -ne 0 ]; then
        msg warn "Please run $0 as root or with sudo"
        exit 1
    fi
}

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

msg() {
    set_colors
    case "$1" in
        info) echo "${FG_CYAN}$2${RESET}" >&2 ;;
        warn) echo "${FG_YELLOW}$2${RESET}" >&2 ;;
        err) echo "${FG_RED}$2${RESET}" >&2 ;;
        succ) echo "${FG_GREEN}$2${RESET}" >&2 ;;
        *) echo "$1" >&2 ;;
    esac
}

need_api_key() {
    local before after
    before=$(cat "$CONFIG")
    # shellcheck disable=SC2016
    after=$(envsubst '$API_KEY' < "$CONFIG")

    if [ "$before" = "$after" ]; then
        return 1
    fi
    return 0
}

set_api_key() {
    # if we can't set the key, the user will take care of it
    API_KEY="<API_KEY>"
    ret=0

    if command -v cscli >/dev/null; then
        echo "cscli/crowdsec is present, generating API key" >&2
        unique=$(date +%s)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        if [ $? -eq 1 ]; then
            echo "failed to create API key" >&2
            ret=1
        else
            echo "API Key successfully created" >&2
            echo "$bouncer_id" > "$CONFIG.id"
        fi
    else
        echo "cscli/crowdsec is not present, please set the API key manually" >&2
        ret=1
    fi

    (
        umask 077
        # can't use redirection while overwriting a file
        before=$(cat "$CONFIG")
        # shellcheck disable=SC2016
        echo "$before" | API_KEY="$API_KEY" envsubst '$API_KEY' > "$CONFIG"
    )

    return "$ret"
}

set_local_port() {
    command -v cscli >/dev/null || return 0
    PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2)
    if [ "$PORT" != "" ]; then
        sed -i "s/localhost:8080/127.0.0.1:$PORT/g" "$CONFIG"
        sed -i "s/127.0.0.1:8080/127.0.0.1:$PORT/g" "$CONFIG"
    fi
}

delete_bouncer() {
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" 2>/dev/null || true
        rm -f "$CONFIG.id"
    fi
}

upgrade_bin() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found"
        return 1
    fi
    if [ ! -e "$BIN_PATH_INSTALLED" ]; then
        msg err "$BIN_PATH_INSTALLED is not installed"
        return 1
    fi
    rm "$BIN_PATH_INSTALLED"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
}
