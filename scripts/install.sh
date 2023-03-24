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
CONFIG_DIR="/etc/crowdsec/bouncers"
CONFIG="${CONFIG_DIR}/$BOUNCER.yaml"
SYSTEMD_PATH_FILE="/etc/systemd/system/$SERVICE"

# Default firewall backend is nftables
FW_BACKEND="nftables"
API_KEY=""


install_pkg() {
    pkg="$1"
    if [ -f /etc/redhat-release ]; then
        yum install -y "$pkg"
    elif grep -q "Amazon Linux release 2 (Karoo)" /etc/system-release 2>/dev/null; then
        yum install -y "$pkg"
    elif grep -q "suse" /etc/os-release 2>/dev/null; then
        zypper install -y "$pkg"
    elif [ -f /etc/debian_version ]; then
        apt install -y "$pkg"
    else
        msg warn "This distribution is not supported"
        return 1
    fi
    msg succ "$pkg successfully installed"
    return 0
}


check_firewall() {
    FW_BACKEND=""

    iptables="true"
    if command -v iptables >/dev/null; then 
        FW_BACKEND="iptables"
        msg info "iptables found"
    else
        msg warn "iptables not found"
        iptables="false"
    fi

    nftables="true"
    if command -v nft >/dev/null; then 
        FW_BACKEND="nftables"
        msg info "nftables found"
    else
        msg warn "nftables not found"
        nftables="false"
    fi

    if [ "$nftables" = "false" ] && [ "$iptables" = "false" ]; then
        printf '%s ' "No firewall found, do you want to install nftables (Y/n) ?"
        read -r answer
        if echo "$answer" | grep -iq '^n'; then
            msg err "unable to continue without nftables. Please install nftables or iptables to use this bouncer."
            exit 1
        fi
        # shellcheck disable=SC2310
        install_pkg nftables || ( msg err "Cannot install nftables, please install it manually"; exit 1 )
    fi

    if [ "$nftables" = "true" ] && [ "$iptables" = "true" ]; then
        printf '%s ' "Found nftables (default) and iptables, which firewall do you want to use (nftables/iptables) ?"
        read -r answer
        if [ "$answer" = "iptables" ]; then
            FW_BACKEND="iptables"
        fi
    fi

    if [ "$FW_BACKEND" = "iptables" ]; then
        check_ipset
    fi
}


gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        unique=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        bouncer_id="cs-firewall-bouncer-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: ${API_KEY}"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}


gen_config_file() {
    (umask 077; API_KEY=${API_KEY} BACKEND=${FW_BACKEND} envsubst <./config/crowdsec-firewall-bouncer.yaml >"$CONFIG")
}


check_ipset() {
    if ! command -v ipset >/dev/null; then
        printf '%s ' "ipset not found, do you want to install it (Y/n) ?"
        read -r answer
        if echo "$answer" | grep -iq '^n'; then
            msg err "unable to continue without ipset. Exiting"
            exit 1
        fi
        # shellcheck disable=SC2310
        install_pkg ipset || ( msg err "Cannot install ipset, please install it manually"; exit 1 )
    fi
}


set_local_port() {
    if command -v cscli >/dev/null; then
        PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2)
        if [ "$PORT" != "" ]; then
           sed -i "s/localhost:8080/127.0.0.1:${PORT}/g" "$CONFIG"
           sed -i "s/127.0.0.1:8080/127.0.0.1:${PORT}/g" "$CONFIG"
        fi
    fi
}


install_bouncer() {
    if [ -e "$BIN_PATH_INSTALLED" ]; then
        msg warn "$BIN_PATH_INSTALLED is already installed. Exiting"
        exit 1
    fi
    msg info "Installing $BOUNCER"
    check_firewall
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    mkdir -p "$CONFIG_DIR"
    install -m 0600 "./config/crowdsec-firewall-bouncer.yaml" "$CONFIG"
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < "./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    systemctl daemon-reload
    gen_apikey
    gen_config_file
    set_local_port
}


set_colors
install_bouncer

systemctl enable "$SERVICE"
if [ "$READY" = "yes" ]; then
    systemctl start "$SERVICE"
else
    msg warn "service not started. You need to get an API key and configure it in $CONFIG"
fi

msg succ "The $BOUNCER service has been installed!"
exit 0
