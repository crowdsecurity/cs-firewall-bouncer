#!/bin/sh

set -eu

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

API_KEY="<API_KEY>"

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
    # Default firewall backend is nftables
    FW_BACKEND="nftables"

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

gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        unique=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: $API_KEY"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}

gen_config_file() {
    # shellcheck disable=SC2016
    API_KEY=${API_KEY} BACKEND=${FW_BACKEND} envsubst '$API_KEY $BACKEND' <"./config/$CONFIG_FILE" | \
        install -D -m 0600 /dev/stdin "$CONFIG"
}

install_bouncer() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found, exiting."
        exit 1
    fi
    if [ -e "$BIN_PATH_INSTALLED" ]; then
        msg err "$BIN_PATH_INSTALLED is already installed. Exiting"
        exit 1
    fi
    msg "Installing $BOUNCER"
    check_firewall
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0600 "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    systemctl daemon-reload
    gen_apikey
    gen_config_file
    set_local_port
}

# --------------------------------- #

install_bouncer

systemctl enable "$SERVICE"
if [ "$READY" = "yes" ]; then
    systemctl start "$SERVICE"
else
    msg warn "service not started. You need to get an API key and configure it in $CONFIG"
fi

msg succ "The $BOUNCER service has been installed."
exit 0
