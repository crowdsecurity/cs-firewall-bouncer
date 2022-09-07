#!/bin/sh

#shellcheck disable=SC2312
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run $0 as root or with sudo"
    exit 1
fi

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-firewall-bouncer"
BIN_PATH="./crowdsec-firewall-bouncer"

if [ ! -t 0 ]; then
    FG_RED=""
    RESET=""
elif tput sgr0 > /dev/null; then
    FG_RED="$(tput setaf 1)"
    RESET="$(tput sgr0)"
else
    FG_RED="$(printf '%b' '\033[31m')"
    RESET="$(printf '%b' '\033[0m')"
fi

upgrade_bin() {
    rm "$BIN_PATH_INSTALLED" || (echo "crowdsec-firewall-bouncer is not installed, exiting." && exit 1)
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
}

log_err() {
    date=$(date +%x:%X)
    echo "${FG_RED}ERR${RESET}[${date}] crowdsec-firewall-bouncer: $1" >&2
}

systemctl stop crowdsec-firewall-bouncer
upgrade_bin
systemctl start crowdsec-firewall-bouncer

echo "crowdsec-firewall-bouncer upgraded successfully."
exit 0
