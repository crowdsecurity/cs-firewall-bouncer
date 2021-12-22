#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-firewall-bouncer"
BIN_PATH="./crowdsec-firewall-bouncer"

RED='\033[0;31m'
NC='\033[0m'

upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "crowdsec-firewall-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


log_err() {
    msg=$1
    date=$(date +%x:%X)
    echo -e "${RED}ERR${NC}[${date}] crowdsec-firewall-bouncer: ${msg}" 1>&2
}

if ! [ $(id -u) = 0 ]; then
    log_err "Please run the upgrade script as root or with sudo"
    exit 1
fi

systemctl stop crowdsec-firewall-bouncer
upgrade_bin
systemctl start crowdsec-firewall-bouncer
echo "crowdsec-firewall-bouncer upgraded successfully."