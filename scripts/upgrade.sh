#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-firewall-bouncer"
BIN_PATH="./cs-firewall-bouncer"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-firewall-bouncer.service"


upgrade_bin() {
    rm "${BIN_PATH_INSTALLED}" || (echo "cs-firewall-bouncer is not installed, exiting." && exit 1)
    install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
}


if ! [ $(id -u) = 0 ]; then
    log_err "Please run the install script as root or with sudo"
    exit 1
fi

systemctl stop cs-firewall-bouncer
upgrade_bin
systemctl start cs-firewall-bouncer
echo "cs-firewall-bouncer upgraded successfully."