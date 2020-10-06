#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/firewall-bouncer"
BIN_PATH="./firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/firewall-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/firewall-bouncer.service"

check_iptables() {
    which iptables > /dev/null
    if [[ $? != 0 ]]; then
        echo "iptables not found, do you want to install it (Y/n)? "
        read answer
        if [[ ${answer} == "" ]]; then
            answer="y"
        fi
        if [ "$answer" != "${answer#[Yy]}" ] ;then
            apt-get install -y -qq iptables > /dev/null && echo "iptables successfully installed"
        else
            echo "unable to continue without iptables. Exiting" && exit 1
        fi      
    fi
}

check_ipset() {
    which ipset > /dev/null
    if [[ $? != 0 ]]; then
        echo "ipset not found, do you want to install it (Y/n)? "
        read answer
        if [[ ${answer} == "" ]]; then
            answer="y"
        fi
        if [ "$answer" != "${answer#[Yy]}" ] ;then
            apt-get install -y -qq ipset > /dev/null && echo "ipset successfully installed"
        else
            echo "unable to continue without ipset. Exiting" && exit 1
        fi      
    fi
}


install_netfilter_blocker() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/firewall-bouncer.yaml" "${CONFIG_DIR}firewall-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/firewall-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}


check_iptables
check_ipset
echo "Installing firewall-bouncer"
install_netfilter_blocker