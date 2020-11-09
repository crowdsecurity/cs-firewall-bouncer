#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-firewall-bouncer"
BIN_PATH="./cs-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-firewall-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-firewall-bouncer.service"

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


gen_apikey() {
    SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
    API_KEY=`cscli bouncers add cs-firewall-bouncer-${SUFFIX} -o raw`
    API_KEY=${API_KEY} envsubst < ./config/cs-firewall-bouncer.yaml > "${CONFIG_DIR}cs-firewall-bouncer.yaml"
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


install_firewall_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-firewall-bouncer.yaml" "${CONFIG_DIR}cs-firewall-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-firewall-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}


check_iptables
check_ipset
echo "Installing firewall-bouncer"
install_firewall_bouncer
gen_apikey
echo "The firewall-bouncer service has been installed!"
