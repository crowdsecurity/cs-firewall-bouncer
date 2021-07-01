#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-firewall-bouncer"
BIN_PATH="./crowdsec-firewall-bouncer"
CONFIG_DIR="/etc/crowdsec/bouncers/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-firewall-bouncer.service"

# Default pkg manager is apt
PKG="apt"
# Default firewall backend is nftables
FW_BACKEND="nftables"
API_KEY=""

check_pkg_manager(){
    if [ -f /etc/redhat-release ]; then
        PKG="yum"
    elif cat /etc/system-release | grep -q "Amazon Linux release 2 (Karoo)"; then
        PKG="yum"
    elif [ -f /etc/debian_version ]; then
        PKG="apt"
    else
        echo "Distribution is not supported, exiting."
        exit
    fi   
}

check_firewall() {
    iptables="true"
    which iptables > /dev/null
    FW_BACKEND=""
    if [[ $? != 0 ]]; then 
        echo "iptables is not present"
        iptables="false"
    else 
        FW_BACKEND="iptables"
        echo "iptables found"
    fi

    nftables="true"
    which nft > /dev/null
    if [[ $? != 0 ]]; then 
        echo "nftables is not present"
        nftables="false"
    else
        FW_BACKEND="nftables" 
        echo "nftables found"
    fi

    if [ "$nftables" = "false" -a "$iptables" = "false" ]; then
        echo "No firewall found, do you want to install nftables (Y/n) ?"
        read answer
        if [[ ${answer} == "" ]]; then
            answer="y"
        fi
        if [ "$answer" != "${answer#[Yy]}" ] ;then
            "$PKG" install -y -qq nftables > /dev/null && echo "nftables successfully installed"
        else
            echo "unable to continue without nftables. Please install nftables or iptables to use this bouncer." && exit 1
        fi   
    fi

    if [ "$nftables" = "true" -a "$iptables" = "true" ]; then
        echo "Found nftables(default) and iptables, which firewall do you want to use (nftables/iptables)?"
        read answer
        if [ "$answer" = "iptables" ]; then
            FW_BACKEND="iptables"
        fi   
    fi

    if [ "$FW_BACKEND" = "iptables" ]; then
        check_ipset
    fi
}



gen_apikey() {
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        API_KEY=`cscli bouncers add cs-firewall-bouncer-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
}

gen_config_file() {
    API_KEY=${API_KEY} BACKEND=${FW_BACKEND} envsubst < ./config/crowdsec-firewall-bouncer.yaml > "${CONFIG_DIR}crowdsec-firewall-bouncer.yaml"
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
            "$PKG" install -y -qq ipset > /dev/null && echo "ipset successfully installed"
        else
            echo "unable to continue without ipset. Exiting" && exit 1
        fi      
    fi
}


install_firewall_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/crowdsec-firewall-bouncer.yaml" "${CONFIG_DIR}crowdsec-firewall-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/crowdsec-firewall-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}


if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

check_pkg_manager
check_firewall
echo "Installing firewall-bouncer"
install_firewall_bouncer
gen_apikey
gen_config_file
systemctl enable crowdsec-firewall-bouncer.service
if [ "$READY" = "yes" ]; then
    systemctl start crowdsec-firewall-bouncer.service
else
    echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}crowdsec-firewall-bouncer.yaml"
fi
echo "The firewall-bouncer service has been installed!"
