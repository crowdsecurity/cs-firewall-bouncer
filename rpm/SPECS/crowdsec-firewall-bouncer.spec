Name:           crowdsec-firewall-bouncer-iptables
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:      Firewall bouncer for Crowdsec (iptables+ipset configuration)

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
Source1:        80-crowdsec-firewall-bouncer.preset
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  golang >= 1.14
BuildRequires:  make
BuildRequires:  jq
%{?fc33:BuildRequires: systemd-rpm-macros}

Requires: iptables,ipset,gettext,ipset-libs

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-firewall-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -q -T -b 0 -n crowdsec-firewall-bouncer-%{version_number}

%build
BUILD_VERSION=%{local_version} make
TMP=`mktemp -p /tmp/`
cp config/%{name}.service ${TMP}
BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/bouncers/ envsubst < ${TMP} > config/%{name}.service
rm ${TMP}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}%{_presetdir}
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/bouncers/%{name}.yaml 
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -m 644 -D %{SOURCE1} %{buildroot}%{_presetdir}
%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml 
%config(noreplace) %{_presetdir}/80-crowdsec-firewall-bouncer.preset

%post -p /bin/bash

systemctl daemon-reload

START=0
CSCLI=/usr/bin/cscli

#install
if [ "$1" == "1" ] ; then
    type cscli > /dev/null

    if [ "$?" -eq "0" ] ; then
        START=1
        echo "cscli/crowdsec is present, generating API key"
        unique=`date +%s`
        API_KEY=`cscli -oraw bouncers add FirewallBouncer-${unique}`
        if [ $? -eq 1 ] ; then
            echo "failed to create API token, service won't be started."
            START=0
            API_KEY="<API_KEY>"
        else
            echo "API Key : ${API_KEY}"
        fi
    fi

    TMP=`mktemp -p /tmp/`
    install -m 0600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ${TMP}
    BACKEND=iptables API_KEY=${API_KEY} envsubst < ${TMP} | install -m 0600 /dev/stdin /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
    rm ${TMP}
else 
    START=1
fi
 
%changelog
* Tue Feb 16 2021 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging



%package -n crowdsec-firewall-bouncer-nftables
Summary:      Firewall bouncer for Crowdsec (nftables configuration)
Requires: nftables,gettext
%description -n crowdsec-firewall-bouncer-nftables

%files -n crowdsec-firewall-bouncer-nftables
/usr/bin/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml 

%post -p /bin/bash -n crowdsec-firewall-bouncer-nftables

systemctl daemon-reload

START=0
CSCLI=/usr/bin/cscli

# install
if [ "$1" == "1" ] ; then
    if command -v "$CSCLI" >/dev/null; then
        START=1
        echo "cscli/crowdsec is present, generating API key"
        unique=`date +%s`
        API_KEY=`cscli -oraw bouncers add FirewallBouncer-${unique}`
        if [ $? -eq 1 ] ; then
            echo "failed to create API token, service won't be started."
            START=0
            API_KEY="<API_KEY>"
        else
            echo "API Key : ${API_KEY}"
        fi
    fi

    TMP=`mktemp -p /tmp/`
    install -m 0600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ${TMP}
    BACKEND=nftables API_KEY=${API_KEY} envsubst < ${TMP} | install -m 0600 /dev/stdin /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
    rm ${TMP}
else 
    START=1
fi



%preun -p /bin/bash

if [ "$1" == "0" ] ; then
    systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"
fi

%preun -p /bin/bash -n crowdsec-firewall-bouncer-nftables

if [ "$1" == "0" ] ; then
    systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"
fi


%postun -p /bin/bash

if [ "$1" == "1" ] ; then
    systemctl restart  crowdsec-firewall-bouncer || echo "cannot restart service"
fi


%postun -p /bin/bash -n crowdsec-firewall-bouncer-nftables

if [ "$1" == "1" ] ; then
    systemctl restart  crowdsec-firewall-bouncer || echo "cannot restart service"
fi


%systemd_post crowdsec-firewall-bouncer.service

CSCLI=/usr/bin/cscli

if command -v "$CSCLI" >/dev/null; then
    PORT=$(cscli config show --key "Config.API.Server.ListenURI"|cut -d ":" -f2)
    if [ ! -z "$PORT" ]; then     
       sed -i "s/localhost:8080/127.0.0.1:${PORT}/g" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
       sed -i "s/127.0.0.1:8080/127.0.0.1:${PORT}/g" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
    fi
fi


if [ ${START} -eq 0 ] ; then
    echo "no api key was generated, won't start or enanble service"
else 
    %if 0%{?fc35}
    systemctl enable crowdsec-firewall-bouncer 
    %endif
    systemctl start crowdsec-firewall-bouncer
fi
