Name:           crowdsec-firewall-bouncer
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:      Firewall bouncer for Crowdsec (iptables+ipset, nftables or pf)

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  golang >= 1.14
BuildRequires:  make
BuildRequires:  jq
%{?fc33:BuildRequires: systemd-rpm-macros}

Requires: (crowdsec-firewall-bouncer-iptables or crowdsec-firewall-bouncer-nftables)

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-firewall-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -q -T -b 0

%build
BUILD_VERSION=%{local_version} make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/sbin
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/%{name}.yaml 
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
#install -m 644 -D config/patterns/* -t %{buildroot}%{_sysconfdir}/crowdsec/patterns
#install -m 644 -D config/config.yaml %{buildroot}%{_sysconfdir}/crowdsec

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
%{_unitdir}/%{name}.service


%post -p /bin/bash



 
%changelog
* Tue Feb 16 2021 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging

%preun
systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"

%package iptables
Summary:      Firewall bouncer for Crowdsec (iptables configuration)
Requires: iptables,ipset,gettext
%description iptables

%files iptables
/etc/crowdsec/%{name}.yaml 

%package nftables
Summary:      Firewall bouncer for Crowdsec (nftables configuration)
Requires: nftables,gettext
%description nftables

%files nftables
/etc/crowdsec/%{name}.yaml 

%post -p /bin/bash iptables

systemctl daemon-reload


START=0

rpm -q crowdsec | grep -q ^ii >/dev/null

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
cp /etc/crowdsec/crowdsec-firewall-bouncer.yaml ${TMP}
BACKEND=iptables API_KEY=${API_KEY} envsubst < ${TMP} > /etc/crowdsec/crowdsec-firewall-bouncer.yaml
rm ${TMP}

if [ ${START} -eq 0 ] ; then
    echo "no api key was generated, won't start service"
else 
    systemctl start crowdsec-firewall-bouncer
fi


%post -p /bin/bash nftables

systemctl daemon-reload


START=0

rpm -q crowdsec | grep -q ^ii >/dev/null

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
cp /etc/crowdsec/crowdsec-firewall-bouncer.yaml ${TMP}
BACKEND=nftables API_KEY=${API_KEY} envsubst < ${TMP} > /etc/crowdsec/crowdsec-firewall-bouncer.yaml
rm ${TMP}

if [ ${START} -eq 0 ] ; then
    echo "no api key was generated, won't start service"
else 
    systemctl start crowdsec-firewall-bouncer
fi

