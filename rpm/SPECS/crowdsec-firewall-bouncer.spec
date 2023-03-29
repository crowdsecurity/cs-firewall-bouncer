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
BuildRequires:  make
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
before=$(cat config/%{name}.service)
echo "$before" | BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/bouncers/ envsubst '$BIN $CFG' > config/%{name}.service

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_presetdir}
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
mkdir -p %{buildroot}/etc/crowdsec/bouncers
BACKEND=$(echo %{name} | sed 's/crowdsec-firewall-bouncer-//')
(umask 077; BACKEND=$BACKEND envsubst '$BACKEND' < config/%{name}.yaml > %{buildroot}/etc/crowdsec/bouncers/%{name}.yaml)
mkdir -p %{buildroot}/usr/lib/%{name}
install -m 700 -D config/helper.sh %{buildroot}/usr/lib/%{name}/
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -m 644 -D %{SOURCE1} %{buildroot}%{_presetdir}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
/usr/lib/%{name}/helper.sh
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml
%config(noreplace) %{_presetdir}/80-crowdsec-firewall-bouncer.preset

%post -p /bin/sh
systemctl daemon-reload

BOUNCER="crowdsec-firewall-bouncer"
CONFIG="/etc/crowdsec/bouncers/$BOUNCER.yaml"
SERVICE="$BOUNCER.service"

helper="/usr/lib/%{name}/helper.sh"
START=1

if [ "$1" = "1" ]; then
    if $helper need-api-key "$CONFIG"; then
        if ! $helper set-api-key "$CONFIG" "FirewallBouncer"; then
            START=0
        fi
    fi
fi

%systemd_post crowdsec-firewall-bouncer.service

$helper set-local-port "$CONFIG"

if [ "$START" -eq 0 ]; then
    echo "no api key was generated, won't start the service" >&2
else
    %if 0%{?fc35}
    systemctl enable "$SERVICE"
    %endif
    systemctl start "$SERVICE"
fi

%changelog
* Tue Feb 16 2021 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging

%package -n crowdsec-firewall-bouncer-nftables
Summary:  Firewall bouncer for Crowdsec (nftables configuration)
Requires: nftables,gettext

%description -n crowdsec-firewall-bouncer-nftables

%preun -p /bin/sh
if [ "$1" = "0" ]; then
    systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"
fi

%postun -p /bin/sh
BOUNCER="crowdsec-firewall-bouncer"
CONFIG="/etc/crowdsec/bouncers/$BOUNCER.yaml"

if [ "$1" == "0" ]; then
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" 2>/dev/null || true
        rm -f "$CONFIG.id"
    fi
else
    systemctl restart crowdsec-firewall-bouncer || echo "cannot restart service"
fi
