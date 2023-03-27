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
TMP=$(mktemp -p /tmp/)
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

%post -p /bin/sh

systemctl daemon-reload

BACKEND=iptables
CONFIG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

START=1

do_configure() {
    before=$(cat "$CONFIG")
    # shellcheck disable=SC2016
    after=$(envsubst '$BACKEND $API_KEY' < "$CONFIG")

    # are both BACKEND and API_KEY already set?
    if [ "$before" = "$after" ]; then
        return
    fi

    # if we can't set the key, the user will take care of it
    API_KEY="<API_KEY>"

    if command -v cscli >/dev/null; then
        echo "cscli/crowdsec is present, generating API key" >&2
        unique=$(date +%s)
        bouncer_id="FirewallBouncer-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        if [ $? -eq 1 ]; then
            echo "failed to create API token" >&2
            START=0
        else
            echo "API Key: ${API_KEY}" >&2
            echo "$bouncer_id" > "$CONFIG.id"
        fi
    else
        START=0
    fi

    # shellcheck disable=SC2016
    echo "$before" | BACKEND=$BACKEND API_KEY="$API_KEY" envsubst '$BACKEND $API_KEY' | install -m 0600 /dev/stdin "$CONFIG"
}

if [ "$1" = "configure" ]; then
    do_configure
fi

%systemd_post crowdsec-firewall-bouncer.service

if command -v cscli >/dev/null; then
    PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2)
    if [ "$PORT" != "" ]; then
       sed -i "s/localhost:8080/127.0.0.1:${PORT}/g" "$CONFIG"
       sed -i "s/127.0.0.1:8080/127.0.0.1:${PORT}/g" "$CONFIG"
    fi
fi

if [ "$START" -eq 0 ]; then
    echo "no api key was generated, won't start or enable the service" >&2
else
    %if 0%{?fc35}
    systemctl enable crowdsec-firewall-bouncer
    %endif
    systemctl start crowdsec-firewall-bouncer
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

%post -p /bin/sh -n crowdsec-firewall-bouncer-nftables

systemctl daemon-reload

BACKEND=nftables
CONFIG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

START=1

do_configure() {
    before=$(cat "$CONFIG")
    # shellcheck disable=SC2016
    after=$(envsubst '$BACKEND $API_KEY' < "$CONFIG")

    # are both BACKEND and API_KEY already set?
    if [ "$before" = "$after" ]; then
        return
    fi

    # if we can't set the key, the user will take care of it
    API_KEY="<API_KEY>"

    if command -v cscli >/dev/null; then
        echo "cscli/crowdsec is present, generating API key" >&2
        unique=$(date +%s)
        bouncer_id="FirewallBouncer-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        if [ $? -eq 1 ]; then
            echo "failed to create API token" >&2
            START=0
        else
            echo "API Key: ${API_KEY}" >&2
            echo "$bouncer_id" > "$CONFIG.id"
        fi
    else
        START=0
    fi

    # shellcheck disable=SC2016
    echo "$before" | BACKEND=$BACKEND API_KEY="$API_KEY" envsubst '$BACKEND $API_KEY' | install -m 0600 /dev/stdin "$CONFIG"
}

if [ "$1" = "configure" ]; then
    do_configure
fi

%systemd_post crowdsec-firewall-bouncer.service

if command -v cscli >/dev/null; then
    PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2)
    if [ "$PORT" != "" ]; then
       sed -i "s/localhost:8080/127.0.0.1:${PORT}/g" "$CONFIG"
       sed -i "s/127.0.0.1:8080/127.0.0.1:${PORT}/g" "$CONFIG"
    fi
fi

if [ "$START" -eq 0 ]; then
    echo "no api key was generated, won't start or enable the service" >&2
else
    %if 0%{?fc35}
    systemctl enable crowdsec-firewall-bouncer
    %endif
    systemctl start crowdsec-firewall-bouncer
fi

%preun -p /bin/sh

if [ "$1" = "0" ]; then
    systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"
fi

%preun -p /bin/sh -n crowdsec-firewall-bouncer-nftables

if [ "$1" = "0" ]; then
    systemctl stop crowdsec-firewall-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-firewall-bouncer || echo "cannot disable service"
fi


%postun -p /bin/sh

CONFIG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

if [ "$1" == "0" ]; then
    # If the bouncer ID was stored and wasn't deleted, try and unregister it from
    # the API, without failing if that doesn't work for some reason:
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" 2>/dev/null || true
        rm -f "$CONFIG.id"
    fi
else
    systemctl restart crowdsec-firewall-bouncer || echo "cannot restart service"
fi


%postun -p /bin/sh -n crowdsec-firewall-bouncer-nftables

CONFIG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

if [ "$1" == "0" ]; then
    # If the bouncer ID was stored and wasn't deleted, try and unregister it from
    # the API, without failing if that doesn't work for some reason:
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" 2>/dev/null || true
        rm -f "$CONFIG.id"
    fi
else
    systemctl restart crowdsec-firewall-bouncer || echo "cannot restart service"
fi

