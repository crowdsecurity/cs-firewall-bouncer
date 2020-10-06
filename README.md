# cs-firewall-bouncer
Crowdsec bouncer written in golang for firewalls.

firewall-bouncer will fetch new and old decisions from a CrowdSec API to add them in a blocklist used by supported firewalls.

Supported firewalls:
 - iptables (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )


## Installation

First, download the latest [`cs-firewall-bouncer` release](https://github.com/crowdsecurity/cs-firewall-bouncer/releases).

```sh
$ tar xzvf `cs-firewall-bouncer.tgz`
$ sudo ./install.sh
```

## Configuration

Before starting the `firewall-bouncer` service, please edit the configuration to add your API url and key.
The default configuration file is located under : `/etc/crowdsec/firewall-bouncer/`

```sh
$ vim /etc/crowdsec/firewall-bouncer/firewall-bouncer.yaml
```

```yaml
mode: iptables
piddir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: <API_URL>  # when install, default is "localhost:8080"
api_key: <API_KEY>  # Add your API key generated with `cscli bouncers add --name <bouncer_name>`
```

You can then start the service:

```sh
sudo systemctl start firewall-bouncer
```