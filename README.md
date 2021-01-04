<p align="center">
<img src="https://github.com/crowdsecurity/cs-firewall-bouncer/raw/main/docs/assets/crowdsec_linux_logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4DA; <a href="#installation">Documentation</a>
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>


# cs-firewall-bouncer
Crowdsec bouncer written in golang for firewalls.

cs-firewall-bouncer will fetch new and old decisions from a CrowdSec API to add them in a blocklist used by supported firewalls.

Supported firewalls:
 - iptables (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )
 - nftables (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )

## Installation

### Assisted

First, download the latest [`cs-firewall-bouncer` release](https://github.com/crowdsecurity/cs-firewall-bouncer/releases).

```sh
$ tar xzvf cs-firewall-bouncer.tgz
$ sudo ./install.sh
```

### From source

Run the following commands:

```bash
git clone https://github.com/crowdsecurity/cs-firewall-bouncer.git
cd cs-firewall-bouncer/
make release
tar xzvf cs-firewall-bouncer.tgz
cd cs-firewall-bouncer-v*/
sudo ./install.sh
```

## Upgrade

If you already have `cs-firewall-bouncer` installed, please download the [latest release](https://github.com/crowdsecurity/cs-firewall-bouncer/releases) and run the following commands:

```bash
tar xzvf cs-firewall-bouncer.tgz
cd cs-firewall-bouncer-v*/
sudo ./upgrade.sh
```


## Configuration

To be functional, the `cs-firewall-bouncer` service must be able to comunicate with the local API.
The `install.sh` script will take care of it (it will call `cscli bouncers add` on your behalf).
If it was not the case, the default configuration file is located under : `/etc/crowdsec/cs-firewall-bouncer/`

```sh
$ vim /etc/crowdsec/cs-firewall-bouncer/cs-firewall-bouncer.yaml
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
#if present, insert rule in those chains
iptables_chains:
  - INPUT
  - FORWARD
```

 - `mode` can be set to `iptables` or `nftables`
 - `update_frequency` controls how often the bouncer is going to query the local API
 - `api_url` and `api_key` control local API parameters.
 - `iptables_chains` allows (in _iptables_ mode) to control in which chain rules are going to be inserted. (if empty,the bouncer will only maintain ipset lists)

You can then start the service:

```sh
sudo systemctl start cs-firewall-bouncer
```

### iptables vs nftables

The bouncer supports two modes : `iptables` or `nftables`.
When using `nftables`, it doesn't directly rely on any available command, but rather on github.com/google/nftables.
When using `iptables`, it relies on `iptables` and `ipset` commands.






