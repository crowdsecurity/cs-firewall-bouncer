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


# crowdsec-firewall-bouncer
Crowdsec bouncer written in golang for firewalls.

crowdsec-firewall-bouncer will fetch new and old decisions from a CrowdSec API to add them in a blocklist used by supported firewalls.

Supported firewalls:
 - iptables (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )
 - nftables (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )
 - ipset only (IPv4 :heavy_check_mark: / IPv6 :heavy_check_mark: )
 - pf (IPV4 :heavy_check_mark: / IPV6 :heavy_check_mark: )

# Installation

Please follow the [official documentation](https://doc.crowdsec.net/docs/bouncers/firewall).
