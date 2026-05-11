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

## Profiling

On-demand Go **pprof** endpoints and optional automatic heap dumps are controlled only by environment variables (no YAML changes). The pprof server uses a separate listener from Prometheus so routes are not mixed with `/metrics`.

| Variable | Meaning |
|----------|---------|
| `CS_PROFILING_ENABLED` | When set to `true`, starts the pprof HTTP server. |
| `CS_PROFILING_ADDR` | Listen address for pprof (default `:6060`). |
| `CS_PROFILING_HEAP_DUMP_DIR` | If set to a non-empty path, runs a background watcher that can write heap profiles to this directory when memory is high. Independent of `CS_PROFILING_ENABLED`. |
| `CS_PROFILING_HEAP_DUMP_THRESHOLD_MB` | Heap allocation threshold in mebibytes before a dump (default `200`). |
| `CS_PROFILING_HEAP_POLL_INTERVAL` | How often heap use is checked, as a Go duration (default `30s`). |
| `CS_PROFILING_HEAP_DUMP_COOLDOWN` | Minimum time between successful heap dumps, as a Go duration (default `5m`). |

For garbage-collection tracing, set **`GODEBUG=gctrace=1`** in the container environment before the process starts (the Go runtime reads this at startup).

Protect the pprof port with network policy or bind to loopback only (`127.0.0.1:6060`) where appropriate; profiling endpoints expose sensitive in-process data.

# Installation

Please follow the [official documentation](https://doc.crowdsec.net/docs/bouncers/firewall).
