module github.com/crowdsecurity/cs-firewall-bouncer

go 1.14

require (
	github.com/antonmedv/expr v1.9.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/crowdsec v1.4.1
	github.com/crowdsecurity/go-cs-bouncer v0.0.0-20220817075151-29237cbe9873
	github.com/crowdsecurity/grokky v0.1.0 // indirect
	github.com/go-bindata/go-bindata v1.0.1-0.20190711162640-ee3c2418e368 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-openapi/runtime v0.21.1 // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/google/nftables v0.0.0-20220808154552-2eca00135732
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.2.3 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.13.0
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/sys v0.0.0-20220817070843-5a390386f1f2
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
)

exclude github.com/mattn/go-sqlite3 v2.0.3+incompatible

exclude github.com/mattn/go-sqlite3 v2.0.1+incompatible

replace github.com/koneu/natend => ./koneu/natend
