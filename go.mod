module github.com/crowdsecurity/cs-firewall-bouncer

go 1.14

require (
	github.com/antonmedv/expr v1.9.0 // indirect
	github.com/c-robinson/iplib v1.0.3 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/crowdsec v1.3.2
	github.com/crowdsecurity/go-cs-bouncer v0.0.0-20220316095558-5aef3b37e4fe
	github.com/go-openapi/loads v0.21.1 // indirect
	github.com/go-openapi/runtime v0.23.2 // indirect
	github.com/go-openapi/strfmt v0.21.2 // indirect
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/google/nftables v0.0.0-20220221214239-211824995dcb
	github.com/hashicorp/go-version v1.4.0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.2.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	go.mongodb.org/mongo-driver v1.8.4 // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
)

exclude github.com/mattn/go-sqlite3 v2.0.3+incompatible

exclude github.com/mattn/go-sqlite3 v2.0.1+incompatible

replace github.com/koneu/natend => ./koneu/natend
