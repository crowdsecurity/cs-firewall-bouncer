module github.com/crowdsecurity/cs-firewall-bouncer

go 1.14

require (
	github.com/ahmetb/dlog v0.0.0-20170105205344-4fb5f8204f26 // indirect
	github.com/antonmedv/expr v1.9.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/crowdsec v1.2.2
	github.com/crowdsecurity/go-cs-bouncer v0.0.0-20211102140123-4cf1e1b3f89b
	github.com/crowdsecurity/grokky v0.0.0-20210908140943-c4460be565eb // indirect
	github.com/go-openapi/analysis v0.21.1 // indirect
	github.com/go-openapi/runtime v0.21.0 // indirect
	github.com/go-playground/validator/v10 v10.4.1
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/google/nftables v0.0.0-20210916140115-16a134723a96
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/logrusorgru/grokky v0.0.0-20180829062225-47edf017d42c // indirect
	github.com/mdlayher/netlink v1.4.1 // indirect
	github.com/mdlayher/socket v0.0.0-20211007213009-516dcbdf0267 // indirect
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	golang.org/x/net v0.0.0-20211101193420-4a448f8816b3 // indirect
	golang.org/x/sys v0.0.0-20211102061401-a2f17f7b995c
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
)

exclude github.com/mattn/go-sqlite3 v2.0.3+incompatible

exclude github.com/mattn/go-sqlite3 v2.0.1+incompatible
