package backend

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/iptables"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/nftables"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/pf"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

type BackendCTX struct {
	firewall types.Backend
}

func (b *BackendCTX) Init() error {
	return b.firewall.Init()
}

func (b *BackendCTX) Commit() error {
	return b.firewall.Commit()
}

func (b *BackendCTX) ShutDown() error {
	return b.firewall.ShutDown()
}

func (b *BackendCTX) Add(decision *models.Decision) error {
	return b.firewall.Add(decision)
}

func (b *BackendCTX) Delete(decision *models.Decision) error {
	return b.firewall.Delete(decision)
}

func (b *BackendCTX) CollectMetrics() {
	b.firewall.CollectMetrics()
}

func isPFSupported(runtimeOS string) bool {
	var supported bool

	switch runtimeOS {
	case "openbsd", "freebsd":
		supported = true
	default:
		supported = false
	}

	return supported
}

func NewBackend(config *cfg.BouncerConfig) (*BackendCTX, error) {
	var err error

	b := &BackendCTX{}
	log.Printf("backend type : %s", config.Mode)
	if config.DisableIPV6 {
		log.Println("IPV6 is disabled")
	}
	switch config.Mode {
	case cfg.IptablesMode, cfg.IpsetMode:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("iptables and ipset is linux only")
		}
		b.firewall, err = iptables.NewIPTables(config)
		if err != nil {
			return nil, err
		}
	case cfg.NftablesMode:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("nftables is linux only")
		}
		b.firewall, err = nftables.NewNFTables(config)
		if err != nil {
			return nil, err
		}
	case "pf":
		if !isPFSupported(runtime.GOOS) {
			log.Warning("pf mode can only work with openbsd and freebsd. It is available on other platforms only for testing purposes")
		}
		b.firewall, err = pf.NewPF(config)
		if err != nil {
			return nil, err
		}
	default:
		return b, fmt.Errorf("firewall '%s' is not supported", config.Mode)
	}
	return b, nil
}
