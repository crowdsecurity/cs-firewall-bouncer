package main

import (
	"fmt"
	"runtime"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type backend interface {
	Init() error
	ShutDown() error
	Add(*models.Decision) error
	Delete(*models.Decision) error
	Commit() error
	CollectMetrics()
}

type backendCTX struct {
	firewall backend
}

func (b *backendCTX) Init() error {
	return b.firewall.Init()
}

func (b *backendCTX) Commit() error {
	return b.firewall.Commit()
}

func (b *backendCTX) ShutDown() error {
	return b.firewall.ShutDown()
}

func (b *backendCTX) Add(decision *models.Decision) error {
	return b.firewall.Add(decision)
}

func (b *backendCTX) Delete(decision *models.Decision) error {
	return b.firewall.Delete(decision)
}

func (b *backendCTX) CollectMetrics() {
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

func newBackend(config *bouncerConfig) (*backendCTX, error) {
	var err error

	b := &backendCTX{}
	log.Printf("backend type : %s", config.Mode)
	if config.DisableIPV6 {
		log.Println("IPV6 is disabled")
	}
	switch config.Mode {
	case IptablesMode, IpsetMode:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("iptables and ipset is linux only")
		}
		b.firewall, err = newIPTables(config)
		if err != nil {
			return nil, err
		}
	case NftablesMode:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("nftables is linux only")
		}
		b.firewall, err = newNFTables(config)
		if err != nil {
			return nil, err
		}
	case "pf":
		if !isPFSupported(runtime.GOOS) {
			log.Warning("pf mode can only work with openbsd and freebsd. It is available on other platforms only for testing purposes")
		}
		b.firewall, err = newPF(config)
		if err != nil {
			return nil, err
		}
	default:
		return b, fmt.Errorf("firewall '%s' is not supported", config.Mode)
	}
	return b, nil
}
