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
}

type backendCTX struct {
	firewall backend
}

func (b *backendCTX) Init() error {
	err := b.firewall.Init()
	if err != nil {
		return err
	}
	return nil
}

func (b *backendCTX) ShutDown() error {
	err := b.firewall.ShutDown()
	if err != nil {
		return err
	}
	return nil
}

func (b *backendCTX) Add(decision *models.Decision) error {
	if err := b.firewall.Add(decision); err != nil {
		return err
	}
	return nil
}

func (b *backendCTX) Delete(decision *models.Decision) error {
	if err := b.firewall.Delete(decision); err != nil {
		return err
	}
	return nil
}

func newBackend(config *bouncerConfig) (*backendCTX, error) {
	var ok bool

	b := &backendCTX{}
	log.Printf("backend type : %s", config.Mode)
	if config.DisableIPV6 {
		log.Println("IPV6 is disabled")
	}
	switch config.Mode {
	case "iptables", "ipset":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("iptables and ipset is linux only")
		}
		tmpCtx, err := newIPTables(config)
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("unexpected type '%T' for iptables context", tmpCtx)
		}
	case "nftables":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("iptables and ipset is linux only")
		}
		tmpCtx, err := newNFTables(config)
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("unexpected type '%T' for nftables context", tmpCtx)
		}
	case "pf":
		if runtime.GOOS != "openbsd" {
			return nil, fmt.Errorf("pf is openbsd only")
		}
		tmpCtx, err := newPF(config)
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("unexpected type '%T' for pf context", tmpCtx)
		}
	default:
		return b, fmt.Errorf("firewall '%s' is not supported", config.Mode)
	}
	return b, nil
}
