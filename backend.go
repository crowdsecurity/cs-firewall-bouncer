package main

import (
	"fmt"
	"runtime"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

const defaultBatch = 1000

type backend interface {
	Init() error
	ShutDown() error
	Add(*models.Decision) error
	Delete(*models.Decision) error
	Commit() error
}

type backendCTX struct {
	firewall          backend
	bufferedDecisions int
	buffering         bool
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
	if b.buffering {
		if err := b.sendBatch(); err != nil {
			return err
		}
	}
	return nil
}

func (b *backendCTX) Delete(decision *models.Decision) error {
	if err := b.firewall.Delete(decision); err != nil {
		return err
	}
	if b.buffering {
		if err := b.sendBatch(); err != nil {
			return err
		}
	}
	return nil
}

func (b *backendCTX) Commit() error {
	defer func() { b.bufferedDecisions = 0 }()

	if err := b.firewall.Commit(); err != nil {
		return err
	}
	if b.buffering {
		log.Debugf("committed %d decisions", b.bufferedDecisions)
	}
	return nil
}

func (b *backendCTX) sendBatch() error {
	if b.buffering {
		b.bufferedDecisions++
		if b.bufferedDecisions == defaultBatch {
			if err := b.Commit(); err != nil {
				return err
			}
		}
	}
	return nil
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
	var ok bool

	b := &backendCTX{}
	b.bufferedDecisions = 0
	b.buffering = false // Decision buffering disabled by default
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
			return nil, fmt.Errorf("nftables is linux only")
		}
		tmpCtx, err := newNFTables(config)
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		b.buffering = true // Decision buffering enabled
		if !ok {
			return nil, fmt.Errorf("unexpected type '%T' for nftables context", tmpCtx)
		}
	case "pf":
		if !isPFSupported(runtime.GOOS) {
			return nil, fmt.Errorf("pf mode is supported only for openbsd and freebsd")
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
