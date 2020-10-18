package main

import (
	"fmt"

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

func newBackend(backendType string) (*backendCTX, error) {
	var ok bool
	b := &backendCTX{}
	log.Printf("backend type : %s", backendType)
	switch backendType {
	case "iptables":
		tmpCtx, err := newIPTables()
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("interface iptables type is : %T", tmpCtx)
		}
	case "nftables":
		tmpCtx, err := newNFTables()
		if err != nil {
			return nil, err
		}
		b.firewall, ok = tmpCtx.(backend)
		if !ok {
			return nil, fmt.Errorf("interface nftables is : %T", tmpCtx)
		}
	default:
		return b, fmt.Errorf("firewall '%s' is not supported", backendType)
	}
	return b, nil
}
