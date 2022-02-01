package main

import (
	"fmt"
	"runtime"
	"time"

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
	buffered          bool
	bufferedDeletions map[string]*models.Decision
	bufferedAdditions map[string]*models.Decision
}

func (b *backendCTX) Init() error {
	err := b.firewall.Init()
	b.bufferedDeletions = make(map[string]*models.Decision)
	b.bufferedAdditions = make(map[string]*models.Decision)
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

	if b.buffered {
		if old, ok := b.bufferedAdditions[*decision.Value]; ok {
			// old decision exists
			timeout_old, err := time.ParseDuration(*old.Duration)
			timeout_new, err := time.ParseDuration(*decision.Duration)
			if err != nil {
				log.Errorf("unable to parse timeout '%s' for '%s' : %s", *decision.Duration, *decision.Value, err)
				timeout_new = defaultTimeout
			}
			if timeout_new > timeout_old {
				b.bufferedAdditions[*decision.Value] = decision
				log.Debugf("updating Add-decision for %s to %s", *decision.Value, *decision.Duration)
			}

		} else {
			_, err := time.ParseDuration(*decision.Duration)
			if err != nil {
				log.Errorf("unable to parse timeout '%s' for '%s' : %s", *decision.Duration, *decision.Value, err)
				*decision.Duration = defaultTimeout.String()
			}
			b.bufferedDecisions++ // only count unique decisions
			b.bufferedAdditions[*decision.Value] = decision
		}
		if err := b.sendBatch(); err != nil {
			return err
		}
	} else {
		if err := b.firewall.Add(decision); err != nil {
			return err
		}
	}
	return nil
}

func (b *backendCTX) Delete(decision *models.Decision) error {
	if b.buffered {
		if _, ok := b.bufferedDeletions[*decision.Value]; !ok {
			b.bufferedDecisions++ // only count unique decisions
		}
		b.bufferedDeletions[*decision.Value] = decision
		if err := b.sendBatch(); err != nil {
			return err
		}
	} else {
		if err := b.firewall.Delete(decision); err != nil {
			return err
		}
	}
	return nil
}

func (b *backendCTX) Commit() error {
	defer func() { b.bufferedDecisions = 0 }()

	if b.buffered {
		for _, decision := range b.bufferedDeletions {
			if err := b.firewall.Delete(decision); err != nil {
				return err
			}
		}

		for _, decision := range b.bufferedAdditions {
			if err := b.firewall.Add(decision); err != nil {
				return err
			}
		}

		nounDeleted := "decisions"
		if len(b.bufferedDeletions) == 1 {
			nounDeleted = "decision"
		}
		nounAdded := "decisions"
		if len(b.bufferedAdditions) == 1 {
			nounAdded = "decision"
		}

		log.Debugf("committing %d unique deleted %s and %d unique added %s", len(b.bufferedDeletions), nounDeleted, len(b.bufferedAdditions), nounAdded)
		b.bufferedDeletions = make(map[string]*models.Decision)
		b.bufferedAdditions = make(map[string]*models.Decision)

		if err := b.firewall.Commit(); err != nil {
			return err
		}
		log.Debugf("commit successful")
	}

	return nil
}

func (b *backendCTX) sendBatch() error {
	if b.buffered {
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
	b.buffered = false // Decision buffering disabled by default
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
		b.buffered = true // Decision buffering enabled
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
