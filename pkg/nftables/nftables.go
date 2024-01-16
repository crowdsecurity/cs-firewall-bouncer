//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
)

const (
	chunkSize      = 200
	defaultTimeout = "4h"
)

type nft struct {
	v4                *nftContext
	v6                *nftContext
	decisionsToAdd    []*models.Decision
	decisionsToDelete []*models.Decision
	DenyAction        string
	DenyLog           bool
	DenyLogPrefix     string
	Hooks             []string
}

func NewNFTables(config *cfg.BouncerConfig) (*nft, error) {
	ret := &nft{
		v4:            NewNFTV4Context(config),
		v6:            NewNFTV6Context(config),
		DenyAction:    config.DenyAction,
		DenyLog:       config.DenyLog,
		DenyLogPrefix: config.DenyLogPrefix,
		Hooks:         config.NftablesHooks,
	}

	return ret, nil
}

func (n *nft) Init() error {
	log.Debug("nftables: Init()")

	if err := n.v4.init(n.Hooks, n.DenyLog, n.DenyLogPrefix, n.DenyAction); err != nil {
		return err
	}

	if err := n.v6.init(n.Hooks, n.DenyLog, n.DenyLogPrefix, n.DenyAction); err != nil {
		return err
	}

	log.Infof("nftables initiated")

	return nil
}

func (n *nft) Add(decision *models.Decision) error {
	n.decisionsToAdd = append(n.decisionsToAdd, decision)
	return nil
}

func (n *nft) Set(decisions []*models.Decision) (added int, deleted int, err error) {
	banned, err := n.getBannedState()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get current state: %w", err)
	}

	// Map for fast lookup and decide what to add
	dm := map[string]*models.Decision{}
	for _, d := range decisions {
		dm[*d.Value] = d

		if _, ok := banned[*d.Value]; !ok {
			n.Add(d)
			added++
		}
	}

	// Check which we need to delete
	for ip, _ := range banned {
		if dm[ip] == nil {
			n.Delete(&models.Decision{
				Value: &ip,
			})

			deleted++
		}
	}

	return
}

func (n *nft) getBannedState() (map[string]struct{}, error) {
	banned := make(map[string]struct{})
	if err := n.v4.setBanned(banned); err != nil {
		return nil, err
	}

	if err := n.v6.setBanned(banned); err != nil {
		return nil, err
	}

	return banned, nil
}

func (n *nft) reset() {
	n.decisionsToAdd = make([]*models.Decision, 0)
	n.decisionsToDelete = make([]*models.Decision, 0)
}

func (n *nft) commitDeletedDecisions() error {
	banned, err := n.getBannedState()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := []nftables.SetElement{}
	ip6 := []nftables.SetElement{}

	for _, decision := range n.decisionsToDelete {
		ip := net.ParseIP(*decision.Value)
		if _, ok := banned[ip.String()]; !ok {
			log.Debugf("not deleting %s since it's not in the set", ip)
			continue
		}

		if strings.Contains(ip.String(), ":") {
			if n.v6.conn != nil {
				log.Tracef("adding %s to buffer", ip)

				ip6 = append(ip6, nftables.SetElement{Key: ip.To16()})
			}

			continue
		}

		if n.v4.conn != nil {
			log.Tracef("adding %s to buffer", ip)

			ip4 = append(ip4, nftables.SetElement{Key: ip.To4()})
		}
	}

	if len(ip4) > 0 {
		log.Debugf("removing %d ip%s elements from set", len(ip4), n.v4.version)

		if err := n.v4.deleteElements(ip4); err != nil {
			return err
		}
	}

	if len(ip6) > 0 {
		log.Debugf("removing %d ip%s elements from set", len(ip6), n.v6.version)

		if err := n.v6.deleteElements(ip6); err != nil {
			return err
		}
	}

	return nil
}

func (n *nft) commitAddedDecisions() error {
	banned, err := n.getBannedState()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := []nftables.SetElement{}
	ip6 := []nftables.SetElement{}

	n.decisionsToAdd = normalizedDecisions(n.decisionsToAdd)

	for _, decision := range n.decisionsToAdd {
		ip := net.ParseIP(*decision.Value)
		if _, ok := banned[ip.String()]; ok {
			log.Debugf("not adding %s since it's already in the set", ip)
			continue
		}

		t, _ := time.ParseDuration(*decision.Duration)

		if strings.Contains(ip.String(), ":") {
			if n.v6.conn != nil {
				log.Tracef("adding %s to buffer", ip)

				ip6 = append(ip6, nftables.SetElement{Timeout: t, Key: ip.To16()})
			}

			continue
		}

		if n.v4.conn != nil {
			log.Tracef("adding %s to buffer", ip)

			ip4 = append(ip4, nftables.SetElement{Timeout: t, Key: ip.To4()})
		}
	}

	if err := n.v4.addElements(ip4); err != nil {
		return err
	}

	if err := n.v6.addElements(ip6); err != nil {
		return err
	}

	return nil
}

func (n *nft) Commit() error {
	defer n.reset()

	if err := n.commitDeletedDecisions(); err != nil {
		return err
	}

	if err := n.commitAddedDecisions(); err != nil {
		return err
	}

	return nil
}

// remove duplicates, normalize decision timeouts, keep the longest decision when dups are present.
func normalizedDecisions(decisions []*models.Decision) []*models.Decision {
	vals := make(map[string]time.Duration)
	finalDecisions := make([]*models.Decision, 0)

	for _, d := range decisions {
		t, err := time.ParseDuration(*d.Duration)
		if err != nil {
			t, _ = time.ParseDuration(defaultTimeout)
		}

		*d.Value = strings.Split(*d.Value, "/")[0]
		vals[*d.Value] = maxTime(t, vals[*d.Value])
	}

	for ip, duration := range vals {
		d := duration.String()
		i := ip // copy it because we don't same value for all decisions as `ip` is same pointer :)

		finalDecisions = append(finalDecisions, &models.Decision{
			Duration: &d,
			Value:    &i,
		})
	}

	return finalDecisions
}

func (n *nft) Delete(decision *models.Decision) error {
	n.decisionsToDelete = append(n.decisionsToDelete, decision)
	return nil
}

func (n *nft) ShutDown() error {
	if err := n.v4.shutDown(); err != nil {
		return err
	}

	if err := n.v6.shutDown(); err != nil {
		return err
	}

	return nil
}

func maxTime(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}

	return b
}
