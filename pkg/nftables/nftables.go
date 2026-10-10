//go:build linux

package nftables

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/iputils"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/state"
)

const (
	chunkSize      = 200
	defaultTimeout = 4 * time.Hour
	// Elements expiring sooner than this are always left out to avoid racing
	// with the kernel.
	minTimeout = time.Second
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
	ranges            bool
}

func NewNFTables(config *cfg.BouncerConfig) (*nft, error) {
	ret := &nft{
		v4:            NewNFTV4Context(config),
		v6:            NewNFTV6Context(config),
		DenyAction:    config.DenyAction,
		DenyLog:       config.DenyLog,
		DenyLogPrefix: config.DenyLogPrefix,
		Hooks:         config.NftablesHooks,
		ranges:        config.Nftables.EnableExperimentalRanges,
	}

	return ret, nil
}

func (n *nft) Init() error {
	log.Debug("nftables: Init()")

	if err := n.v4.init(n.Hooks); err != nil {
		return err
	}

	if err := n.v6.init(n.Hooks); err != nil {
		return err
	}

	log.Infof("nftables initiated")

	return nil
}

func (n *nft) Add(decision *models.Decision) error {
	n.decisionsToAdd = append(n.decisionsToAdd, decision)
	return nil
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

	n.decisionsToDelete = normalizedDecisions(n.decisionsToDelete)

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

func (n *nft) createSetAndRuleForOrigin(ctx *nftContext, origin string) error {
	if _, ok := ctx.sets[origin]; !ok {
		// First time we see this origin, create the rule/set for all hooks
		set := &nftables.Set{
			Name:         fmt.Sprintf("%s-%s", ctx.blacklists, origin),
			Table:        ctx.table,
			KeyType:      ctx.typeIPAddr,
			KeyByteOrder: binaryutil.BigEndian,
			HasTimeout:   true,
			Interval:     ctx.ranges,
		}

		ctx.sets[origin] = set
		if ctx.ranges {
			ctx.setsState[origin] = state.New(state.Options{
				DefaultExpiration: defaultTimeout,
				BatchSize:         chunkSize,
			})
		}

		if err := ctx.conn.AddSet(set, []nftables.SetElement{}); err != nil {
			return err
		}

		for _, chain := range ctx.chains {
			rule, err := ctx.createRule(chain, set, n.DenyLog, n.DenyLogPrefix, n.DenyAction)
			if err != nil {
				return err
			}

			ctx.conn.AddRule(rule)
			log.Infof("Created set and rule for origin %s and type %s in chain %s", origin, ctx.typeIPAddr.Name, chain.Name)
		}
	}

	return nil
}

func (n *nft) commitAddedDecisions() error {
	banned, err := n.getBannedState()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := make(map[string][]nftables.SetElement, 0)
	ip6 := make(map[string][]nftables.SetElement, 0)

	n.decisionsToAdd = normalizedDecisions(n.decisionsToAdd)

	for _, decision := range n.decisionsToAdd {
		ip := net.ParseIP(*decision.Value)
		if _, ok := banned[ip.String()]; ok {
			log.Debugf("not adding %s since it's already in the set", ip)
			continue
		}

		t, _ := time.ParseDuration(*decision.Duration)

		origin := *decision.Origin

		if origin == "lists" {
			origin = origin + "-" + *decision.Scenario
		}

		if strings.Contains(ip.String(), ":") {
			if n.v6.conn != nil {
				if n.v6.setOnly {
					origin = n.v6.blacklists
				}

				log.Tracef("adding %s to buffer", ip)

				if _, ok := ip6[origin]; !ok {
					ip6[origin] = make([]nftables.SetElement, 0)
				}

				ip6[origin] = append(ip6[origin], nftables.SetElement{Timeout: t, Key: ip.To16()})

				if !n.v6.setOnly {
					err := n.createSetAndRuleForOrigin(n.v6, origin)
					if err != nil {
						return err
					}
				}
			}

			continue
		}

		if n.v4.conn != nil {
			if n.v4.setOnly {
				origin = n.v4.blacklists
			}

			log.Tracef("adding %s to buffer", ip)

			if _, ok := ip4[origin]; !ok {
				ip4[origin] = make([]nftables.SetElement, 0)
			}

			ip4[origin] = append(ip4[origin], nftables.SetElement{Timeout: t, Key: ip.To4()})

			if !n.v4.setOnly {
				err := n.createSetAndRuleForOrigin(n.v4, origin)
				if err != nil {
					return err
				}
			}
		}
	}

	if err := n.v4.addElements(ip4); err != nil {
		return err
	}

	return n.v6.addElements(ip6)
}

func (n *nft) Commit() error {
	defer n.reset()

	if n.ranges {
		return n.commitWithState()
	}

	if err := n.commitDeletedDecisions(); err != nil {
		return err
	}

	return n.commitAddedDecisions()
}

// contextFor returns the context handling a decision, or nil when the
// corresponding address family is disabled.
func (n *nft) contextFor(decision *models.Decision) *nftContext {
	// An IPv4 address can be written in the IPv6 notation, so the family
	// comes from the parsed address and not from the text.
	rng, err := iputils.ParseIPRange(*decision.Value)

	ctx := n.v4
	if err == nil && rng.First.Is6() {
		ctx = n.v6
	}

	if ctx.conn == nil {
		return nil
	}

	return ctx
}

func (n *nft) deleteDecisionFromState(decision *models.Decision) {
	ctx := n.contextFor(decision)
	if ctx == nil {
		return
	}

	origin := ctx.originFor(decision)

	setState, ok := ctx.setsState[origin]
	if !ok {
		log.Debugf("not deleting %s, no set for origin %s", *decision.Value, origin)
		return
	}

	if err := setState.Delete(decision); err != nil {
		log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
	}
}

func (n *nft) addDecisionToState(decision *models.Decision) error {
	ctx := n.contextFor(decision)
	if ctx == nil {
		return nil
	}

	origin := ctx.originFor(decision)

	if !ctx.setOnly {
		if err := n.createSetAndRuleForOrigin(ctx, origin); err != nil {
			return err
		}
	}

	log.Tracef("adding %s to buffer", *decision.Value)

	if err := ctx.setsState[origin].Insert(decision); err != nil {
		log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
	}

	return nil
}

// commitWithState mirrors the decisions into the state and submits the changes
// to the kernel.
func (n *nft) commitWithState() error {
	for _, decision := range n.decisionsToDelete {
		n.deleteDecisionFromState(decision)
	}

	for _, decision := range n.decisionsToAdd {
		if err := n.addDecisionToState(decision); err != nil {
			return err
		}
	}

	if err := n.v4.applyState(); err != nil {
		return err
	}

	return n.v6.applyState()
}

type tmpDecisions struct {
	duration time.Duration
	origin   string
	scenario string
}

// remove duplicates, normalize decision timeouts, keep the longest decision when dups are present.
func normalizedDecisions(decisions []*models.Decision) []*models.Decision {
	vals := make(map[string]tmpDecisions)
	finalDecisions := make([]*models.Decision, 0)

	for _, d := range decisions {
		t, err := time.ParseDuration(*d.Duration)
		if err != nil {
			t = defaultTimeout
		}

		*d.Value = strings.Split(*d.Value, "/")[0]
		if longest, ok := vals[*d.Value]; !ok || t > longest.duration {
			vals[*d.Value] = tmpDecisions{
				duration: t,
				origin:   *d.Origin,
				scenario: *d.Scenario,
			}
		}
	}

	for ip, decision := range vals {
		d := decision.duration.String()
		i := ip // copy it because we don't same value for all decisions as `ip` is same pointer :)
		origin := decision.origin
		scenario := decision.scenario

		finalDecisions = append(finalDecisions, &models.Decision{
			Duration: &d,
			Value:    &i,
			Origin:   &origin,
			Scenario: &scenario,
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

	return n.v6.shutDown()
}
