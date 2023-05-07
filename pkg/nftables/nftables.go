//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/slicetools"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

const (
	chunkSize      = 200
	defaultTimeout = "4h"
)

var HookNameToHookID = map[string]nftables.ChainHook{
	"prerouting":  nftables.ChainHookPrerouting,
	"input":       nftables.ChainHookInput,
	"forward":     nftables.ChainHookForward,
	"output":      nftables.ChainHookOutput,
	"postrouting": nftables.ChainHookPostrouting,
	"ingress":     nftables.ChainHookIngress,
}

type nftContext struct {
	conn          *nftables.Conn
	set           *nftables.Set
	table         *nftables.Table
	tableFamily   nftables.TableFamily
	ipVersion     string
	payloadOffset uint32
	payloadLength uint32
	priority      int
	blacklists    string
	chainName     string
	tableName     string
	setOnly       bool
}

func (c *nftContext) shutDown() error {
	if c.conn == nil {
		return nil
	}
	if c.setOnly {
		// Flush blacklist4 set empty
		log.Infof("flushing '%s' set in '%s' table", c.set.Name, c.table.Name)
		c.conn.FlushSet(c.set)
	} else {
		log.Infof("removing '%s' table", c.table.Name)
		c.conn.DelTable(c.table)
	}
	if err := c.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (c *nftContext) initSetOnly() error {
	// Use to existing nftables configuration
	log.Debugf("nftables: %s set-only", c.ipVersion)
	var err error
	c.table, err = c.lookupTable()
	if err != nil {
		return err
	}

	set, err := c.conn.GetSetByName(c.table, c.blacklists)
	if err != nil {
		log.Debugf("nftables: could not find %s blacklist '%s' in table '%s': creating...", c.ipVersion, c.blacklists, c.tableName)
		set = &nftables.Set{
			Name:       c.blacklists,
			Table:      c.table,
			KeyType:    nftables.TypeIPAddr,
			HasTimeout: true,
		}

		if err := c.conn.AddSet(set, []nftables.SetElement{}); err != nil {
			return err
		}
		if err := c.conn.Flush(); err != nil {
			return err
		}
	}
	c.set = set
	log.Debugf("nftables: %s set '%s' configured", c.ipVersion, c.blacklists)

	return nil
}

func (c *nftContext) initOwnTable(hooks []string, denyLog bool, denyLogPrefix string, denyAction string) error {
	log.Debugf("nftables: %s own table", c.ipVersion)
	table := &nftables.Table{
		Family: c.tableFamily,
		Name:   c.tableName,
	}
	c.table = c.conn.AddTable(table)

	set := &nftables.Set{
		Name:       c.blacklists,
		Table:      c.table,
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true,
	}

	if err := c.conn.AddSet(set, []nftables.SetElement{}); err != nil {
		return err
	}
	c.set = set

	for _, hook := range hooks {
		chain := c.conn.AddChain(&nftables.Chain{
			Name:     c.chainName + "-" + hook,
			Table:    c.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  HookNameToHookID[hook],
			Priority: nftables.ChainPriority(c.priority),
		})

		r := c.createRule(chain, set, denyLog, denyLogPrefix, denyAction)
		c.conn.AddRule(r)
	}

	if err := c.conn.Flush(); err != nil {
		return err
	}
	log.Debugf("nftables: %s table created", c.ipVersion)
	return nil
}

func (c *nftContext) init(hooks []string, denyLog bool, denyLogPrefix string, denyAction string) error {
	if c.conn == nil {
		return nil
	}

	log.Debugf("nftables: %s init starting", c.ipVersion)

	if c.setOnly {
		return c.initSetOnly()
	}
	return c.initOwnTable(hooks, denyLog, denyLogPrefix, denyAction)
}

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

func NewNFTables(config *cfg.BouncerConfig) (types.Backend, error) {
	ret := &nft{}

	if *config.Nftables.Ipv4.Enabled {
		log.Debug("nftables: ipv4 enabled")
		ret.v4.conn = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv4 disabled")
	}
	if *config.Nftables.Ipv6.Enabled {
		log.Debug("nftables: ipv6 enabled")
		ret.v6.conn = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv6 disabled")
	}
	ret.DenyAction = config.DenyAction
	ret.DenyLog = config.DenyLog
	ret.DenyLogPrefix = config.DenyLogPrefix
	ret.Hooks = config.NftablesHooks

	ret.v4.ipVersion = "ipv4"
	ret.v4.tableFamily = nftables.TableFamilyIPv4
	ret.v4.payloadOffset = 12
	ret.v4.payloadOffset = 4
	ret.v4.tableName = config.Nftables.Ipv4.Table
	ret.v4.chainName = config.Nftables.Ipv4.Chain
	ret.v4.blacklists = config.BlacklistsIpv4
	ret.v4.setOnly = config.Nftables.Ipv4.SetOnly
	ret.v4.priority = config.Nftables.Ipv4.Priority
	log.Debugf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		*config.Nftables.Ipv4.Enabled, ret.v4.tableName, ret.v4.chainName, ret.v4.blacklists, ret.v4.setOnly)

	ret.v4.ipVersion = "ipv6"
	ret.v4.tableFamily = nftables.TableFamilyIPv6
	ret.v6.payloadOffset = 8
	ret.v6.payloadOffset = 16
	ret.v6.tableName = config.Nftables.Ipv6.Table
	ret.v6.chainName = config.Nftables.Ipv6.Chain
	ret.v6.blacklists = config.BlacklistsIpv6
	ret.v6.setOnly = config.Nftables.Ipv6.SetOnly
	ret.v6.priority = config.Nftables.Ipv6.Priority
	log.Debugf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		*config.Nftables.Ipv6.Enabled, ret.v6.tableName, ret.v6.chainName, ret.v6.blacklists, ret.v6.setOnly)

	return ret, nil
}

func (c *nftContext) lookupTable() (*nftables.Table, error) {
	tables, err := c.conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == c.tableName {
			return t, nil
		}
	}
	return nil, fmt.Errorf("nftables: could not find table '%s'", c.tableName)
}

func (c *nftContext) createRule(chain *nftables.Chain, set *nftables.Set,
	denyLog bool, denyLogPrefix string, denyAction string) *nftables.Rule {
	r := &nftables.Rule{
		Table: c.table,
		Chain: chain,
		Exprs: []expr.Any{},
	}
	// [ payload load 4b @ network header + 16 => reg 1 ]
	r.Exprs = append(r.Exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       c.payloadOffset,
		Len:          c.payloadLength,
	})
	// [ lookup reg 1 set whitelist ]
	r.Exprs = append(r.Exprs, &expr.Lookup{
		SourceRegister: 1,
		SetName:        set.Name,
		SetID:          set.ID,
	})

	r.Exprs = append(r.Exprs, &expr.Counter{})

	if denyLog {
		r.Exprs = append(r.Exprs, &expr.Log{
			Key:  1 << unix.NFTA_LOG_PREFIX,
			Data: []byte(denyLogPrefix),
		})
	}
	if strings.EqualFold(denyAction, "REJECT") {
		r.Exprs = append(r.Exprs, &expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
		})
	} else {
		r.Exprs = append(r.Exprs, &expr.Verdict{
			Kind: expr.VerdictDrop,
		})
	}
	return r
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

func (n *nft) bannedSet() (map[string]struct{}, error) {
	state := make(map[string]struct{})

	if n.v4.conn != nil {
		elements, err := n.v4.conn.GetSetElements(n.v4.set)
		if err != nil {
			return nil, err
		}
		for _, el := range elements {
			state[net.IP(el.Key).String()] = struct{}{}
		}
	}

	if n.v6.conn != nil {
		elements, err := n.v6.conn.GetSetElements(n.v6.set)
		if err != nil {
			return nil, err
		}
		for _, el := range elements {
			state[net.IP(el.Key).String()] = struct{}{}
		}
	}

	return state, nil
}

func (n *nft) reset() {
	n.decisionsToAdd = make([]*models.Decision, 0)
	n.decisionsToDelete = make([]*models.Decision, 0)
}

func (n *nft) commitDeletedDecisions() error {
	banned, err := n.bannedSet()
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
				ip6 = append(ip6, nftables.SetElement{Key: ip.To16()})
				log.Tracef("adding %s to buffer", ip)
			}
			continue
		}
		if n.v4.conn != nil {
			ip4 = append(ip4, nftables.SetElement{Key: ip.To4()})
			log.Tracef("adding %s to buffer", ip)
		}
	}

	for _, chunk := range slicetools.Chunks(ip4, chunkSize) {
		log.Debugf("removing %d ipv4 elements from set", len(chunk))
		if err := n.v4.conn.SetDeleteElements(n.v4.set, chunk); err != nil {
			return fmt.Errorf("failed to remove ipv4 elements from set: %w", err)
		}
		if err := n.v4.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv4 conn: %w", err)
		}
	}

	for _, chunk := range slicetools.Chunks(ip6, chunkSize) {
		log.Debugf("removing %d ipv6 elements from set", len(chunk))
		if err := n.v6.conn.SetDeleteElements(n.v6.set, chunk); err != nil {
			return fmt.Errorf("failed to remove ipv6 elements from set: %w", err)
		}
		if err := n.v6.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv6 conn: %w", err)
		}
	}

	return nil
}

func (n *nft) commitAddedDecisions() error {
	banned, err := n.bannedSet()
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	ip4 := []nftables.SetElement{}
	elements6 := []nftables.SetElement{}

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
				elements6 = append(elements6, nftables.SetElement{Timeout: t, Key: ip.To16()})
				log.Tracef("adding %s to buffer", ip)
			}
			continue
		}
		if n.v4.conn != nil {
			ip4 = append(ip4, nftables.SetElement{Timeout: t, Key: ip.To4()})
			log.Tracef("adding %s to buffer", ip)
		}
	}

	for _, chunk := range slicetools.Chunks(ip4, chunkSize) {
		log.Debugf("adding %d ipv4 elements to set", len(chunk))
		if err := n.v4.conn.SetAddElements(n.v4.set, chunk); err != nil {
			return fmt.Errorf("failed to add ipv4 elements to set: %w", err)
		}
		if err := n.v4.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv4 conn: %w", err)
		}
	}

	for _, chunk := range slicetools.Chunks(elements6, chunkSize) {
		log.Debugf("adding %d ipv6 elements to set", len(chunk))
		if err := n.v6.conn.SetAddElements(n.v6.set, chunk); err != nil {
			return fmt.Errorf("failed to add ipv6 elements to set: %w", err)
		}
		if err := n.v6.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv6 conn: %w", err)
		}
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
	// continue here
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
