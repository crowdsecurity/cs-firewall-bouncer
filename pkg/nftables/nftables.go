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
		// delete whole crowdsec table
		log.Infof("removing '%s' table", c.table.Name)
		c.conn.DelTable(c.table)
	}
	if err := c.conn.Flush(); err != nil {
		return err
	}
	return nil
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

func lookupTable(conn *nftables.Conn, tableName string) (*nftables.Table, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == tableName {
			return t, nil
		}
	}
	return nil, fmt.Errorf("nftables: could not find table '%s'", tableName)
}

func createRule(table *nftables.Table, chain *nftables.Chain, set *nftables.Set,
	denyLog bool, denyLogPrefix string, denyAction string, offset uint32, length uint32) *nftables.Rule {
	r := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{},
	}
	// [ payload load 4b @ network header + 16 => reg 1 ]
	r.Exprs = append(r.Exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
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
	var err error
	log.Debug("nftables: Init()")
	/* ip4 */
	if n.v4.conn != nil {
		log.Debug("nftables: ipv4 init starting")
		if n.v4.setOnly {
			// Use to existing nftables configuration
			log.Debug("nftables: ipv4 set-only")
			n.v4.table, err = lookupTable(n.v4.conn, n.v4.tableName)
			if err != nil {
				return err
			}

			set, err := n.v4.conn.GetSetByName(n.v4.table, n.v4.blacklists)
			if err != nil {
				log.Debugf("nftables: could not find ipv4 blacklist '%s' in table '%s': creating...", n.v4.blacklists, n.v4.tableName)
				set = &nftables.Set{
					Name:       n.v4.blacklists,
					Table:      n.v4.table,
					KeyType:    nftables.TypeIPAddr,
					HasTimeout: true,
				}

				if err := n.v4.conn.AddSet(set, []nftables.SetElement{}); err != nil {
					return err
				}
				if err := n.v4.conn.Flush(); err != nil {
					return err
				}
			}
			n.v4.set = set
			log.Debug("nftables: ipv4 set '" + n.v4.blacklists + "' configured")
		} else { // Create crowdsec table,chain, blacklist set and rules
			log.Debug("nftables: ipv4 own table")
			table := &nftables.Table{
				Family: n.v4.tableFamily,
				Name:   n.v4.tableName,
			}
			n.v4.table = n.v4.conn.AddTable(table)

			set := &nftables.Set{
				Name:       n.v4.blacklists,
				Table:      n.v4.table,
				KeyType:    nftables.TypeIPAddr,
				HasTimeout: true,
			}

			if err := n.v4.conn.AddSet(set, []nftables.SetElement{}); err != nil {
				return err
			}
			n.v4.set = set

			for _, hook := range n.Hooks {
				chain := n.v4.conn.AddChain(&nftables.Chain{
					Name:     n.v4.chainName + "-" + hook,
					Table:    n.v4.table,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  HookNameToHookID[hook],
					Priority: nftables.ChainPriority(n.v4.priority),
				})

				r := createRule(n.v4.table, chain, set, n.DenyLog, n.DenyLogPrefix, n.DenyAction, n.v4.payloadOffset, n.v4.payloadLength)
				n.v4.conn.AddRule(r)
			}

			if err := n.v4.conn.Flush(); err != nil {
				return err
			}
			log.Debug("nftables: ipv4 table created")
		} // IPv4 set-only
	} // IPv4

	/* ipv6 */
	if n.v6.conn != nil {
		if n.v6.setOnly {
			// Use to existing nftables configuration
			log.Debug("nftables: ipv4 set-only")
			n.v6.table, err = lookupTable(n.v6.conn, n.v6.tableName)
			if err != nil {
				return err
			}

			set, err := n.v6.conn.GetSetByName(n.v6.table, n.v6.blacklists)
			if err != nil {
				return err
			}
			n.v6.set = set
			log.Debug("nftables: ipv6 set '" + n.v6.blacklists + "' configured")
		} else {
			log.Debug("nftables: ipv6 own table")
			table := &nftables.Table{
				Family: n.v6.tableFamily,
				Name:   n.v6.tableName,
			}
			n.v6.table = n.v6.conn.AddTable(table)

			set := &nftables.Set{
				Name:       n.v6.blacklists,
				Table:      n.v6.table,
				KeyType:    nftables.TypeIP6Addr,
				HasTimeout: true,
			}

			if err := n.v6.conn.AddSet(set, []nftables.SetElement{}); err != nil {
				return err
			}
			n.v6.set = set

			for _, hook := range n.Hooks {
				chain := n.v6.conn.AddChain(&nftables.Chain{
					Name:     n.v6.chainName + "-" + hook,
					Table:    n.v6.table,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  HookNameToHookID[hook],
					Priority: nftables.ChainPriority(n.v6.priority),
				})

				r := createRule(n.v6.table, chain, set, n.DenyLog, n.DenyLogPrefix, n.DenyAction, n.v6.payloadOffset, n.v6.payloadLength)
				n.v6.conn.AddRule(r)
			}
			if err := n.v6.conn.Flush(); err != nil {
				return err
			}
			log.Debug("nftables: ipv6 table created")
		}
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
