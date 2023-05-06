//go:build linux
// +build linux

package nftables

import (
	"errors"
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
	chunkSize = 200
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

type nft struct {
	conn              *nftables.Conn
	conn6             *nftables.Conn
	set               *nftables.Set
	set6              *nftables.Set
	table             *nftables.Table
	table6            *nftables.Table
	priority          int
	priority6         int
	decisionsToAdd    []*models.Decision
	decisionsToDelete []*models.Decision
	DenyAction        string
	DenyLog           bool
	DenyLogPrefix     string
	BlacklistsIpv4    string
	BlacklistsIpv6    string
	ChainName4        string
	TableName4        string
	SetOnly4          bool
	ChainName6        string
	TableName6        string
	SetOnly6          bool
	Hooks             []string
}

func NewNFTables(config *cfg.BouncerConfig) (types.Backend, error) {
	ret := &nft{}

	if *config.Nftables.Ipv4.Enabled {
		log.Debug("nftables: ipv4 enabled")
		ret.conn = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv4 disabled")
	}
	if *config.Nftables.Ipv6.Enabled {
		log.Debug("nftables: ipv6 enabled")
		ret.conn6 = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv6 disabled")
	}
	ret.DenyAction = config.DenyAction
	ret.DenyLog = config.DenyLog
	ret.DenyLogPrefix = config.DenyLogPrefix
	ret.Hooks = config.NftablesHooks

	// IPv4
	ret.TableName4 = config.Nftables.Ipv4.Table
	ret.ChainName4 = config.Nftables.Ipv4.Chain
	ret.BlacklistsIpv4 = config.BlacklistsIpv4
	ret.SetOnly4 = config.Nftables.Ipv4.SetOnly
	ret.priority = config.Nftables.Ipv4.Priority
	log.Debugf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		*config.Nftables.Ipv4.Enabled, ret.TableName4, ret.ChainName4, ret.BlacklistsIpv4, ret.SetOnly4)

	// IPv6
	ret.TableName6 = config.Nftables.Ipv6.Table
	ret.ChainName6 = config.Nftables.Ipv6.Chain
	ret.BlacklistsIpv6 = config.BlacklistsIpv6
	ret.SetOnly6 = config.Nftables.Ipv6.SetOnly
	ret.priority6 = config.Nftables.Ipv6.Priority
	log.Debugf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		*config.Nftables.Ipv6.Enabled, ret.TableName6, ret.ChainName6, ret.BlacklistsIpv6, ret.SetOnly6)

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



func (n *nft) Init() error {
	var err error
	log.Debug("nftables: Init()")
	/* ip4 */
	if n.conn != nil {
		log.Debug("nftables: ipv4 init starting")
		if n.SetOnly4 {
			// Use to existing nftables configuration
			log.Debug("nftables: ipv4 set-only")
			n.table, err = lookupTable(n.conn, n.TableName4)
			if err != nil {
				return err
			}

			set, err := n.conn.GetSetByName(n.table, n.BlacklistsIpv4)
			if err != nil {
				log.Debugf("nftables: could not find ipv4 blacklist '%s' in table '%s': creating...", n.BlacklistsIpv4, n.TableName4)
				set = &nftables.Set{
					Name:       n.BlacklistsIpv4,
					Table:      n.table,
					KeyType:    nftables.TypeIPAddr,
					HasTimeout: true,
				}

				if err := n.conn.AddSet(set, []nftables.SetElement{}); err != nil {
					return err
				}
				if err := n.conn.Flush(); err != nil {
					return err
				}
			}
			n.set = set
			log.Debug("nftables: ipv4 set '" + n.BlacklistsIpv4 + "' configured")
		} else { // Create crowdsec table,chain, blacklist set and rules
			log.Debug("nftables: ipv4 own table")
			table := &nftables.Table{
				Family: nftables.TableFamilyIPv4,
				Name:   n.TableName4,
			}
			n.table = n.conn.AddTable(table)
			set := &nftables.Set{
				Name:       n.BlacklistsIpv4,
				Table:      n.table,
				KeyType:    nftables.TypeIPAddr,
				HasTimeout: true,
			}

			if err := n.conn.AddSet(set, []nftables.SetElement{}); err != nil {
				return err
			}
			n.set = set

			for _, hook := range n.Hooks {
				chain := n.conn.AddChain(&nftables.Chain{
					Name:     n.ChainName4 + "-" + hook,
					Table:    n.table,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  HookNameToHookID[hook],
					Priority: nftables.ChainPriority(n.priority),
				})

				r := &nftables.Rule{
					Table: n.table,
					Chain: chain,
					Exprs: []expr.Any{},
				}
				// [ payload load 4b @ network header + 16 => reg 1 ]
				r.Exprs = append(r.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				})
				// [ lookup reg 1 set whitelist ]
				r.Exprs = append(r.Exprs, &expr.Lookup{
					SourceRegister: 1,
					SetName:        n.set.Name,
					SetID:          n.set.ID,
				})

				r.Exprs = append(r.Exprs, &expr.Counter{})

				if n.DenyLog {
					r.Exprs = append(r.Exprs, &expr.Log{
						Key:  1 << unix.NFTA_LOG_PREFIX,
						Data: []byte(n.DenyLogPrefix),
					})
				}
				if strings.EqualFold(n.DenyAction, "REJECT") {
					r.Exprs = append(r.Exprs, &expr.Reject{
						Type: unix.NFT_REJECT_ICMP_UNREACH,
						Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
					})
				} else {
					r.Exprs = append(r.Exprs, &expr.Verdict{
						Kind: expr.VerdictDrop,
					})
				}

				n.conn.AddRule(r)
			}

			if err := n.conn.Flush(); err != nil {
				return err
			}
			log.Debug("nftables: ipv4 table created")
		} // IPv4 set-only
	} // IPv4

	/* ipv6 */
	if n.conn6 != nil {
		if n.SetOnly6 {
			// Use to existing nftables configuration
			log.Debug("nftables: ipv4 set-only")
			n.table, err = lookupTable(n.conn6, n.TableName6)
			if err != nil {
				return err
			}

			set, err := n.conn6.GetSetByName(n.table6, n.BlacklistsIpv6)
			if err != nil {
				return err
			}
			n.set6 = set
			log.Debug("nftables: ipv6 set '" + n.BlacklistsIpv6 + "' configured")
		} else {
			log.Debug("nftables: ipv6 own table")
			table := &nftables.Table{
				Family: nftables.TableFamilyIPv6,
				Name:   n.TableName6,
			}
			n.table6 = n.conn6.AddTable(table)

			set := &nftables.Set{
				Name:       n.BlacklistsIpv6,
				Table:      n.table6,
				KeyType:    nftables.TypeIP6Addr,
				HasTimeout: true,
			}

			if err := n.conn6.AddSet(set, []nftables.SetElement{}); err != nil {
				return err
			}
			n.set6 = set

			for _, hook := range n.Hooks {
				chain := n.conn6.AddChain(&nftables.Chain{
					Name:     n.ChainName6 + "-" + hook,
					Table:    n.table6,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  HookNameToHookID[hook],
					Priority: nftables.ChainPriority(n.priority),
				})

				r := &nftables.Rule{
					Table: n.table6,
					Chain: chain,
					Exprs: []expr.Any{},
				}
				// [ payload load 4b @ network header + 16 => reg 1 ]
				r.Exprs = append(r.Exprs, &expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       8,
					Len:          16,
				})
				// [ lookup reg 1 set whitelist ]
				r.Exprs = append(r.Exprs, &expr.Lookup{
					SourceRegister: 1,
					SetName:        n.set6.Name,
					SetID:          n.set6.ID,
				})

				r.Exprs = append(r.Exprs, &expr.Counter{})

				if n.DenyLog {
					r.Exprs = append(r.Exprs, &expr.Log{
						Key:  1 << unix.NFTA_LOG_PREFIX,
						Data: []byte(n.DenyLogPrefix),
					})
				}
				if strings.EqualFold(n.DenyAction, "REJECT") {
					r.Exprs = append(r.Exprs, &expr.Reject{
						Type: unix.NFT_REJECT_ICMP_UNREACH,
						Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
					})
				} else {
					r.Exprs = append(r.Exprs, &expr.Verdict{
						Kind: expr.VerdictDrop,
					})
				}

				n.conn6.AddRule(r)
			}
			if err := n.conn6.Flush(); err != nil {
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

	if n.conn != nil {
		elements, err := n.conn.GetSetElements(n.set)
		if err != nil {
			return nil, err
		}
		for _, el := range elements {
			state[net.IP(el.Key).String()] = struct{}{}
		}
	}

	if n.conn6 != nil {
		elements, err := n.conn6.GetSetElements(n.set6)
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
			if n.conn6 != nil {
				ip6 = append(ip6, nftables.SetElement{Key: ip.To16()})
				log.Tracef("adding %s to buffer", ip)
			}
			continue
		}
		if n.conn != nil {
			ip4 = append(ip4, nftables.SetElement{Key: ip.To4()})
			log.Tracef("adding %s to buffer", ip)
		}
	}

	for _, chunk := range slicetools.Chunks(ip4, chunkSize) {
		log.Debugf("removing %d ipv4 elements from set", len(chunk))
		if err := n.conn.SetDeleteElements(n.set, chunk); err != nil {
			return fmt.Errorf("failed to remove ipv4 elements from set: %w", err)
		}
		if err := n.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv4 conn: %w", err)
		}
	}

	for _, chunk := range slicetools.Chunks(ip6, chunkSize) {
		log.Debugf("removing %d ipv6 elements from set", len(chunk))
		if err := n.conn6.SetDeleteElements(n.set6, chunk); err != nil {
			return fmt.Errorf("failed to remove ipv6 elements from set: %w", err)
		}
		if err := n.conn6.Flush(); err != nil {
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
			if n.conn6 != nil {
				elements6 = append(elements6, nftables.SetElement{Timeout: t, Key: ip.To16()})
				log.Tracef("adding %s to buffer", ip)
			}
			continue
		}
		if n.conn != nil {
			ip4 = append(ip4, nftables.SetElement{Timeout: t, Key: ip.To4()})
			log.Tracef("adding %s to buffer", ip)
		}
	}

	for _, chunk := range slicetools.Chunks(ip4, chunkSize) {
		log.Debugf("adding %d ipv4 elements to set", len(chunk))
		if err := n.conn.SetAddElements(n.set, chunk); err != nil {
			return fmt.Errorf("failed to add ipv4 elements to set: %w", err)
		}
		if err := n.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush ipv4 conn: %w", err)
		}
	}

	for _, chunk := range slicetools.Chunks(elements6, chunkSize) {
		log.Debugf("adding %d ipv6 elements to set", len(chunk))
		if err := n.conn6.SetAddElements(n.set6, chunk); err != nil {
			return fmt.Errorf("failed to add ipv6 elements to set: %w", err)
		}
		if err := n.conn6.Flush(); err != nil {
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
	if n.conn != nil {
		if n.SetOnly4 {
			// Flush blacklist4 set empty
			log.Infof("flushing '%s' set in '%s' table", n.set.Name, n.table.Name)
			n.conn.FlushSet(n.set)
		} else {
			// delete whole crowdsec table
			log.Infof("removing '%s' table", n.table.Name)
			n.conn.DelTable(n.table)
		}
		if err := n.conn.Flush(); err != nil {
			return err
		}
	}

	if n.conn6 != nil {
		if n.SetOnly6 {
			// Flush blacklist6 set empty
			log.Infof("flushing '%s' set in '%s' table", n.set6.Name, n.table6.Name)
			n.conn.FlushSet(n.set6)
		} else {
			log.Infof("removing '%s' table", n.TableName6)
			n.conn6.DelTable(n.table6)
		}
		if err := n.conn6.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func maxTime(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
