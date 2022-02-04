// +build linux

package main

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var defaultTimeout = "4h"

type nft struct {
	conn              *nftables.Conn
	conn6             *nftables.Conn
	set               *nftables.Set
	set6              *nftables.Set
	table             *nftables.Table
	table6            *nftables.Table
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
}

func newNFTables(config *bouncerConfig) (backend, error) {

	ret := &nft{}

	if config.Nftables.Ipv4.Enabled {
		log.Debug("nftables: ipv4 enabled")
		ret.conn = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv4 disabled")
	}
	if config.Nftables.Ipv6.Enabled {
		log.Debug("nftables: ipv6 enabled")
		ret.conn6 = &nftables.Conn{}
	} else {
		log.Debug("nftables: ipv6 disabled")
	}
	ret.DenyAction = config.DenyAction
	ret.DenyLog = config.DenyLog
	ret.DenyLogPrefix = config.DenyLogPrefix

	// IPv4
	ret.TableName4 = config.Nftables.Ipv4.Table
	ret.ChainName4 = config.Nftables.Ipv4.Chain
	ret.BlacklistsIpv4 = config.Nftables.Ipv4.Blacklist
	ret.SetOnly4 = config.Nftables.Ipv4.SetOnly
	log.Debugf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		config.Nftables.Ipv4.Enabled, ret.TableName4, ret.ChainName4, ret.BlacklistsIpv4, ret.SetOnly4)

	// IPv6
	ret.TableName6 = config.Nftables.Ipv6.Table
	ret.ChainName6 = config.Nftables.Ipv6.Chain
	ret.BlacklistsIpv6 = config.Nftables.Ipv6.Blacklist
	ret.SetOnly6 = config.Nftables.Ipv6.SetOnly
	log.Debugf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		config.Nftables.Ipv6.Enabled, ret.TableName6, ret.ChainName6, ret.BlacklistsIpv6, ret.SetOnly6)

	return ret, nil
}

func (n *nft) Init() error {
	log.Debug("nftables: Init()")
	/* ip4 */
	if n.conn != nil {
		log.Debug("nftables: ipv4 init starting")
		if n.SetOnly4 {
			log.Debug("nftables: ipv4 set-only")
			// Use to existing nftables configuration
			var table *nftables.Table
			tables, err := n.conn.ListTables()
			if err != nil {
				return err
			}
			for _, t := range tables {
				if t.Name == n.TableName4 {
					table = t
				}
			} // for
			if table == nil {
				return errors.New("nftables: could not find ipv4 table '" + n.TableName4 + "'")
			}
			n.table = table

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

			chain := n.conn.AddChain(&nftables.Chain{
				Name:     n.ChainName4,
				Table:    n.table,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookInput,
				Priority: nftables.ChainPriorityFilter,
			})
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
			if n.DenyLog {
				r.Exprs = append(r.Exprs, &expr.Log{
					Key:  unix.NFTA_LOG_PREFIX,
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
			var table *nftables.Table

			tables, err := n.conn6.ListTables()
			if err != nil {
				return err
			}
			for _, t := range tables {
				if t.Name == n.TableName6 {
					table = t
				}
			} // for
			if table == nil {
				return errors.New("nftables: could not find ipv6 table '" + n.TableName6 + "'")
			}
			n.table6 = table

			set, err := n.conn.GetSetByName(n.table6, n.BlacklistsIpv6)
			if err != nil {
				return err
			}
			n.set6 = set
			log.Debug("nftables: ipv6 set '" + n.BlacklistsIpv6 + "' configured")

		} else {
			table := &nftables.Table{
				Family: nftables.TableFamilyIPv6,
				Name:   n.TableName6,
			}
			n.table6 = n.conn6.AddTable(table)

			chain := n.conn6.AddChain(&nftables.Chain{
				Name:     n.ChainName6,
				Table:    n.table6,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookInput,
				Priority: nftables.ChainPriorityFilter,
			})
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
			if n.DenyLog {
				r.Exprs = append(r.Exprs, &expr.Log{
					Key:  unix.NFTA_LOG_PREFIX,
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

// returns a set of currently banned IPs
func (n *nft) getCurrentState() (map[string]struct{}, error) {
	elements, err := n.conn.GetSetElements(n.set)
	if err != nil {
		return nil, err
	}

	if n.conn6 != nil {
		ipv6Elements, err := n.conn6.GetSetElements(n.set6)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ipv6Elements...)
	}
	return elementSliceToIPSet(elements), nil
}
func (n *nft) reset() {
	n.decisionsToAdd = make([]*models.Decision, 0)
	n.decisionsToDelete = make([]*models.Decision, 0)
}

func (n *nft) commitDeletedDecisions() error {
	n.decisionsToDelete = normalizedDecisions(n.decisionsToDelete)
	deletedIPV6, deletedIPV4 := false, false
	currentState := make(map[string]struct{})
	var err error
	for i := 0; i < len(n.decisionsToDelete); {
		if i == 0 || deletedIPV6 || deletedIPV4 {
			currentState, err = n.getCurrentState()
			if err != nil {
				return err
			}
			deletedIPV4, deletedIPV6 = false, false
		}
		for canDelete := 200; canDelete > 0 && i < len(n.decisionsToDelete); {
			decision := n.decisionsToDelete[i]
			i++
			decisionIP := net.ParseIP(*decision.Value)
			if _, ok := currentState[decisionIP.String()]; ok {
				log.Debugf("will delete %s", decisionIP)
				if strings.Contains(decisionIP.String(), ":") && n.conn6 != nil {
					if err := n.conn6.SetDeleteElements(n.set6, []nftables.SetElement{{Key: decisionIP.To16()}}); err != nil {
						return err
					}
					deletedIPV6 = true
				} else {
					if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: decisionIP.To4()}}); err != nil {
						return err
					}
					deletedIPV4 = true
				}
				canDelete--
			} else {
				log.Debugf("not deleting %s as it's not present in set", decisionIP)
			}
		}
		if deletedIPV4 {
			if err := n.conn.Flush(); err != nil {
				return err
			}
		}
		if deletedIPV6 {
			if err := n.conn6.Flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *nft) commitAddedDecisions() error {
	n.decisionsToAdd = normalizedDecisions(n.decisionsToAdd)
	addedIPV6, addedIPV4 := false, false
	currentState := make(map[string]struct{})
	var err error
	for i := 0; i < len(n.decisionsToAdd); {
		if i == 0 || addedIPV4 || addedIPV6 {
			currentState, err = n.getCurrentState()
			if err != nil {
				return err
			}
			addedIPV4, addedIPV6 = false, false
		}
		for canAdd := 200; canAdd > 0 && i < len(n.decisionsToAdd); {
			decision := n.decisionsToAdd[i]
			i++
			decisionIP := net.ParseIP(*decision.Value)
			if _, ok := currentState[decisionIP.String()]; ok {
				log.Debugf("skipping %s since it's already in set", decisionIP)

			} else {
				if strings.Contains(decisionIP.String(), ":") && n.conn6 != nil {
					if err := n.conn6.SetAddElements(n.set6, []nftables.SetElement{{Key: decisionIP.To16()}}); err != nil {
						return err
					}
					addedIPV6 = true
				} else {
					if err := n.conn.SetAddElements(n.set, []nftables.SetElement{{Key: decisionIP.To4()}}); err != nil {
						return err
					}
					addedIPV4 = true
				}
				canAdd--
				log.Debugf("adding %s to buffer ", decisionIP)
			}
		}
		if addedIPV4 {
			if err := n.conn.Flush(); err != nil {
				return err
			}
		}
		if addedIPV6 {
			if err := n.conn6.Flush(); err != nil {
				return err
			}
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

func elementSliceToIPSet(elements []nftables.SetElement) map[string]struct{} {
	ipSet := make(map[string]struct{})
	for _, element := range elements {
		ipSet[net.IP(element.Key).String()] = struct{}{}
	}
	return ipSet
}

// remove duplicates, normalize decision timeouts
func normalizedDecisions(decisions []*models.Decision) []*models.Decision {
	vals := make(map[string]struct{})
	finalDecisions := make([]*models.Decision, 0)
	for _, d := range decisions {
		if _, ok := vals[*d.Value]; ok {
			continue
		}
		vals[*d.Value] = struct{}{}
		if _, err := time.ParseDuration(*d.Duration); err != nil {
			d.Duration = &defaultTimeout
		}
		*d.Value = strings.Split(*d.Value, "/")[0]
		finalDecisions = append(finalDecisions, d)
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
	} // ipv4

	if err := n.conn.Flush(); err != nil {
		return err
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
