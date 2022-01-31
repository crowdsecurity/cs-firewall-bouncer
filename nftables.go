// +build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const defaultTimeout = 4 * time.Hour

type nft struct {
	conn           *nftables.Conn
	conn6          *nftables.Conn
	set            *nftables.Set
	set6           *nftables.Set
	table          *nftables.Table
	table6         *nftables.Table
	DenyAction     string
	DenyLog        bool
	DenyLogPrefix  string
	BlacklistsIpv4 string
	BlacklistsIpv6 string
	//	Enabled4       bool
	ChainName4 string
	TableName4 string
	SetOnly4   bool
	//	Enabled6       bool
	ChainName6 string
	TableName6 string
	SetOnly6   bool
}

func newNFTables(config *bouncerConfig) (interface{}, error) {
	ret := &nft{}

	/*	ret.Enabled4 = config.Nftables.Ipv4.Enabled
		ret.Enabled6 = config.Nftables.Ipv6.Enabled */

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
	log.Debug(fmt.Sprintf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		config.Nftables.Ipv4.Enabled, ret.TableName4, ret.ChainName4, ret.BlacklistsIpv4, ret.SetOnly4))

	// IPv6
	ret.TableName6 = config.Nftables.Ipv6.Table
	ret.ChainName6 = config.Nftables.Ipv6.Chain
	ret.BlacklistsIpv6 = config.Nftables.Ipv6.Blacklist
	ret.SetOnly6 = config.Nftables.Ipv6.SetOnly
	log.Debug(fmt.Sprintf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		config.Nftables.Ipv6.Enabled, ret.TableName6, ret.ChainName6, ret.BlacklistsIpv6, ret.SetOnly6))

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
				log.Debug(fmt.Sprintf("nftables: could not find ipv4 blacklist '%s' in table '%s': creating...", n.BlacklistsIpv4, n.TableName4))
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
	timeout, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		log.Errorf("unable to parse timeout '%s' for '%s' : %s", *decision.Duration, *decision.Value, err)
		timeout = defaultTimeout
	}
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if err := n.conn6.SetAddElements(n.set6, []nftables.SetElement{{Key: []byte(net.ParseIP(*decision.Value).To16()), Timeout: timeout}}); err != nil {
				return err
			}
			/* if err := n.conn6.Flush(); err != nil {
				return err
			} */
		} else {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		if n.conn != nil {
			var ipAddr string
			if strings.Contains(*decision.Value, "/") {
				ipAddr = strings.Split(*decision.Value, "/")[0]
			} else {
				ipAddr = *decision.Value
			}
			if err := n.conn.SetAddElements(n.set, []nftables.SetElement{{Key: []byte(net.ParseIP(ipAddr).To4()), Timeout: timeout}}); err != nil {
				return err
			}
			/* if err := n.conn.Flush(); err != nil {
				return err
			} */
		}
	}

	return nil
}

func (n *nft) Delete(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if err := n.conn6.SetDeleteElements(n.set6, []nftables.SetElement{{Key: []byte(net.ParseIP(*decision.Value).To16())}}); err != nil {
				return err
			}
			/* if err := n.conn6.Flush(); err != nil {
				return err
			} */
		} else {
			log.Debugf("not removing '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		if n.conn != nil {
			var ipAddr string
			if strings.Contains(*decision.Value, "/") {
				ipAddr = strings.Split(*decision.Value, "/")[0]
			} else {
				ipAddr = *decision.Value
			}
			if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(ipAddr).To4()}}); err != nil {
				return err
			}
			/* if err := n.conn.Flush(); err != nil {
				return err
			} */
		}
	}

	return nil
}

func (n *nft) Commit() error {
	var ret error = nil
	if n.conn != nil {
		if err := n.conn.Flush(); err != nil {
			ret = err
		}
	}
	if n.conn6 != nil {
		if err := n.conn6.Flush(); err != nil {
			ret = err
		}
	}
	return ret
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
	} // ipv4

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
