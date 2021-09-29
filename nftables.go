// +build linux

package main

import (
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
	conn          *nftables.Conn
	conn6         *nftables.Conn
	set           *nftables.Set
	set6          *nftables.Set
	table         *nftables.Table
	table6        *nftables.Table
	DenyAction    string
	DenyLog       bool
	DenyLogPrefix string
}

func newNFTables(config *bouncerConfig) (interface{}, error) {
	ret := &nft{}

	ret.conn = &nftables.Conn{}
	if !config.DisableIPV6 {
		ret.conn6 = &nftables.Conn{}
	}
	ret.DenyAction = config.DenyAction
	ret.DenyLog = config.DenyLog
	ret.DenyLogPrefix = config.DenyLogPrefix
	return ret, nil
}

func (n *nft) Init() error {
	/* ip4 */
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "crowdsec",
	}
	n.table = n.conn.AddTable(table)

	chain := n.conn.AddChain(&nftables.Chain{
		Name:     "crowdsec_chain",
		Table:    n.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	set := &nftables.Set{
		Name:     "crowdsec_blocklist",
		Table:    n.table,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
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

	/* ipv6 */
	if n.conn6 != nil {
		table := &nftables.Table{
			Family: nftables.TableFamilyIPv6,
			Name:   "crowdsec6",
		}
		n.table6 = n.conn6.AddTable(table)

		chain := n.conn6.AddChain(&nftables.Chain{
			Name:     "crowdsec6_chain",
			Table:    n.table6,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
		})
		set := &nftables.Set{
			Name:    "crowdsec6_blocklist",
			Table:   n.table6,
			KeyType: nftables.TypeIP6Addr,
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
			if err := n.conn.SetAddElements(n.set6, []nftables.SetElement{{Key: []byte(net.ParseIP(*decision.Value).To16()), Timeout: timeout}}); err != nil {
				return err
			}
			if err := n.conn6.Flush(); err != nil {
				return err
			}
		} else {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		var network string
		if !strings.Contains(*decision.Value, "/") {
			network = fmt.Sprintf("%s/32", *decision.Value)
		} else {
			network = *decision.Value
		}
		_, cidr, err := net.ParseCIDR(network)
		if err != nil {
			return err
		}
		n.conn.SetAddElements(
			n.set,
			[]nftables.SetElement{
				{Key: cidr.IP},
				{Key: incrementIP(BroadcastAddr(cidr)), IntervalEnd: true},
			},
		)
		if err := n.conn.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func (n *nft) Delete(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(*decision.Value).To16()}}); err != nil {
				return err
			}
			if err := n.conn.Flush(); err != nil {
				return err
			}
		} else {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		var ipAddr string
		if strings.Contains(*decision.Value, "/") {
			ipAddr = strings.Split(*decision.Value, "/")[0]
		} else {
			ipAddr = *decision.Value
		}
		if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(ipAddr).To4()}}); err != nil {
			return err
		}
		if err := n.conn.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func (n *nft) ShutDown() error {
	log.Infof("removing 'crowdsec' table")
	n.conn.DelTable(n.table)
	if err := n.conn.Flush(); err != nil {
		return err
	}

	if n.conn6 != nil {
		log.Infof("removing 'crowdsec6' table")
		n.conn6.DelTable(n.table6)
		if err := n.conn6.Flush(); err != nil {
			return err
		}
	}
	return nil
}
