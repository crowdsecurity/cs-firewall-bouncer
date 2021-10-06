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
	ret.BlacklistsIpv4 = config.BlacklistsIpv4
	ret.BlacklistsIpv6 = config.BlacklistsIpv6
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
		Name:     "crowdsec-chain",
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
		Interval:   true,
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
			Name:     "crowdsec6-chain",
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
			Interval:   true,
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
	var cidr string
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if !strings.Contains(*decision.Value, "/") {
				cidr = fmt.Sprintf("%s/128", *decision.Value)
			} else {
				cidr = *decision.Value
			}
			_, cidrNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return err
			}
			bca, err := BroadcastAddr(cidrNet)
			if err != nil {
				return err
			}
			if err := n.conn6.SetAddElements(n.set6,
				[]nftables.SetElement{
					{Key: []byte(cidrNet.IP.To16()), Timeout: timeout},
					{Key: []byte(incrementIP(bca).To16()), IntervalEnd: true},
				}); err != nil {
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
		if !strings.Contains(*decision.Value, "/") {
			cidr = fmt.Sprintf("%s/32", *decision.Value)
		} else {
			cidr = *decision.Value
		}
		_, cidrNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		bca, err := BroadcastAddr(cidrNet)
		if err != nil {
			return err
		}
		if err := n.conn.SetAddElements(n.set,
			[]nftables.SetElement{
				{Key: cidrNet.IP, Timeout: timeout},
				{Key: incrementIP(bca), IntervalEnd: true},
			}); err != nil {
			return err
		}
		if err := n.conn.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func (n *nft) Delete(decision *models.Decision) error {
	var cidr string
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if !strings.Contains(*decision.Value, "/") {
				cidr = fmt.Sprintf("%s/128", *decision.Value)
			} else {
				cidr = *decision.Value
			}
			_, cidrNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return err
			}
			bca, err := BroadcastAddr(cidrNet)
			if err != nil {
				return err
			}
			if err := n.conn6.SetDeleteElements(n.set6,
				[]nftables.SetElement{
					{Key: []byte(cidrNet.IP.To16())},
					{Key: []byte(incrementIP(bca).To16()), IntervalEnd: true},
				}); err != nil {
				return err
			}
			if err := n.conn6.Flush(); err != nil {
				return err
			}

		} else {
			log.Debugf("not removing '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		var cidr string
		if !strings.Contains(*decision.Value, "/") {
			cidr = fmt.Sprintf("%s/32", *decision.Value)
		} else {
			cidr = *decision.Value
		}
		_, cidrNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		bca, err := BroadcastAddr(cidrNet)
		if err != nil {
			return err
		}
		if err := n.conn.SetDeleteElements(n.set,
			[]nftables.SetElement{
				{Key: cidrNet.IP},
				{Key: incrementIP(bca), IntervalEnd: true},
			}); err != nil {
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

// Utilites from https://github.com/IBM/netaddr/blob/master/net_utils.go

// NewIP returns a new IP with the given size. The size must be 4 for IPv4 and
// 16 for IPv6.
func NewIP(size int) (net.IP, error) {
	if size == 4 {
		return net.ParseIP("0.0.0.0").To4(), nil
	}
	if size == 16 {
		return net.ParseIP("::"), nil
	}
	return net.IP{}, fmt.Errorf("invalid size %d", size)
}

// BroadcastAddr returns the last address in the given network, or the broadcast address.
func BroadcastAddr(n *net.IPNet) (net.IP, error) {
	// The golang net package doesn't make it easy to calculate the broadcast address. :(
	broadcast, err := NewIP(len(n.IP))
	if err != nil {
		return net.IP{}, err
	}
	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast, nil
}

// incrementIP returns the given IP + 1
func incrementIP(ip net.IP) (result net.IP) {
	result = make([]byte, len(ip)) // start off with a nice empty ip of proper length

	carry := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if carry {
			result[i]++
			if result[i] != 0 {
				carry = false
			}
		}
	}
	return
}
