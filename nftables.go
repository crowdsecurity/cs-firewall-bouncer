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
)

const defaultTimeout = 4 * time.Hour

type nft struct {
	conn   *nftables.Conn
	conn6  *nftables.Conn
	set    *nftables.Set
	set6   *nftables.Set
	table  *nftables.Table
	table6 *nftables.Table
}

func newNFTables(disableIPV6 bool) (interface{}, error) {
	ret := &nft{}

	ret.conn = &nftables.Conn{}
	if !disableIPV6 {
		ret.conn6 = &nftables.Conn{}
	}
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
		Name:    "crowdsec_blocklist",
		Table:   n.table,
		KeyType: nftables.TypeIPAddr,
	}

	if err := n.conn.AddSet(set, []nftables.SetElement{}); err != nil {
		return err
	}
	n.set = set

	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			// [ lookup reg 1 set whitelist ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        n.set.Name,
				SetID:          n.set.ID,
			},
			//[ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := n.conn.Flush(); err != nil {
		return err
	}
	log.Debug("nftables: ipv4 table created")

	/* ipv6 */
	if n.conn6 != nil {
		table = &nftables.Table{
			Family: nftables.TableFamilyIPv6,
			Name:   "crowdsec6",
		}
		n.table6 = n.conn6.AddTable(table)
	
		chain = n.conn6.AddChain(&nftables.Chain{
			Name:     "crowdsec6_chain",
			Table:    n.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
		})
		set = &nftables.Set{
			Name:    "crowdsec6_blocklist",
			Table:   n.table,
			KeyType: nftables.TypeIP6Addr,
		}
	
		if err := n.conn6.AddSet(set, []nftables.SetElement{}); err != nil {
			return err
		}
		n.set6 = set
	
		n.conn6.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: chain,
			Exprs: []expr.Any{
				// [ payload load 4b @ network header + 16 => reg 1 ]
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				// [ lookup reg 1 set whitelist ]
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        n.set.Name,
					SetID:          n.set.ID,
				},
				//[ immediate reg 0 drop ]
				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		})
	
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
			return fmt.Errorf("failed inserting ban %s, ipv6 is disabled in configuration", *decision.Value)
		}
	} else { // ipv4
		if err := n.conn.SetAddElements(n.set, []nftables.SetElement{{Key: []byte(net.ParseIP(*decision.Value).To4())}}); err != nil {
			return err
		}
	}

	if err := n.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *nft) Delete(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") { // ipv6
		if n.conn6 != nil {
			if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(*decision.Value).To16()}}); err != nil {
				return err
			}
			return fmt.Errorf("failed deleting ban %s, ipv6 is disabled in configuration", *decision.Value)
		}
	} else { // ipv4
		if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(*decision.Value).To4()}}); err != nil {
			return err
		}
	}

	if err := n.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *nft) ShutDown() error {
	n.conn.DelTable(n.table)
	if n.conn6 != nil {
		n.conn.DelTable(n.table6)
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}

	return nil
}
