package main

import (
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
)

type nft struct {
	conn  *nftables.Conn
	set   *nftables.Set
	table *nftables.Table
}

func newNFTables() (interface{}, error) {
	ret := &nft{}

	ret.conn = &nftables.Conn{}

	return ret, nil
}

func (n *nft) Init() error {
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

	log.Infof("nftables initiated")

	return nil
}

func (n *nft) Add(decision *models.Decision) error {
	if err := n.conn.SetAddElements(n.set, []nftables.SetElement{{Key: []byte(net.ParseIP(*decision.Value).To4())}}); err != nil {
		return err
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *nft) Delete(decision *models.Decision) error {
	if err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{{Key: net.ParseIP(*decision.Value).To4()}}); err != nil {
		return err
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *nft) ShutDown() error {
	n.conn.DelTable(n.table)

	if err := n.conn.Flush(); err != nil {
		return err
	}

	return nil
}
