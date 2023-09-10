//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

var HookNameToHookID = map[string]nftables.ChainHook{
	"prerouting":  *nftables.ChainHookPrerouting,
	"input":       *nftables.ChainHookInput,
	"forward":     *nftables.ChainHookForward,
	"output":      *nftables.ChainHookOutput,
	"postrouting": *nftables.ChainHookPostrouting,
	"ingress":     *nftables.ChainHookIngress,
}

type nftContext struct {
	version       string
	conn          *nftables.Conn
	set           *nftables.Set
	table         *nftables.Table
	tableFamily   nftables.TableFamily
	typeIPAddr    nftables.SetDatatype
	payloadOffset uint32
	payloadLength uint32
	priority      int
	blacklist     string
	hook          string
	chainName     string
	tableName     string
	setOnly       bool
}

// convert a binary representation of an IP (4 or 16 bytes) to a string.
func reprIP(ip []byte) string {
	return net.IP(ip).String()
}

func NewNFTContext(target *types.NftablesTargetConfig) *nftContext {
	var tableFamily nftables.TableFamily
	if target.Family == "ip" {
		tableFamily = nftables.TableFamilyIPv4
	} else if target.Family == "ip6" {
		tableFamily = nftables.TableFamilyIPv6
	} else if target.Family == "inet" {
		tableFamily = nftables.TableFamilyINet
	}

	var setIPAddrType nftables.SetDatatype
	var payloadOffset, payloadLength uint32
	if target.Protocol == "ip" {
		setIPAddrType = nftables.TypeIPAddr
		payloadOffset, payloadLength = 12, 4
	} else if target.Protocol == "ip6" {
		setIPAddrType = nftables.TypeIP6Addr
		payloadOffset, payloadLength = 8, 16
	}

	ret := &nftContext{
		version:       target.Protocol,
		conn:          &nftables.Conn{},
		tableFamily:   tableFamily,
		typeIPAddr:    setIPAddrType,
		payloadOffset: payloadOffset,
		payloadLength: payloadLength,
		tableName:     target.Table,
		chainName:     target.Chain,
		hook:          target.Hook,
		blacklist:     target.Blacklist,
		setOnly:       target.SetOnly,
		priority:      target.Priority,
	}

	log.Debugf("nftables: %s, table: %s, chain: %s, blacklist: %s, set-only: %t",
		target.Protocol, target.Table, target.Chain, ret.blacklist, ret.setOnly)

	return ret
}

// setBanned retrieves the list of banned IPs from the nftables set and adds them to the banned map.
func (c *nftContext) setBanned(banned map[string]struct{}) error {
	if c.conn == nil {
		return nil
	}

	elements, err := c.conn.GetSetElements(c.set)
	if err != nil {
		return err
	}

	for _, el := range elements {
		banned[net.IP(el.Key).String()] = struct{}{}
	}

	return nil
}

func (c *nftContext) initSetOnly() error {
	var err error

	// Use existing nftables configuration
	log.Debugf("nftables: %s set-only", c.version)

	c.table, err = c.lookupTable()
	if err != nil {
		return err
	}

	set, err := c.conn.GetSetByName(c.table, c.blacklist)
	if err != nil {
		log.Debugf("nftables: could not find %s blacklist '%s' in table '%s': creating...", c.version, c.blacklist, c.tableName)

		set = &nftables.Set{
			Name:         c.blacklist,
			Table:        c.table,
			KeyType:      c.typeIPAddr,
			KeyByteOrder: binaryutil.BigEndian,
			HasTimeout:   true,
		}

		if err := c.conn.AddSet(set, []nftables.SetElement{}); err != nil {
			return err
		}

		if err := c.conn.Flush(); err != nil {
			return err
		}
	}

	c.set = set
	log.Debugf("nftables: %s set '%s' configured", c.version, c.blacklist)

	return nil
}

func (c *nftContext) initOwnTable(denyLog bool, denyLogPrefix string, denyAction string) error {
	log.Debugf("nftables: %s own table", c.version)

	c.table = c.conn.AddTable(&nftables.Table{
		Family: c.tableFamily,
		Name:   c.tableName,
	})

	set := &nftables.Set{
		Name:         c.blacklist,
		Table:        c.table,
		KeyType:      c.typeIPAddr,
		KeyByteOrder: binaryutil.BigEndian,
		HasTimeout:   true,
	}

	if err := c.conn.AddSet(set, []nftables.SetElement{}); err != nil {
		return err
	}

	c.set = set

	hooknum := HookNameToHookID[c.hook]
	priority := nftables.ChainPriority(c.priority)
	chain := c.conn.AddChain(&nftables.Chain{
		Name:     c.chainName + "-" + c.hook,
		Table:    c.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  &hooknum,
		Priority: &priority,
	})

	log.Debugf("nftables: %s chain '%s' created", c.version, chain.Name)
	r, err := c.createRule(chain, set, denyLog, denyLogPrefix, denyAction)
	if err != nil {
		return err
	}
	c.conn.AddRule(r)

	if err := c.conn.Flush(); err != nil {
		return err
	}

	log.Debugf("nftables: %s table created", c.version)

	return nil
}

func (c *nftContext) init(denyLog bool, denyLogPrefix string, denyAction string) error {
	if c.conn == nil {
		return nil
	}

	log.Debugf("nftables: %s init starting", c.version)

	var err error

	if c.setOnly {
		err = c.initSetOnly()
	} else {
		err = c.initOwnTable(denyLog, denyLogPrefix, denyAction)
	}

	if err != nil && strings.Contains(err.Error(), "out of range") {
		return fmt.Errorf("nftables: %w. Please check the name length of tables, sets and chains. "+
			"Some legacy systems have 32 or 15 character limits. "+
			"For example, use 'crowdsec-set' instead of 'crowdsec-blacklists'", err)
	}

	return err
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
	denyLog bool, denyLogPrefix string, denyAction string,
) (*nftables.Rule, error) {
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

	action := strings.ToUpper(denyAction)
	if action == "" {
		action = "DROP"
	}

	switch action {
	case "DROP":
		r.Exprs = append(r.Exprs, &expr.Verdict{
			Kind: expr.VerdictDrop,
		})
	case "REJECT":
		r.Exprs = append(r.Exprs, &expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
		})
	default:
		return nil, fmt.Errorf("invalid deny_action '%s', must be one of DROP, REJECT", action)
	}

	log.Tracef("using '%s' as deny_action", action)

	return r, nil
}

func (c *nftContext) deleteElementChunk(els []nftables.SetElement) error {
	if err := c.conn.SetDeleteElements(c.set, els); err != nil {
		return fmt.Errorf("failed to remove %s elements from set: %w", c.version, err)
	}
	if err := c.conn.Flush(); err != nil {
		if len(els) == 1 {
			log.Debugf("deleting %s, failed to flush: %s", reprIP(els[0].Key), err)
			return nil
		}
		log.Infof("failed to flush chunk of %d elements, will retry each one: %s", len(els), err)
		for _, el := range els {
			if err := c.deleteElementChunk([]nftables.SetElement{el}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *nftContext) deleteElements(els []nftables.SetElement) error {
	if len(els) <= chunkSize {
		return c.deleteElementChunk(els)
	}

	log.Debugf("splitting %d elements into chunks of %d", len(els), chunkSize)
	for _, chunk := range slicetools.Chunks(els, chunkSize) {
		if err := c.deleteElementChunk(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (c *nftContext) addElements(els []nftables.SetElement) error {
	for _, chunk := range slicetools.Chunks(els, chunkSize) {
		log.Debugf("adding %d %s elements to set", len(chunk), c.version)

		if err := c.conn.SetAddElements(c.set, chunk); err != nil {
			return fmt.Errorf("failed to add %s elements to set: %w", c.version, err)
		}

		if err := c.conn.Flush(); err != nil {
			return fmt.Errorf("failed to flush %s conn: %w", c.version, err)
		}
	}

	return nil
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
