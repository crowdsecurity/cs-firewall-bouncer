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

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
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
	chains        map[string]*nftables.Chain
	conn          *nftables.Conn
	sets          map[string]*nftables.Set
	table         *nftables.Table
	tableFamily   nftables.TableFamily
	typeIPAddr    nftables.SetDatatype
	version       string
	payloadOffset uint32
	payloadLength uint32
	priority      int
	blacklists    string
	chainName     string
	tableName     string
	setOnly       bool
}

// convert a binary representation of an IP (4 or 16 bytes) to a string.
func reprIP(ip []byte) string {
	return net.IP(ip).String()
}

func NewNFTV4Context(config *cfg.BouncerConfig) *nftContext {
	if !*config.Nftables.Ipv4.Enabled {
		log.Debug("nftables: ipv4 disabled")

		return &nftContext{}
	}

	log.Debug("nftables: ipv4 enabled")

	ret := &nftContext{
		conn:          &nftables.Conn{},
		version:       "v4",
		tableFamily:   nftables.TableFamilyIPv4,
		typeIPAddr:    nftables.TypeIPAddr,
		payloadOffset: 12,
		payloadLength: 4,
		tableName:     config.Nftables.Ipv4.Table,
		chainName:     config.Nftables.Ipv4.Chain,
		blacklists:    config.BlacklistsIpv4,
		setOnly:       config.Nftables.Ipv4.SetOnly,
		priority:      config.Nftables.Ipv4.Priority,
		sets:          make(map[string]*nftables.Set),
	}

	log.Debugf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		*config.Nftables.Ipv4.Enabled, ret.tableName, ret.chainName, ret.blacklists, ret.setOnly)

	return ret
}

func NewNFTV6Context(config *cfg.BouncerConfig) *nftContext {
	if !*config.Nftables.Ipv6.Enabled {
		log.Debug("nftables: ipv6 disabled")

		return &nftContext{}
	}

	log.Debug("nftables: ipv6 enabled")

	ret := &nftContext{
		conn:          &nftables.Conn{},
		version:       "v6",
		tableFamily:   nftables.TableFamilyIPv6,
		typeIPAddr:    nftables.TypeIP6Addr,
		payloadOffset: 8,
		payloadLength: 16,
		tableName:     config.Nftables.Ipv6.Table,
		chainName:     config.Nftables.Ipv6.Chain,
		blacklists:    config.BlacklistsIpv6,
		setOnly:       config.Nftables.Ipv6.SetOnly,
		priority:      config.Nftables.Ipv6.Priority,
		sets:          make(map[string]*nftables.Set),
	}

	log.Debugf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		*config.Nftables.Ipv6.Enabled, ret.tableName, ret.chainName, ret.blacklists, ret.setOnly)

	return ret
}

// setBanned retrieves the list of banned IPs from the nftables set and adds them to the banned map.
func (c *nftContext) setBanned(banned map[string]struct{}) error {
	if c.conn == nil {
		return nil
	}

	for _, set := range c.sets {

		elements, err := c.conn.GetSetElements(set)
		if err != nil {
			return err
		}

		for _, el := range elements {
			banned[net.IP(el.Key).String()] = struct{}{}
		}
	}

	return nil
}

func (c *nftContext) initSetOnly() error {
	var err error

	// Use existing nftables configuration
	log.Debugf("nftables: ip%s set-only", c.version)

	c.table, err = c.lookupTable()
	if err != nil {
		return err
	}

	set, err := c.conn.GetSetByName(c.table, c.blacklists)
	if err != nil {
		log.Debugf("nftables: could not find ip%s blacklist '%s' in table '%s': creating...", c.version, c.blacklists, c.tableName)

		set = &nftables.Set{
			Name:         c.blacklists,
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

	c.sets[c.blacklists] = set
	log.Debugf("nftables: ip%s set '%s' configured", c.version, c.blacklists)

	return nil
}

func (c *nftContext) initOwnTable(hooks []string) error {
	log.Debugf("nftables: ip%s own table", c.version)

	c.table = c.conn.AddTable(&nftables.Table{
		Family: c.tableFamily,
		Name:   c.tableName,
	})

	for _, hook := range hooks {
		hooknum := HookNameToHookID[hook]
		priority := nftables.ChainPriority(c.priority)
		chain := c.conn.AddChain(&nftables.Chain{
			Name:     c.chainName + "-" + hook,
			Table:    c.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  &hooknum,
			Priority: &priority,
		})

		r := &nftables.Rule{
			Table: c.table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Counter{},
			},
			UserData: []byte("processed"),
		}

		c.conn.AddRule(r)

		c.chains[hook] = chain

		log.Debugf("nftables: ip%s chain '%s' created", c.version, chain.Name)
		//Rules and sets are created on the fly when we detect a new origin
	}

	if err := c.conn.Flush(); err != nil {
		return err
	}

	log.Debugf("nftables: ip%s table created", c.version)

	return nil
}

func (c *nftContext) init(hooks []string) error {
	if c.conn == nil {
		return nil
	}

	if c.chains == nil {
		c.chains = make(map[string]*nftables.Chain)
	}

	log.Debugf("nftables: ip%s init starting", c.version)

	var err error

	if c.setOnly {
		err = c.initSetOnly()
	} else {
		err = c.initOwnTable(hooks)
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
		Table:    c.table,
		Chain:    chain,
		Exprs:    []expr.Any{},
		UserData: []byte(set.Name),
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
	//FIXME: only delete IPs from the set they are in
	//But this could lead to strange behavior if we have duplicate decisions with different origins
	for _, set := range c.sets {
		log.Debugf("removing %d ip%s elements from set %s", len(els), c.version, set.Name)
		if err := c.conn.SetDeleteElements(set, els); err != nil {
			return fmt.Errorf("failed to remove ip%s elements from set: %w", c.version, err)
		}

		if err := c.conn.Flush(); err != nil {
			if len(els) == 1 {
				log.Debugf("deleting %s, failed to flush: %s", reprIP(els[0].Key), err)
				continue
			}

			log.Debugf("failed to flush chunk of %d elements, will retry each one: %s", len(els), err)

			for _, el := range els {
				if err := c.deleteElementChunk([]nftables.SetElement{el}); err != nil {
					return err
				}
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

func (c *nftContext) addElements(els map[string][]nftables.SetElement) error {
	var setName string

	for origin, set := range c.sets {
		if c.setOnly {
			setName = c.blacklists
		} else {
			setName = fmt.Sprintf("%s-%s", c.blacklists, origin)
		}
		log.Debugf("Using %s as origin | len of IPs: %d | set name is %s", origin, len(els[origin]), setName)
		for _, chunk := range slicetools.Chunks(els[origin], chunkSize) {
			log.Debugf("adding %d ip%s elements to set %s", len(chunk), c.version, setName)

			if err := c.conn.SetAddElements(set, chunk); err != nil {
				return fmt.Errorf("failed to add ip%s elements to set: %w", c.version, err)
			}

			if err := c.conn.Flush(); err != nil {
				return fmt.Errorf("failed to flush ip%s conn: %w", c.version, err)
			}
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
		log.Infof("flushing '%s' set in '%s' table", c.sets[c.blacklists].Name, c.table.Name)
		c.conn.FlushSet(c.sets[c.blacklists])
	} else {
		log.Infof("removing '%s' table", c.table.Name)
		c.conn.DelTable(c.table)
	}

	if err := c.conn.Flush(); err != nil {
		return err
	}

	return nil
}
