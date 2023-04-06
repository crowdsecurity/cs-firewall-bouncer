//go:build linux
// +build linux

package nftables

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

var defaultTimeout = "4h"

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
	log.Debugf("nftables: ipv4: %t, table: %s, chain: %s, blacklist: %s, set-only: %t",
		*config.Nftables.Ipv4.Enabled, ret.TableName4, ret.ChainName4, ret.BlacklistsIpv4, ret.SetOnly4)

	// IPv6
	ret.TableName6 = config.Nftables.Ipv6.Table
	ret.ChainName6 = config.Nftables.Ipv6.Chain
	ret.BlacklistsIpv6 = config.BlacklistsIpv6
	ret.SetOnly6 = config.Nftables.Ipv6.SetOnly
	log.Debugf("nftables: ipv6: %t, table6: %s, chain6: %s, blacklist: %s, set-only6: %t",
		*config.Nftables.Ipv6.Enabled, ret.TableName6, ret.ChainName6, ret.BlacklistsIpv6, ret.SetOnly6)

	return ret, nil
}

func (n *nft) CollectMetrics() {
	type Counter struct {
		Nftables []struct {
			Rule struct {
				Expr []struct {
					Counter *struct {
						Packets int `json:"packets"`
						Bytes   int `json:"bytes"`
					} `json:"counter,omitempty"`
				} `json:"expr"`
			} `json:"rule,omitempty"`
		} `json:"nftables"`
	}

	type Set struct {
		Nftables []struct {
			Set struct {
				Elem []struct {
					Elem struct {
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}

	path, err := exec.LookPath("nft")
	if err != nil {
		log.Error("can't monitor dropped packets: ", err)
		return
	}
	t := time.NewTicker(metrics.MetricCollectionInterval)

	collectDroppedPackets := func(family string, tableName string, chainName string) (float64, float64, error) {
		cmd := exec.Command(path, "-j", "list", "chain", family, tableName, chainName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return 0, 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
		}
		parsedOut := Counter{}
		if err := json.Unmarshal(out, &parsedOut); err != nil {
			return 0, 0, err
		}
		var tdp, tdb float64
	OUT:
		for _, r := range parsedOut.Nftables {
			for _, expr := range r.Rule.Expr {
				if expr.Counter != nil {
					tdp = float64(expr.Counter.Packets)
					tdb = float64(expr.Counter.Bytes)
					break OUT
				}
			}
		}
		return tdp, tdb, nil
	}

	collectActiveBannedIPs := func(family string, tableName string, setName string) (float64, error) {
		cmd := exec.Command(path, "-j", "list", "set", family, tableName, setName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
		}
		set := Set{}
		if err := json.Unmarshal(out, &set); err != nil {
			return 0, err
		}
		ret := 0
		for _, r := range set.Nftables {
			ret += len(r.Set.Elem)
		}
		return float64(ret), nil
	}

	var ip4DroppedPackets, ip4DroppedBytes, ip6DroppedPackets, ip6DroppedBytes, bannedIP4, bannedIP6 float64
	for range t.C {
		for _, hook := range n.Hooks {
			ip4DroppedPackets, ip4DroppedBytes, err = collectDroppedPackets("ip", n.TableName4, n.ChainName4+"-"+hook)
			if err != nil {
				log.Error("can't collect dropped packets for ipv4 from nft: ", err)
			}
		}
		bannedIP4, err = collectActiveBannedIPs("ip", n.TableName4, n.BlacklistsIpv4)
		if err != nil {
			log.Error("can't collect total banned IPs for ipv4 from nft:", err)
		}
		if n.conn6 != nil {
			for _, hook := range n.Hooks {
				ip6DroppedPackets, ip6DroppedBytes, err = collectDroppedPackets("ip6", n.TableName6, n.ChainName6+"-"+hook)
				if err != nil {
					log.Error("can't collect dropped packets for ipv6 from nft: ", err)
				}
			}
			bannedIP6, err = collectActiveBannedIPs("ip6", n.TableName6, n.BlacklistsIpv6)
			if err != nil {
				log.Error("can't collect total banned IPs for ipv6 from nft:", err)
			}
		}
		metrics.TotalDroppedPackets.Set(ip4DroppedPackets + ip6DroppedPackets)
		metrics.TotalDroppedBytes.Set(ip6DroppedBytes + ip4DroppedBytes)
		metrics.TotalActiveBannedIPs.Set(bannedIP4 + bannedIP6)
	}

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
					Priority: nftables.ChainPriorityFilter,
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

			set, err := n.conn6.GetSetByName(n.table6, n.BlacklistsIpv6)
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
					Priority: nftables.ChainPriorityFilter,
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

// returns a set of currently banned IPs.
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
				t, _ := time.ParseDuration(*decision.Duration)
				if strings.Contains(decisionIP.String(), ":") && n.conn6 != nil {
					if err := n.conn6.SetAddElements(n.set6, []nftables.SetElement{{Timeout: t, Key: decisionIP.To16()}}); err != nil {
						return err
					}
					addedIPV6 = true
				} else {
					if err := n.conn.SetAddElements(n.set, []nftables.SetElement{{Timeout: t, Key: decisionIP.To4()}}); err != nil {
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

func maxTime(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
