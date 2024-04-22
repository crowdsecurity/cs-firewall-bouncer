//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
	"github.com/google/nftables/expr"

	log "github.com/sirupsen/logrus"
)

func (c *nftContext) collectDroppedPackets(chain string) (int, int, error) {
	droppedPackets := 0
	droppedBytes := 0
	//setName := ""
	for chainName, chain := range c.chains {
		rules, err := c.conn.GetRules(c.table, chain)
		if err != nil {
			log.Errorf("can't get rules for ip4 chain %s: %s", chainName, err)
			continue
		}
		for _, rule := range rules {
			for _, xpr := range rule.Exprs {
				switch obj := xpr.(type) {
				case *expr.Counter:
					log.Infof("rule %d (%s): packets %d, bytes %d", rule.Position, rule.Table.Name, obj.Packets, obj.Bytes)
					droppedPackets += int(obj.Packets)
					droppedBytes += int(obj.Bytes)
				case *expr.Lookup:
					log.Infof("rule %d (%s): lookup %s", rule.Position, rule.Table.Name, obj.SetName)
					//setName = obj.SetName
				}
			}
		}
	}

	return droppedPackets, droppedBytes, nil
}

func (c *nftContext) collectActiveBannedIPs() (int, error) {
	//Find the size of the set we have created
	set, err := c.conn.GetSetByName(c.table, c.set.Name)

	if err != nil {
		return 0, fmt.Errorf("can't get set %s: %s", c.set.Name, err)
	}

	setContent, err := c.conn.GetSetElements(set)

	if err != nil {
		return 0, fmt.Errorf("can't get set elements for %s: %s", c.set.Name, err)
	}

	return len(setContent), nil
}

func (c *nftContext) collectDropped(hooks []string) (int, int, int) {
	if c.conn == nil {
		return 0, 0, 0
	}

	var droppedPackets, droppedBytes, banned int

	if c.setOnly {
		pkt, byt, err := c.collectDroppedPackets(c.chainName)
		if err != nil {
			log.Errorf("can't collect dropped packets for ip%s from nft: %s", c.version, err)
		}

		droppedPackets += pkt
		droppedBytes += byt
	} else {
		for _, hook := range hooks {
			pkt, byt, err := c.collectDroppedPackets(c.chainName + "-" + hook)
			if err != nil {
				log.Errorf("can't collect dropped packets for ip%s from nft: %s", c.version, err)
			}
			droppedPackets += pkt
			droppedBytes += byt
		}
	}

	banned, err := c.collectActiveBannedIPs()
	if err != nil {
		log.Errorf("can't collect total banned IPs for ip%s from nft: %s", c.version, err)
	}

	return droppedPackets, droppedBytes, banned
}

func (n *nft) CollectMetrics() {

	t := time.NewTicker(metrics.MetricCollectionInterval)

	for range t.C {
		startTime := time.Now()
		ip4DroppedPackets, ip4DroppedBytes, bannedIP4 := n.v4.collectDropped(n.Hooks)
		ip6DroppedPackets, ip6DroppedBytes, bannedIP6 := n.v6.collectDropped(n.Hooks)

		log.Debugf("metrics collection took %s", time.Since(startTime))
		log.Debugf("ip4: dropped packets: %d, dropped bytes: %d, banned IPs: %d", ip4DroppedPackets, ip4DroppedBytes, bannedIP4)
		log.Debugf("ip6: dropped packets: %d, dropped bytes: %d, banned IPs: %d", ip6DroppedPackets, ip6DroppedBytes, bannedIP6)

		metrics.TotalDroppedPackets.Set(float64(ip4DroppedPackets + ip6DroppedPackets))
		metrics.TotalDroppedBytes.Set(float64(ip6DroppedBytes + ip4DroppedBytes))
		metrics.TotalActiveBannedIPs.Set(float64(bannedIP4 + bannedIP6))
	}
}
