//go:build linux
// +build linux

package nftables

import (
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
	"github.com/google/nftables/expr"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
)

func (c *nftContext) collectDroppedPackets() (map[string]int, map[string]int, error) {
	droppedPackets := make(map[string]int)
	droppedBytes := make(map[string]int)
	//setName := ""
	for chainName, chain := range c.chains {
		rules, err := c.conn.GetRules(c.table, chain)
		if err != nil {
			log.Errorf("can't get rules for ip4 chain %s: %s", chainName, err)
			continue
		}
		for _, rule := range rules {
			origin := ""
			pkts := 0
			bytes := 0
			for _, xpr := range rule.Exprs {
				switch obj := xpr.(type) {
				case *expr.Counter:
					log.Debugf("rule %d (%s): packets %d, bytes %d", rule.Position, rule.Table.Name, obj.Packets, obj.Bytes)
					pkts += int(obj.Packets)
					bytes += int(obj.Bytes)
				case *expr.Lookup:
					log.Debugf("rule %d (%s): lookup %s", rule.Position, rule.Table.Name, obj.SetName)
					origin, _ = strings.CutPrefix(obj.SetName, fmt.Sprintf("%s-", c.blacklists))
				}
			}
			if origin != "" {
				droppedPackets[origin] += pkts
				droppedBytes[origin] += bytes
			}
		}
	}

	return droppedPackets, droppedBytes, nil
}

func (c *nftContext) collectActiveBannedIPs() (map[string]int, error) {
	//Find the size of the set we have created
	ret := make(map[string]int)

	for origin, set := range c.sets {
		setContent, err := c.conn.GetSetElements(set)
		if err != nil {
			return nil, fmt.Errorf("can't get set elements for %s: %w", set.Name, err)
		}
		if c.setOnly {
			ret[c.blacklists] = len(setContent)
		} else {
			ret[origin] = len(setContent)
		}
		return ret, nil
	}

	return ret, nil
}

func (c *nftContext) collectDropped() (map[string]int, map[string]int, map[string]int) {
	if c.conn == nil {
		return nil, nil, nil
	}

	droppedPackets, droppedBytes, err := c.collectDroppedPackets()

	if err != nil {
		log.Errorf("can't collect dropped packets for ip%s from nft: %s", c.version, err)
	}

	banned, err := c.collectActiveBannedIPs()
	if err != nil {
		log.Errorf("can't collect total banned IPs for ip%s from nft: %s", c.version, err)
	}

	return droppedPackets, droppedBytes, banned
}

func getOriginForList(origin string) string {
	if !strings.HasPrefix(origin, "lists-") {
		return origin
	}

	return strings.Replace(origin, "-", "", 1)
}

func (n *nft) CollectMetrics() {

	t := time.NewTicker(metrics.MetricCollectionInterval)

	for range t.C {
		startTime := time.Now()
		ip4DroppedPackets, ip4DroppedBytes, bannedIP4 := n.v4.collectDropped()
		ip6DroppedPackets, ip6DroppedBytes, bannedIP6 := n.v6.collectDropped()

		log.Debugf("metrics collection took %s", time.Since(startTime))
		log.Debugf("ip4: dropped packets: %+v, dropped bytes: %+v, banned IPs: %+v", ip4DroppedPackets, ip4DroppedBytes, bannedIP4)
		log.Debugf("ip6: dropped packets: %+v, dropped bytes: %+v, banned IPs: %+v", ip6DroppedPackets, ip6DroppedBytes, bannedIP6)

		for origin, count := range bannedIP4 {
			origin = getOriginForList(origin)
			metrics.TotalActiveBannedIPs.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
		}

		for origin, count := range bannedIP6 {
			origin = getOriginForList(origin)
			metrics.TotalActiveBannedIPs.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
		}

		for origin, count := range ip4DroppedPackets {
			origin = getOriginForList(origin)
			metrics.TotalDroppedPackets.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
		}

		for origin, count := range ip6DroppedPackets {
			origin = getOriginForList(origin)
			metrics.TotalDroppedPackets.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
		}

		for origin, count := range ip4DroppedBytes {
			origin = getOriginForList(origin)
			metrics.TotalDroppedBytes.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
		}

		for origin, count := range ip6DroppedBytes {
			origin = getOriginForList(origin)
			metrics.TotalDroppedBytes.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
		}
	}
}
