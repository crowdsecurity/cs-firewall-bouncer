//go:build linux

package nftables

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/nftables/expr"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

func (c *nftContext) collectDroppedPackets() (map[string]uint64, map[string]uint64, uint64, uint64, error) {
	droppedPackets := make(map[string]uint64)
	droppedBytes := make(map[string]uint64)
	processedPackets := uint64(0)
	processedBytes := uint64(0)
	// setName := ""
	for chainName, chain := range c.chains {
		rules, err := c.conn.GetRules(c.table, chain)
		if err != nil {
			log.Errorf("can't get rules for chain %s: %s", chainName, err)
			continue
		}

		for _, rule := range rules {
			for _, xpr := range rule.Exprs {
				obj, ok := xpr.(*expr.Counter)
				if ok {
					log.Debugf("rule %d (%s): packets %d, bytes %d (%s)", rule.Position, rule.Table.Name, obj.Packets, obj.Bytes, rule.UserData)

					if string(rule.UserData) == "processed" {
						processedPackets += obj.Packets
						processedBytes += obj.Bytes

						continue
					}

					origin, _ := strings.CutPrefix(string(rule.UserData), c.blacklists+"-")

					if origin == "" {
						continue
					}

					droppedPackets[origin] += obj.Packets
					droppedBytes[origin] += obj.Bytes
				}
			}
		}
	}

	return droppedPackets, droppedBytes, processedPackets, processedBytes, nil
}

func (c *nftContext) collectActiveBannedIPs() (map[string]int, error) {
	// Find the size of the set we have created
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

func (c *nftContext) collectDropped() (map[string]uint64, map[string]uint64, uint64, uint64, map[string]int) {
	if c.conn == nil {
		return nil, nil, 0, 0, nil
	}

	droppedPackets, droppedBytes, processedPackets, processedBytes, err := c.collectDroppedPackets()
	if err != nil {
		log.Errorf("can't collect dropped packets for ip%s from nft: %s", c.version, err)
	}

	banned, err := c.collectActiveBannedIPs()
	if err != nil {
		log.Errorf("can't collect total banned IPs for ip%s from nft: %s", c.version, err)
	}

	return droppedPackets, droppedBytes, processedPackets, processedBytes, banned
}

func getOriginForList(origin string) string {
	if !strings.HasPrefix(origin, "lists-") {
		return origin
	}

	return strings.Replace(origin, "-", ":", 1)
}

func (n *nft) CollectMetrics() {
	startTime := time.Now()
	ip4DroppedPackets, ip4DroppedBytes, ip4ProcessedPackets, ip4ProcessedBytes, bannedIP4 := n.v4.collectDropped()
	ip6DroppedPackets, ip6DroppedBytes, ip6ProcessedPackets, ip6ProcessedBytes, bannedIP6 := n.v6.collectDropped()

	log.Debugf("metrics collection took %s", time.Since(startTime))
	log.Debugf("ip4: dropped packets: %+v, dropped bytes: %+v, banned IPs: %+v, proccessed packets: %d, processed bytes: %d", ip4DroppedPackets, ip4DroppedBytes, bannedIP4, ip4ProcessedPackets, ip4ProcessedBytes)
	log.Debugf("ip6: dropped packets: %+v, dropped bytes: %+v, banned IPs: %+v, proccessed packets: %d, processed bytes: %d", ip6DroppedPackets, ip6DroppedBytes, bannedIP6, ip6ProcessedPackets, ip6ProcessedBytes)

	metrics.Map[metrics.ProcessedPackets].Gauge.With(prometheus.Labels{"ip_type": "ipv4"}).Set(float64(ip4ProcessedPackets))
	metrics.Map[metrics.ProcessedBytes].Gauge.With(prometheus.Labels{"ip_type": "ipv4"}).Set(float64(ip4ProcessedBytes))

	metrics.Map[metrics.ProcessedPackets].Gauge.With(prometheus.Labels{"ip_type": "ipv6"}).Set(float64(ip6ProcessedPackets))
	metrics.Map[metrics.ProcessedBytes].Gauge.With(prometheus.Labels{"ip_type": "ipv6"}).Set(float64(ip6ProcessedBytes))

	for origin, count := range bannedIP4 {
		origin = getOriginForList(origin)
		metrics.Map[metrics.ActiveBannedIPs].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
	}

	for origin, count := range bannedIP6 {
		origin = getOriginForList(origin)
		metrics.Map[metrics.ActiveBannedIPs].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
	}

	for origin, count := range ip4DroppedPackets {
		origin = getOriginForList(origin)
		metrics.Map[metrics.DroppedPackets].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
	}

	for origin, count := range ip6DroppedPackets {
		origin = getOriginForList(origin)
		metrics.Map[metrics.DroppedPackets].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
	}

	for origin, count := range ip4DroppedBytes {
		origin = getOriginForList(origin)
		metrics.Map[metrics.DroppedBytes].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv4"}).Set(float64(count))
	}

	for origin, count := range ip6DroppedBytes {
		origin = getOriginForList(origin)
		metrics.Map[metrics.DroppedBytes].Gauge.With(prometheus.Labels{"origin": origin, "ip_type": "ipv6"}).Set(float64(count))
	}
}
