//go:build linux
// +build linux

package nftables

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

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

var disabledCollection = false

func hasNftJ() bool {
	// return true if nft -j is supported.
	cmd := exec.Command("nft", "-j", "list", "tables")
	_, err := cmd.CombinedOutput()
	return err == nil
}

func (c *nftContext) collectDroppedPackets(path string, hook string) (int, int, error) {
	if disabledCollection {
		return 0, 0, nil
	}

	cmd := exec.Command(path, "-j", "list", "chain", c.ipFamily(), c.tableName, c.chainName+"-"+hook)
	out, err := cmd.CombinedOutput()

	if err != nil {
		if hasNftJ() {
			return 0, 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
		}
		disabledCollection = true
		log.Warningf("nft -j is not supported (requires 0.9.7), some metrics are disabled")
	}

	parsedOut := Counter{}
	if err := json.Unmarshal(out, &parsedOut); err != nil {
		return 0, 0, err
	}

	for _, r := range parsedOut.Nftables {
		for _, expr := range r.Rule.Expr {
			if expr.Counter != nil {
				return expr.Counter.Packets, expr.Counter.Bytes, nil
			}
		}
	}

	return 0, 0, nil
}

func (c *nftContext) ipFamily() string {
	if c.version == "v4" {
		return "ip"
	}

	return "ip6"
}

func (c *nftContext) collectActiveBannedIPs(path string) (int, error) {
	if disabledCollection {
		return 0, nil
	}
	cmd := exec.Command(path, "-j", "list", "set", c.ipFamily(), c.tableName, c.blacklists)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if hasNftJ() {
			return 0, fmt.Errorf("while running %s: %w", cmd.String(), err)
		}
		disabledCollection = true
		log.Warningf("nft -j is not supported (requires 0.9.7), some metrics are disabled")
	}

	set := Set{}
	if err := json.Unmarshal(out, &set); err != nil {
		return 0, err
	}

	ret := 0
	for _, r := range set.Nftables {
		ret += len(r.Set.Elem)
	}

	return ret, nil
}

func (c *nftContext) collectDropped(path string, hooks []string) (int, int, int) {
	if c.conn == nil {
		return 0, 0, 0
	}

	var droppedPackets, droppedBytes, banned int

	for _, hook := range hooks {
		pkt, byt, err := c.collectDroppedPackets(path, hook)
		if err != nil {
			log.Errorf("can't collect dropped packets for ip%s from nft: %s", c.version, err)
		}
		droppedPackets += pkt
		droppedBytes += byt
	}

	banned, err := c.collectActiveBannedIPs(path)
	if err != nil {
		log.Errorf("can't collect total banned IPs for ip%s from nft: %s", c.version, err)
	}

	return droppedPackets, droppedBytes, banned
}

func (n *nft) CollectMetrics() {
	path, err := exec.LookPath("nft")
	if err != nil {
		log.Error("can't monitor dropped packets: ", err)
		return
	}

	t := time.NewTicker(metrics.MetricCollectionInterval)

	for range t.C {
		ip4DroppedPackets, ip4DroppedBytes, bannedIP4 := n.v4.collectDropped(path, n.Hooks)
		ip6DroppedPackets, ip6DroppedBytes, bannedIP6 := n.v6.collectDropped(path, n.Hooks)

		metrics.TotalDroppedPackets.Set(float64(ip4DroppedPackets + ip6DroppedPackets))
		metrics.TotalDroppedBytes.Set(float64(ip6DroppedBytes + ip4DroppedBytes))
		metrics.TotalActiveBannedIPs.Set(float64(bannedIP4 + bannedIP6))
	}
}
