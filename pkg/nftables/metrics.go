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

func collectDroppedPackets(path string, family string, tableName string, chainName string) (float64, float64, error) {
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

func collectActiveBannedIPs(path string, family string, tableName string, setName string) (float64, error) {
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

func (n *nft) CollectMetrics() {
	path, err := exec.LookPath("nft")
	if err != nil {
		log.Error("can't monitor dropped packets: ", err)
		return
	}
	t := time.NewTicker(metrics.MetricCollectionInterval)

	var ip4DroppedPackets, ip4DroppedBytes, ip6DroppedPackets, ip6DroppedBytes, bannedIP4, bannedIP6 float64
	for range t.C {
		if n.conn != nil {
			for _, hook := range n.Hooks {
				ip4DroppedPackets, ip4DroppedBytes, err = collectDroppedPackets(path, "ip", n.TableName4, n.ChainName4+"-"+hook)
				if err != nil {
					log.Error("can't collect dropped packets for ipv4 from nft: ", err)
				}
			}
			bannedIP4, err = collectActiveBannedIPs(path, "ip", n.TableName4, n.BlacklistsIpv4)
			if err != nil {
				log.Error("can't collect total banned IPs for ipv4 from nft:", err)
			}
		}
		if n.conn6 != nil {
			for _, hook := range n.Hooks {
				ip6DroppedPackets, ip6DroppedBytes, err = collectDroppedPackets(path, "ip6", n.TableName6, n.ChainName6+"-"+hook)
				if err != nil {
					log.Error("can't collect dropped packets for ipv6 from nft: ", err)
				}
			}
			bannedIP6, err = collectActiveBannedIPs(path, "ip6", n.TableName6, n.BlacklistsIpv6)
			if err != nil {
				log.Error("can't collect total banned IPs for ipv6 from nft:", err)
			}
		}
		metrics.TotalDroppedPackets.Set(ip4DroppedPackets + ip6DroppedPackets)
		metrics.TotalDroppedBytes.Set(ip6DroppedBytes + ip4DroppedBytes)
		metrics.TotalActiveBannedIPs.Set(bannedIP4 + bannedIP6)
	}
}
