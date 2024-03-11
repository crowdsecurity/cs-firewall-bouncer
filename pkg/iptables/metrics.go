//go:build linux
// +build linux

package iptables

import (
	"encoding/xml"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type Ipsets struct {
	Ipset []struct {
		Name   string `xml:"name,attr"`
		Header struct {
			Numentries string `xml:"numentries"`
		} `xml:"header"`
	} `xml:"ipset"`
}

func collectDroppedPackets(binaryPath string, chains []string, setName string) (float64, float64) {
	var droppedPackets, droppedBytes float64

	for _, chain := range chains {
		out, err := exec.Command(binaryPath, "-L", chain, "-v", "-x").CombinedOutput()
		if err != nil {
			log.Error(string(out), err)
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, setName) || strings.Contains(line, "LOG") {
				continue
			}

			parts := strings.Fields(line)

			tdp, err := strconv.ParseFloat(parts[IPTablesDroppedPacketIdx], 64)
			if err != nil {
				log.Error(err.Error())
			}

			droppedPackets += tdp

			tdb, err := strconv.ParseFloat(parts[IPTablesDroppedByteIdx], 64)
			if err != nil {
				log.Error(err.Error())
			}

			droppedBytes += tdb
		}
	}

	return droppedPackets, droppedBytes
}

func (ipt *iptables) CollectMetrics() {
	var ip4DroppedPackets, ip4DroppedBytes, ip6DroppedPackets, ip6DroppedBytes float64

	t := time.NewTicker(metrics.MetricCollectionInterval)
	for range t.C {
		if ipt.v4 != nil && !ipt.v4.ipsetContentOnly {
			ip4DroppedPackets, ip4DroppedBytes = collectDroppedPackets(ipt.v4.iptablesBin, ipt.v4.Chains, ipt.v4.SetName)
		}

		if ipt.v6 != nil && !ipt.v6.ipsetContentOnly {
			ip6DroppedPackets, ip6DroppedBytes = collectDroppedPackets(ipt.v6.iptablesBin, ipt.v6.Chains, ipt.v6.SetName)
		}

		if (ipt.v4 != nil && !ipt.v4.ipsetContentOnly) || (ipt.v6 != nil && !ipt.v6.ipsetContentOnly) {
			metrics.TotalDroppedPackets.Set(ip4DroppedPackets + ip6DroppedPackets)
			metrics.TotalDroppedBytes.Set(ip6DroppedBytes + ip4DroppedBytes)
		}

		out, err := exec.Command(ipt.v4.ipsetBin, "list", "-o", "xml").CombinedOutput()
		if err != nil {
			log.Error(err)
			continue
		}

		ipsets := Ipsets{}

		if err := xml.Unmarshal(out, &ipsets); err != nil {
			log.Error(err)
			continue
		}

		newCount := float64(0)

		for _, ipset := range ipsets.Ipset {
			if ipset.Name == ipt.v4.SetName || (ipt.v6 != nil && ipset.Name == ipt.v6.SetName) {
				if ipset.Header.Numentries == "" {
					continue
				}

				count, err := strconv.ParseFloat(ipset.Header.Numentries, 64)
				if err != nil {
					log.Errorf("error while parsing  Numentries from ipsets: %s", err)
					continue
				}

				newCount += count
			}
		}

		metrics.TotalActiveBannedIPs.Set(newCount)
	}
}
