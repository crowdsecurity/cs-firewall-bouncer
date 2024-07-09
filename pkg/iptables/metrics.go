//go:build linux
// +build linux

package iptables

import (
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	//FIXME: do it per origin
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
			//FIXME: origin
			metrics.TotalDroppedPackets.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(ip4DroppedPackets + ip6DroppedPackets)
			metrics.TotalDroppedBytes.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(ip6DroppedBytes + ip4DroppedBytes)
		}

		if ipt.v4 != nil {
			for origin, set := range ipt.v4.ipsets {
				metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv4", "origin": origin}).Set(float64(set.Len()))
			}
		}

		if ipt.v6 != nil {
			for origin, set := range ipt.v6.ipsets {
				metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv6", "origin": origin}).Set(float64(set.Len()))
			}
		}
	}
}
