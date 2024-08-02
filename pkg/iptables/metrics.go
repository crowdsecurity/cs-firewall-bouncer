//go:build linux
// +build linux

package iptables

import (
	"bufio"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

var chainRegexp = regexp.MustCompile(`^\[(\d+):(\d+)\]`)
var ruleRegexp = regexp.MustCompile(`^\[(\d+):(\d+)\] -A \w+ -m set --match-set (.*) src -j \w+`)

func (ctx *ipTablesContext) collectMetrics() (map[string]int, map[string]int, int, int, error) {
	saveCmd := exec.Command(ctx.iptablesSaveBin, "-c", "-t", "filter")
	out, err := saveCmd.CombinedOutput()
	if err != nil {
		log.Errorf("error while getting iptables rules : %v --> %s", err, string(out))
		return nil, nil, 0, 0, err
	}

	processedBytes := 0
	processedPackets := 0

	droppedBytes := make(map[string]int)
	droppedPackets := make(map[string]int)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	for scanner.Scan() {
		line := scanner.Text()

		//Ignore chain declaration
		if line[0] == ':' {
			continue
		}

		//Jump to our chain, we can get the processed packets and bytes
		if strings.Contains(line, "-j "+chainName) {
			matches := chainRegexp.FindStringSubmatch(line)
			if len(matches) != 3 {
				log.Errorf("error while parsing counters : %s | not enough matches", line)
				continue
			}
			val, err := strconv.Atoi(matches[1])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}
			processedPackets += val

			val, err = strconv.Atoi(matches[2])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}
			processedBytes += val

			continue
		}

		//This is a rule
		if strings.Contains(line, "-A "+chainName) {
			matches := ruleRegexp.FindStringSubmatch(line)
			if len(matches) != 4 {
				log.Errorf("error while parsing counters : %s | not enough matches", line)
				continue
			}

			originIdStr, found := strings.CutPrefix(matches[3], ctx.SetName+"-")
			if !found {
				log.Errorf("error while parsing counters : %s | no origin found", line)
				continue
			}
			originId, err := strconv.Atoi(originIdStr)

			if err != nil {
				log.Errorf("error while parsing counters : %s | %s", line, err)
				continue
			}

			if len(ctx.originSetMapping) < originId {
				log.Errorf("Found unknown origin id : %d", originId)
				continue
			}

			origin := ctx.originSetMapping[originId]

			val, err := strconv.Atoi(matches[1])
			if err != nil {
				log.Errorf("error while parsing counters : %s | %s", line, err)
				continue
			}
			droppedPackets[origin] += val

			val, err = strconv.Atoi(matches[2])
			if err != nil {
				log.Errorf("error while parsing counters : %s | %s", line, err)
				continue
			}

			droppedBytes[origin] += val
		}
	}

	log.Debugf("Processed %d packets and %d bytes", processedPackets, processedBytes)
	log.Debugf("Dropped packets : %v", droppedPackets)
	log.Debugf("Dropped bytes : %v", droppedBytes)

	return droppedPackets, droppedBytes, processedPackets, processedBytes, nil
}

func (ipt *iptables) CollectMetrics() {
	if ipt.v4 != nil {
		for origin, set := range ipt.v4.ipsets {
			metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv4", "origin": origin}).Set(float64(set.Len()))
		}
		if !ipt.v4.ipsetContentOnly {
			ipv4DroppedPackets, ipv4DroppedBytes, ipv4ProcessedPackets, ipv4ProcessedBytes, err := ipt.v4.collectMetrics()

			if err != nil {
				log.Errorf("can't collect dropped packets for ipv4 from iptables: %s", err)
			} else {
				metrics.TotalProcessedPackets.With(prometheus.Labels{"ip_type": "ipv4"}).Set(float64(ipv4ProcessedPackets))
				metrics.TotalProcessedBytes.With(prometheus.Labels{"ip_type": "ipv4"}).Set(float64(ipv4ProcessedBytes))

				for origin, count := range ipv4DroppedPackets {
					metrics.TotalDroppedPackets.With(prometheus.Labels{"ip_type": "ipv4", "origin": origin}).Set(float64(count))
				}

				for origin, count := range ipv4DroppedBytes {
					metrics.TotalDroppedBytes.With(prometheus.Labels{"ip_type": "ipv4", "origin": origin}).Set(float64(count))
				}
			}

		}
	}

	if ipt.v6 != nil {
		for origin, set := range ipt.v6.ipsets {
			metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv6", "origin": origin}).Set(float64(set.Len()))
		}
		if !ipt.v6.ipsetContentOnly {
			ipv6DroppedPackets, ipv6DroppedBytes, ipv6ProcessedPackets, ipv6ProcessedBytes, err := ipt.v6.collectMetrics()

			if err != nil {
				log.Errorf("can't collect dropped packets for ipv6 from iptables: %s", err)
			} else {
				metrics.TotalProcessedPackets.With(prometheus.Labels{"ip_type": "ipv6"}).Set(float64(ipv6ProcessedPackets))
				metrics.TotalProcessedBytes.With(prometheus.Labels{"ip_type": "ipv6"}).Set(float64(ipv6ProcessedBytes))

				for origin, count := range ipv6DroppedPackets {
					metrics.TotalDroppedPackets.With(prometheus.Labels{"ip_type": "ipv6", "origin": origin}).Set(float64(count))
				}

				for origin, count := range ipv6DroppedBytes {
					metrics.TotalDroppedBytes.With(prometheus.Labels{"ip_type": "ipv6", "origin": origin}).Set(float64(count))
				}
			}
		}
	}
}
