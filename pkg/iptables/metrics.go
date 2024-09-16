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

//iptables does not provide a "nice" way to get the counters for a rule, so we have to parse the output of iptables-save
//chainRegexp is just used to get the counters for the chain CROWDSEC_CHAIN (the chain managed by the bouncer that will contains our rules) from the JUMP rule
//ruleRegexp is used to get the counters for the rules we have added that will actually block the traffic
//Example output of iptables-save :
//[2080:13210403] -A INPUT -j CROWDSEC_CHAIN
//...
//[0:0] -A CROWDSEC_CHAIN -m set --match-set test-set-ipset-mode-0 src -j DROP
//First number is the number of packets, second is the number of bytes
//In case of a jump, the counters represent the number of packets and bytes that have been processed by the chain (ie, whether the packets have been accepted or dropped)
//In case of a rule, the counters represent the number of packets and bytes that have been matched by the rule (ie, the packets that have been dropped)

var chainRegexp = regexp.MustCompile(`^\[(\d+):(\d+)\]`)
var ruleRegexp = regexp.MustCompile(`^\[(\d+):(\d+)\] -A [0-9A-Za-z_-]+ -m set --match-set (.*) src -j \w+`)

// In ipset mode, we have to track the numbers of processed bytes/packets at the chain level
// This is not really accurate, as a rule *before* the crowdsec rule could impact the numbers, but we don't have any other way
var ipsetChainDeclaration = regexp.MustCompile(`^:([0-9A-Za-z_-]+) ([0-9A-Za-z_-]+) \[(\d+):(\d+)\]`)
var ipsetRule = regexp.MustCompile(`^\[(\d+):(\d+)\] -A ([0-9A-Za-z_-]+)`)

func (ctx *ipTablesContext) collectMetricsIptables(scanner *bufio.Scanner) (map[string]int, map[string]int, int, int) {
	processedBytes := 0
	processedPackets := 0

	droppedBytes := make(map[string]int)
	droppedPackets := make(map[string]int)

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

			originIDStr, found := strings.CutPrefix(matches[3], ctx.SetName+"-")
			if !found {
				log.Errorf("error while parsing counters : %s | no origin found", line)
				continue
			}
			originID, err := strconv.Atoi(originIDStr)

			if err != nil {
				log.Errorf("error while parsing counters : %s | %s", line, err)
				continue
			}

			if len(ctx.originSetMapping) < originID {
				log.Errorf("Found unknown origin id : %d", originID)
				continue
			}

			origin := ctx.originSetMapping[originID]

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

	return droppedPackets, droppedBytes, processedPackets, processedBytes

}

type chainCounters struct {
	bytes   int
	packets int
}

// In ipset mode, we only get dropped packets and bytes by matching on the set name in the rule
// It's probably not perfect, but good enough for most users
// At the moment, we do not get processed packets and bytes because we'd need
func (ctx *ipTablesContext) collectMetricsIpset(scanner *bufio.Scanner) (map[string]int, map[string]int, int, int) {
	processedBytes := 0
	processedPackets := 0

	droppedBytes := make(map[string]int)
	droppedPackets := make(map[string]int)

	//We need to store the counters for all chains
	//As we don't know in which chain the user has setup the rules
	//We'll resolve the value laters
	chainsCounter := make(map[string]chainCounters)

	//Hardcode the origin to ipset as we cannot know it based on the rule
	droppedBytes["ipset"] = 0
	droppedPackets["ipset"] = 0

	for scanner.Scan() {
		line := scanner.Text()

		//Chain declaration
		if line[0] == ':' {
			matches := ipsetChainDeclaration.FindStringSubmatch(line)
			if len(matches) != 5 {
				log.Errorf("error while parsing counters : %s | not enough matches", line)
				continue
			}

			log.Debugf("Found chain %s with matches %+v", matches[1], matches)

			c, ok := chainsCounter[matches[1]]
			if !ok {
				c = chainCounters{}
			}

			val, err := strconv.Atoi(matches[3])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}
			c.packets += val

			val, err = strconv.Atoi(matches[4])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}
			c.bytes += val

			chainsCounter[matches[1]] = c
			continue
		}

		//Assume that if a line contains the set name, it's a rule we are interested in
		if strings.Contains(line, ctx.SetName) {
			matches := ipsetRule.FindStringSubmatch(line)
			if len(matches) != 4 {
				log.Errorf("error while parsing counters : %s | not enough matches", line)
				continue
			}

			val, err := strconv.Atoi(matches[1])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}
			droppedPackets["ipset"] += val

			val, err = strconv.Atoi(matches[2])
			if err != nil {
				log.Errorf("error while parsing counters : %s", line)
				continue
			}

			droppedBytes["ipset"] += val

			//Resolve the chain counters
			c, ok := chainsCounter[matches[3]]
			if !ok {
				log.Errorf("error while parsing counters : %s | chain not found", line)
				continue
			}

			processedPackets += c.packets
			processedBytes += c.bytes
		}
	}

	return droppedPackets, droppedBytes, processedPackets, processedBytes
}

func (ctx *ipTablesContext) collectMetrics() (map[string]int, map[string]int, int, int, error) {
	//-c is required to get the counters
	cmd := []string{ctx.iptablesSaveBin, "-c", "-t", "filter"}
	saveCmd := exec.Command(cmd[0], cmd[1:]...)
	out, err := saveCmd.CombinedOutput()
	if err != nil {
		log.Errorf("error while getting iptables rules with cmd %+v : %v --> %s", cmd, err, string(out))
		return nil, nil, 0, 0, err
	}

	processedBytes := 0
	processedPackets := 0

	var droppedBytes map[string]int
	var droppedPackets map[string]int

	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	if !ctx.ipsetContentOnly {
		droppedPackets, droppedBytes, processedPackets, processedBytes = ctx.collectMetricsIptables(scanner)
	} else {
		droppedPackets, droppedBytes, processedPackets, processedBytes = ctx.collectMetricsIpset(scanner)
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

	if ipt.v6 != nil {
		for origin, set := range ipt.v6.ipsets {
			metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv6", "origin": origin}).Set(float64(set.Len()))
		}
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
