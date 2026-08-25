package ipfw

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type counter struct {
	packets uint64
	bytes   uint64
}

// parseMetrics reads the output of "ipfw -a list" and extracts the packet/byte
// counters of the rule(s) referencing one of the given tables, e.g.:
//
//	00100        16        4096 deny ip from table(crowdsec-blacklists) to any
func parseMetrics(reader *strings.Reader, tables []string) map[string]counter {
	ret := make(map[string]counter)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		packets, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		bytes, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}

		rule := strings.Join(fields[3:], " ")

		for _, table := range tables {
			// table references look like "table(name)" or "table(name,value)"
			if strings.Contains(rule, fmt.Sprintf("table(%s)", table)) ||
				strings.Contains(rule, fmt.Sprintf("table(%s,", table)) {
				ret[table] = counter{packets: packets, bytes: bytes}
			}
		}
	}

	return ret
}

// countIPs returns the number of IPs in a table.
func countIPs(table string) int {
	cmd := execIpfw("table", table, "list")

	out, err := cmd.Output()
	if err != nil {
		log.Errorf("failed to run 'ipfw table %s list': %s", table, err)
		return 0
	}

	// one IP per line
	return strings.Count(string(out), "\n")
}

// CollectMetrics collects metrics from ipfw.
// In ipfw mode the firewall rules are not controlled by the bouncer, so we can only
// trust they are set up correctly, and retrieve stats from the ipfw tables.
func (fw *ipfw) CollectMetrics() {
	tables := []string{}

	if fw.inet != nil {
		tables = append(tables, fw.inet.table)
	}

	if fw.inet6 != nil {
		tables = append(tables, fw.inet6.table)
	}

	cmd := execIpfw("-a", "list")

	out, err := cmd.Output()
	if err != nil {
		log.Errorf("failed to run 'ipfw -a list': %s", err)
		return
	}

	reader := strings.NewReader(string(out))
	stats := parseMetrics(reader, tables)

	for _, table := range tables {
		st, ok := stats[table]
		if !ok {
			continue
		}

		droppedPackets := float64(st.packets)
		droppedBytes := float64(st.bytes)
		bannedIPs := countIPs(table)

		if fw.inet != nil && table == fw.inet.table {
			metrics.Map[metrics.DroppedPackets].Gauge.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(droppedPackets)
			metrics.Map[metrics.DroppedBytes].Gauge.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(droppedBytes)
			metrics.Map[metrics.ActiveBannedIPs].Gauge.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(float64(bannedIPs))
		} else if fw.inet6 != nil && table == fw.inet6.table {
			metrics.Map[metrics.DroppedPackets].Gauge.With(prometheus.Labels{"ip_type": "ipv6", "origin": ""}).Set(droppedPackets)
			metrics.Map[metrics.DroppedBytes].Gauge.With(prometheus.Labels{"ip_type": "ipv6", "origin": ""}).Set(droppedBytes)
			metrics.Map[metrics.ActiveBannedIPs].Gauge.With(prometheus.Labels{"ip_type": "ipv6", "origin": ""}).Set(float64(bannedIPs))
		}
	}
}
