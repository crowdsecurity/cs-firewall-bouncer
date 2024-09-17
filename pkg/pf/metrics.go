package pf

import (
	"bufio"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type counter struct {
	packets int
	bytes   int
}

var (
	// table names can contain _ or - characters.
	rexpTable   = regexp.MustCompile(`^block .* from <(?P<table>[^ ]+)> .*"$`)
	rexpMetrics = regexp.MustCompile(`^\s+\[.*Packets: (?P<packets>\d+)\s+Bytes: (?P<bytes>\d+).*\]$`)
)

func parseMetrics(reader *strings.Reader, tables []string) map[string]counter {
	ret := make(map[string]counter)

	// scan until we find a table name between <>
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		// parse the line and extract the table name
		match := rexpTable.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}

		table := match[1]
		// if the table is not in the list of tables we want to parse, skip it
		if !slices.Contains(tables, table) {
			continue
		}

		// parse the line with the actual metrics
		if !scanner.Scan() {
			break
		}

		line = scanner.Text()

		match = rexpMetrics.FindStringSubmatch(line)
		if len(match) == 0 {
			log.Errorf("failed to parse metrics: %s", line)
			continue
		}

		packets, err := strconv.Atoi(match[1])
		if err != nil {
			log.Errorf("failed to parse metrics - dropped packets: %s", err)

			packets = 0
		}

		bytes, err := strconv.Atoi(match[2])
		if err != nil {
			log.Errorf("failed to parse metrics - dropped bytes: %s", err)

			bytes = 0
		}

		ret[table] = counter{
			packets: packets,
			bytes:   bytes,
		}
	}

	return ret
}

// countIPs returns the number of IPs in a table.
func (pf *pf) countIPs(table string) int {
	cmd := execPfctl("", "-T", "show", "-t", table)

	out, err := cmd.Output()
	if err != nil {
		log.Errorf("failed to run 'pfctl -T show -t %s': %s", table, err)
		return 0
	}

	// one IP per line
	return strings.Count(string(out), "\n")
}

// CollectMetrics collects metrics from pfctl.
// In pf mode the firewall rules are not controlled by the bouncer, so we can only
// trust they are set up correctly, and retrieve stats from the pfctl tables.
func (pf *pf) CollectMetrics() {
	droppedPackets := float64(0)
	droppedBytes := float64(0)

	tables := []string{}

	if pf.inet != nil {
		tables = append(tables, pf.inet.table)
	}

	if pf.inet6 != nil {
		tables = append(tables, pf.inet6.table)
	}

	cmd := execPfctl("", "-v", "-sr")

	out, err := cmd.Output()
	if err != nil {
		log.Errorf("failed to run 'pfctl -v -sr': %s", err)
		return
	}

	reader := strings.NewReader(string(out))
	stats := parseMetrics(reader, tables)
	bannedIPs := 0

	for _, table := range tables {
		st, ok := stats[table]
		if !ok {
			continue
		}

		droppedPackets += float64(st.packets)
		droppedBytes += float64(st.bytes)

		bannedIPs += pf.countIPs(table)
	}

	metrics.TotalDroppedPackets.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(droppedPackets)
	metrics.TotalDroppedBytes.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(droppedBytes)
	metrics.TotalActiveBannedIPs.With(prometheus.Labels{"ip_type": "ipv4", "origin": ""}).Set(float64(bannedIPs))
}
