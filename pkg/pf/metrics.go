package pf

import (
	"bufio"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type counter struct {
	packets int
	bytes   int
}

var (
	rexpTable   = regexp.MustCompile(`^block .* from <(?P<table>\w+)> .*"$`)
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

func (pf *pf) CollectMetrics() {
	t := time.NewTicker(metrics.MetricCollectionInterval)

	droppedPackets := float64(0)
	droppedBytes := float64(0)

	tables := []string{}

	if pf.inet != nil {
		tables = append(tables, pf.inet.table)
	}

	if pf.inet6 != nil {
		tables = append(tables, pf.inet6.table)
	}

	for range t.C {
		cmd := execPfctl("", "-v", "-sr")

		out, err := cmd.Output()
		if err != nil {
			log.Errorf("failed to run 'pfctl -v -sr': %s", err)
			return
		}

		reader := strings.NewReader(string(out))
		stats := parseMetrics(reader, tables)

		for _, table := range tables {
			st, ok := stats[table]
			if !ok {
				continue
			}

			droppedPackets += float64(st.packets)
			droppedBytes += float64(st.bytes)
		}

		metrics.TotalDroppedPackets.Set(droppedPackets)
		metrics.TotalDroppedBytes.Set(droppedBytes)
		metrics.TotalActiveBannedIPs.Set(0)
	}
}
