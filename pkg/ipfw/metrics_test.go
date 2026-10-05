package ipfw

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetrics(t *testing.T) {
	metricsInput := `00100        16        4096 deny ip from table(crowdsec-blacklists) to any
00200         8        2048 deny ip from table(crowdsec6-blacklists) to any
65535         0           0 allow ip from any to any`

	reader := strings.NewReader(metricsInput)
	tables := []string{"crowdsec-blacklists", "crowdsec6-blacklists"}

	metrics := parseMetrics(reader, tables)

	require.Contains(t, metrics, "crowdsec-blacklists")
	require.Contains(t, metrics, "crowdsec6-blacklists")

	ip4Metrics := metrics["crowdsec-blacklists"]
	assert.Equal(t, uint64(16), ip4Metrics.packets)
	assert.Equal(t, uint64(4096), ip4Metrics.bytes)

	ip6Metrics := metrics["crowdsec6-blacklists"]
	assert.Equal(t, uint64(8), ip6Metrics.packets)
	assert.Equal(t, uint64(2048), ip6Metrics.bytes)
}

func TestParseMetricsNoPrefixCollision(t *testing.T) {
	metricsInput := `00100        16        4096 deny ip from table(crowdsec-blacklists6) to any`

	reader := strings.NewReader(metricsInput)
	tables := []string{"crowdsec-blacklists"}

	metrics := parseMetrics(reader, tables)

	assert.NotContains(t, metrics, "crowdsec-blacklists")
}
