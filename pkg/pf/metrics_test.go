package pf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetrics(t *testing.T) {
	metricsInput := `block drop in quick inet from <crowdsec_blacklists> to any label "CrowdSec IPv4"
  [ Evaluations: 1519      Packets: 16         Bytes: 4096           States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]
block drop in quick inet6 from <crowdsec6_blacklists> to any label "CrowdSec IPv6"
  [ Evaluations: 914       Packets: 8          Bytes: 2048           States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]`

	reader := strings.NewReader(metricsInput)
	tables := []string{"crowdsec_blacklists", "crowdsec6_blacklists"}

	metrics := parseMetrics(reader, tables)

	require.Contains(t, metrics, "crowdsec_blacklists")
	require.Contains(t, metrics, "crowdsec6_blacklists")

	ip4Metrics := metrics["crowdsec_blacklists"]
	assert.Equal(t, uint64(16), ip4Metrics.packets)
	assert.Equal(t, uint64(4096), ip4Metrics.bytes)

	ip6Metrics := metrics["crowdsec6_blacklists"]
	assert.Equal(t, uint64(8), ip6Metrics.packets)
	assert.Equal(t, uint64(2048), ip6Metrics.bytes)
}
