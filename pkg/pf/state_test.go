package pf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStateIPs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:  "ipv4",
			input: "all tcp 192.0.2.1:22 <- 198.51.100.7:51234       ESTABLISHED:ESTABLISHED\n",
			expected: map[string]bool{
				"192.0.2.1":    true,
				"198.51.100.7": true,
			},
		},
		{
			name:  "ipv6",
			input: "all tcp 2001:db8::1[22] <- 2001:db8:ffff::7[51234]       ESTABLISHED:ESTABLISHED\n",
			expected: map[string]bool{
				"2001:db8::1":      true,
				"2001:db8:ffff::7": true,
			},
		},
		{
			name:  "ipv6 without ports",
			input: "all ipv6-icmp 2001:db8::1 -> 2001:db8:ffff::7       NO_TRAFFIC:NO_TRAFFIC\n",
			expected: map[string]bool{
				"2001:db8::1":      true,
				"2001:db8:ffff::7": true,
			},
		},
		{
			name:  "outbound nat",
			input: "all tcp 203.0.113.5:62000 (10.0.0.10:51234) -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED\n",
			expected: map[string]bool{
				"203.0.113.5":  true,
				"10.0.0.10":    true,
				"198.51.100.7": true,
			},
		},
		{
			name:  "inbound rdr",
			input: "em0 tcp 10.0.0.10:80 (203.0.113.5:80) <- 198.51.100.7:4444       ESTABLISHED:ESTABLISHED\n",
			expected: map[string]bool{
				"10.0.0.10":    true,
				"203.0.113.5":  true,
				"198.51.100.7": true,
			},
		},
		{
			name:     "short or empty lines",
			input:    "\nNo ALTQ support in kernel\n",
			expected: map[string]bool{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseStateIPs(strings.NewReader(tc.input)))
		})
	}
}
