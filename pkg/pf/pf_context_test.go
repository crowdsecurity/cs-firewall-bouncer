package pf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func strPtr(s string) *string {
	return &s
}

func TestDecisionsToIPs(t *testing.T) {
	tests := []struct {
		name      string
		decisions []*models.Decision
		expected  []string
	}{
		{
			name:      "no decisions",
			decisions: []*models.Decision{},
			expected:  []string{},
		},
		{
			name: "multiple decisions",
			decisions: []*models.Decision{
				{Value: strPtr("192.0.2.1")},
				{Value: strPtr("198.51.100.0/24")},
				{Value: strPtr("2001:db8::1")},
			},
			expected: []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1"},
		},
		{
			// regression: v0.0.36 indexed into a zero-length slice and panicked
			// with "index out of range [0] with length 0" on any non-empty batch
			name: "nil decisions and nil values are skipped",
			decisions: []*models.Decision{
				nil,
				{Value: nil},
				{Value: strPtr("192.0.2.1")},
				nil,
				{Value: strPtr("192.0.2.2")},
			},
			expected: []string{"192.0.2.1", "192.0.2.2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decisionsToIPs(tc.decisions))
		})
	}
}
