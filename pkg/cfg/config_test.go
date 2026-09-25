package cfg

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPFFlushStates(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected bool
	}{
		{
			name:     "default when pf section is absent",
			config:   "mode: pf\nlog_mode: stdout\n",
			expected: true,
		},
		{
			name:     "default when pf section is present but empty (null)",
			config:   "mode: pf\nlog_mode: stdout\npf:\n",
			expected: true,
		},
		{
			name:     "default when pf section omits the option",
			config:   "mode: pf\nlog_mode: stdout\npf:\n  anchor_name: \"\"\n",
			expected: true,
		},
		{
			name:     "explicitly enabled",
			config:   "mode: pf\nlog_mode: stdout\npf:\n  flush_states: true\n",
			expected: true,
		},
		{
			name:     "explicitly disabled",
			config:   "mode: pf\nlog_mode: stdout\npf:\n  flush_states: false\n",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config, err := NewConfig(strings.NewReader(tc.config))
			require.NoError(t, err)
			require.NotNil(t, config.PF.FlushStates)
			require.Equal(t, tc.expected, *config.PF.FlushStates)
		})
	}
}
