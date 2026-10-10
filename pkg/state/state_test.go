package state

import (
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// Decisions are told apart by their ID, which crowdsec makes unique.
var decisionID atomic.Int64

func newDecision(scope, value, duration string) *models.Decision {
	return &models.Decision{
		ID:       decisionID.Add(1),
		Duration: ptr.Of(duration),
		Origin:   ptr.Of("cscli"),
		Scenario: ptr.Of("test"),
		Scope:    ptr.Of(scope),
		Type:     ptr.Of("ban"),
		Value:    ptr.Of(value),
	}
}

// fakeFirewall acts like a fake firewall backend: it holds rules and refuses
// overlapping ones.
type fakeFirewall struct {
	t     *testing.T
	now   time.Time
	rules []*Rule
}

func (fw *fakeFirewall) apply(diff Diff) error {
	fw.t.Helper()

	for _, rule := range diff.ToDelete {
		idx := slices.IndexFunc(fw.rules, func(other *Rule) bool {
			return other.IPRange == rule.IPRange
		})
		require.NotEqual(fw.t, -1, idx, "deleting %s, which is not in the firewall", fw.format(rule))

		fw.rules = slices.Delete(fw.rules, idx, idx+1)
	}

	for _, rule := range diff.ToAdd {
		for _, other := range fw.rules {
			overlaps := rule.First.Compare(other.Last) <= 0 && other.First.Compare(rule.Last) <= 0
			require.False(fw.t, overlaps, "adding %s, which overlaps %s", fw.format(rule), fw.format(other))
		}

		fw.rules = append(fw.rules, rule)
	}

	return nil
}

func (fw *fakeFirewall) format(rule *Rule) string {
	ttl := "never"
	if !rule.ExpiresAt.IsZero() {
		ttl = rule.ExpiresAt.Sub(fw.now).String()
	}

	return fmt.Sprintf("%s-%s %s", rule.First, rule.Last, ttl)
}

// assertRules checks that the firewall holds exactly these rules.
func (fw *fakeFirewall) assertRules(expected ...string) {
	fw.t.Helper()

	got := make([]string, 0, len(fw.rules))
	for _, rule := range fw.rules {
		got = append(got, fw.format(rule))
	}

	assert.ElementsMatch(fw.t, expected, got)
}

func newTest(t *testing.T) (*State, *fakeFirewall) {
	t.Helper()

	fw := &fakeFirewall{t: t, now: time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)}
	state := New(Options{
		DefaultExpiration: 4 * time.Hour,
		Now:               func() time.Time { return fw.now },
	})

	return state, fw
}

func TestDecisionsBecomeRules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		decisions []*models.Decision
		rules     []string
	}{
		{
			name: "one rule per ip",
			decisions: []*models.Decision{
				newDecision("Ip", "10.0.0.1", "1h"),
				newDecision("Ip", "10.0.0.2", "2h"),
				newDecision("Ip", "10.0.0.3/32", "3h"),
			},
			rules: []string{
				"10.0.0.1-10.0.0.1 1h0m0s",
				"10.0.0.2-10.0.0.2 2h0m0s",
				"10.0.0.3-10.0.0.3 3h0m0s",
			},
		},
		{
			name:      "a range becomes a single rule",
			decisions: []*models.Decision{newDecision("Range", "10.0.0.0/24", "1h")},
			rules:     []string{"10.0.0.0-10.0.0.255 1h0m0s"},
		},
		{
			name: "ipv6 addresses and ranges",
			decisions: []*models.Decision{
				newDecision("Ip", "2001:db8::1", "1h"),
				newDecision("Range", "2001:db8:1::/48", "2h"),
			},
			rules: []string{
				"2001:db8::1-2001:db8::1 1h0m0s",
				"2001:db8:1::-2001:db8:1:ffff:ffff:ffff:ffff:ffff 2h0m0s",
			},
		},
		{
			name: "overlapping decisions keep the longest ban",
			decisions: []*models.Decision{
				newDecision("Range", "10.0.0.0/24", "1h"),
				// overlaps, but longer timeout
				newDecision("Range", "10.0.0.64/27", "3h"),
				// overlaps, but shorter timeout covered by a longer decision (removed)
				newDecision("Ip", "10.0.0.200", "30m"),
			},
			rules: []string{
				"10.0.0.0-10.0.0.63 1h0m0s",
				"10.0.0.64-10.0.0.95 3h0m0s",
				"10.0.0.96-10.0.0.255 1h0m0s",
			},
		},
		{
			name:      "a range reaching the last ipv4 address",
			decisions: []*models.Decision{newDecision("Range", "255.255.255.0/24", "1h")},
			rules:     []string{"255.255.255.0-255.255.255.255 1h0m0s"},
		},
		{
			name:      "a range reaching the last ipv6 address",
			decisions: []*models.Decision{newDecision("Range", "ffff:ffff:ffff:ffff::/64", "2h")},
			rules:     []string{"ffff:ffff:ffff:ffff::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 2h0m0s"},
		},
		{
			name:      "the whole ipv4 address space",
			decisions: []*models.Decision{newDecision("Range", "0.0.0.0/0", "1h")},
			rules:     []string{"0.0.0.0-255.255.255.255 1h0m0s"},
		},
		{
			name:      "the whole ipv6 address space",
			decisions: []*models.Decision{newDecision("Range", "::/0", "2h")},
			rules:     []string{"::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 2h0m0s"},
		},
		{
			name: "a decision without duration prevails",
			decisions: []*models.Decision{
				newDecision("Range", "10.0.0.0/24", "0s"),
				newDecision("Ip", "10.0.0.1", "1h"),
			},
			rules: []string{"10.0.0.0-10.0.0.255 never"},
		},
		{
			name:      "an unparseable duration falls back to the default",
			decisions: []*models.Decision{newDecision("Ip", "10.0.0.1", "not a duration")},
			rules:     []string{"10.0.0.1-10.0.0.1 4h0m0s"},
		},
		{
			name:      "an already expired decision is not inserted",
			decisions: []*models.Decision{newDecision("Ip", "10.0.0.1", "-1h")},
			rules:     []string{},
		},
		{
			name:      "an unsupported scope is ignored",
			decisions: []*models.Decision{newDecision("Username", "someone", "1h")},
			rules:     []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, fw := newTest(t)

			for _, decision := range tc.decisions {
				require.NoError(t, state.Insert(decision))
			}

			require.NoError(t, state.ApplyDiff(fw.apply))
			fw.assertRules(tc.rules...)
		})
	}
}

func TestInvalidDecisionValue(t *testing.T) {
	state, _ := newTest(t)

	require.ErrorContains(
		t,
		state.Insert(newDecision("Ip", "not an ip", "1h")),
		"can't parse IP address 'not an ip'",
	)
	require.ErrorContains(
		t,
		state.Insert(newDecision("Range", "10.0.0.0/64", "1h")),
		"can't parse IP range '10.0.0.0/64'",
	)
}

func TestDeletingAnUnsupportedDecisionIsIgnored(t *testing.T) {
	state, fw := newTest(t)

	require.NoError(t, state.Delete(newDecision("Username", "someone", "1h")))
	fw.assertRules()
}

func TestRuleSpanningSeveralDecisions(t *testing.T) {
	state, fw := newTest(t)

	wide := newDecision("Range", "10.0.0.0/28", "1h")

	require.NoError(t, state.Insert(wide))
	require.NoError(t, state.Insert(newDecision("Range", "10.0.0.0/29", "1h")))
	require.NoError(t, state.Insert(newDecision("Range", "10.0.0.8/29", "1h")))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.0-10.0.0.15 1h0m0s")

	require.NoError(t, state.Delete(wide))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.0-10.0.0.15 1h0m0s")

	// touching the first half must fragment
	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.2", "2h")))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.0-10.0.0.1 1h0m0s",
		"10.0.0.2-10.0.0.2 2h0m0s",
		"10.0.0.3-10.0.0.15 1h0m0s",
	)
}

func TestNestedRangesAcrossCommits(t *testing.T) {
	state, fw := newTest(t)

	outer := newDecision("Range", "10.0.0.0/24", "1h")
	inner := newDecision("Range", "10.0.0.64/28", "2h")
	other := newDecision("Range", "10.0.0.128/28", "3h")

	require.NoError(t, state.Insert(outer))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.0-10.0.0.255 1h0m0s")

	require.NoError(t, state.Insert(inner))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.0-10.0.0.63 1h0m0s",
		"10.0.0.64-10.0.0.79 2h0m0s",
		"10.0.0.80-10.0.0.255 1h0m0s",
	)

	require.NoError(t, state.Insert(other))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.0-10.0.0.63 1h0m0s",
		"10.0.0.64-10.0.0.79 2h0m0s",
		"10.0.0.80-10.0.0.127 1h0m0s",
		"10.0.0.128-10.0.0.143 3h0m0s",
		"10.0.0.144-10.0.0.255 1h0m0s",
	)

	require.NoError(t, state.Delete(inner))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.0-10.0.0.127 1h0m0s",
		"10.0.0.128-10.0.0.143 3h0m0s",
		"10.0.0.144-10.0.0.255 1h0m0s",
	)

	require.NoError(t, state.Delete(other))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.0-10.0.0.255 1h0m0s")

	require.NoError(t, state.Delete(outer))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules()
}

func TestDecisionsSharingAValue(t *testing.T) {
	state, fw := newTest(t)

	short := newDecision("Ip", "10.0.0.1", "1h")
	long := newDecision("Ip", "10.0.0.1", "3h")

	require.NoError(t, state.Insert(short))
	require.NoError(t, state.Insert(long))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.1-10.0.0.1 3h0m0s")

	require.NoError(t, state.Delete(short))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.1-10.0.0.1 3h0m0s")

	require.NoError(t, state.Delete(long))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules()
}

func TestExpiredDecisionsAreGarbageCollected(t *testing.T) {
	state, fw := newTest(t)

	long := newDecision("Ip", "10.0.0.1", "3h")

	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.1", "1h")))
	require.NoError(t, state.Insert(long))
	require.NoError(t, state.ApplyDiff(fw.apply))

	// the short decision expires
	fw.now = fw.now.Add(2 * time.Hour)

	fresh := newDecision("Ip", "10.0.0.1", "10m")

	require.NoError(t, state.Insert(fresh))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules("10.0.0.1-10.0.0.1 1h0m0s")

	require.NoError(t, state.Delete(fresh))
	require.NoError(t, state.Delete(long))
	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules()
}

func TestRebuild(t *testing.T) {
	state, fw := newTest(t)

	require.NoError(t, state.Insert(newDecision("Range", "10.0.0.0/24", "1h")))
	require.NoError(t, state.Insert(newDecision("Range", "10.0.0.64/27", "3h")))
	require.NoError(t, state.Insert(newDecision("Ip", "192.168.0.1", "2h")))
	require.NoError(t, state.ApplyDiff(fw.apply))

	rules := []string{
		"10.0.0.0-10.0.0.63 1h0m0s",
		"10.0.0.64-10.0.0.95 3h0m0s",
		"10.0.0.96-10.0.0.255 1h0m0s",
		"192.168.0.1-192.168.0.1 2h0m0s",
	}
	fw.assertRules(rules...)

	fw.rules = nil
	require.NoError(t, state.Rebuild(func(diff Diff) error {
		assert.Empty(t, diff.ToDelete)

		return fw.apply(diff)
	}))

	fw.assertRules(rules...)
}

func TestApplyDiffKeepsPendingChangesOnError(t *testing.T) {
	state, fw := newTest(t)

	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.1", "1h")))
	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.2", "1h")))

	errSentinel := errors.New("")
	require.ErrorIs(t, state.ApplyDiff(func(_ Diff) error {
		return errSentinel
	}), errSentinel)

	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.1-10.0.0.1 1h0m0s",
		"10.0.0.2-10.0.0.2 1h0m0s",
	)
}

func TestRebuildRetriesAfterFailure(t *testing.T) {
	state, fw := newTest(t)

	require.NoError(t, state.Insert(newDecision("Range", "10.0.0.0/24", "1h")))
	require.NoError(t, state.Insert(newDecision("Ip", "192.168.0.1", "2h")))
	require.NoError(t, state.ApplyDiff(fw.apply))

	fw.rules = nil
	errSentinel := errors.New("")
	require.ErrorIs(t, state.Rebuild(func(_ Diff) error {
		return errSentinel
	}), errSentinel)

	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.0-10.0.0.255 1h0m0s",
		"192.168.0.1-192.168.0.1 2h0m0s",
	)
}

func TestBatchesAreRecordedAsTheyGo(t *testing.T) {
	state, fw := newTest(t)
	state.opts.BatchSize = 1

	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.1", "4h")))
	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.5", "4h")))
	require.NoError(t, state.Insert(newDecision("Ip", "10.0.0.9", "4h")))

	errSentinel := errors.New("")
	batches := 0
	require.ErrorIs(t, state.ApplyDiff(func(diff Diff) error {
		assert.Len(t, diff.ToAdd, 1)

		batches++
		// take the first batch, then refuses
		if batches > 1 {
			return errSentinel
		}

		return fw.apply(diff)
	}), errSentinel)
	fw.assertRules("10.0.0.1-10.0.0.1 4h0m0s")

	require.NoError(t, state.ApplyDiff(fw.apply))
	fw.assertRules(
		"10.0.0.1-10.0.0.1 4h0m0s",
		"10.0.0.5-10.0.0.5 4h0m0s",
		"10.0.0.9-10.0.0.9 4h0m0s",
	)
}
