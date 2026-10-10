package state

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rdleal/intervalst/interval"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/iputils"
)

// errUnsupportedScope is returned for decisions unsupported by this package.
var errUnsupportedScope = errors.New("unsupported decision scope")

type Rule struct {
	iputils.IPRange

	// Date the rule stops applying, the zero value meaning never.
	ExpiresAt time.Time
}

func (r *Rule) Equal(other *Rule) bool {
	return r.IPRange == other.IPRange && r.ExpiresAt.Equal(other.ExpiresAt)
}

type decisionRule struct {
	Rule

	// Decision the rule comes from.
	Decision *models.Decision
}

type Diff struct {
	ToDelete []*Rule
	ToAdd    []*Rule
}

type Options struct {
	// Default expiration of the rule when none is provided.
	DefaultExpiration time.Duration

	// Maximum number of rules handed over at once, zero meaning no limit.
	BatchSize int

	// Implementation of current time. Mostly useful for tests.
	Now func() time.Time
}

// State keeps track of the current state of decisions in CrowdSec and a local
// cache of the rules set in the firewall. When a new decision is added or
// removed from crowdsec, this state must be updated to reflect that. State can
// then generate a diff of changes that should be applied to the firewall to
// make it match current crowdsec's state. The generated diff provides the
// following guarantees:
//   - The firewall rules will never be overlapping. If a rule currently in the
//     firewall state overlaps with a new decision, the rule will be deleted and
//     replaced with as many rules as necessary.
//   - In case of overlaps in crowsec state, the resulting firewall rule will use
//     the longest expiration among all the rules.
//
// A state should hold a single address family, as the firewall keeps a
// separate set for each.
type State struct {
	opts Options

	// decisions represents IP ranges that are banned from crowdsec's perspective
	decisions *interval.MultiValueSearchTree[*decisionRule, netip.Addr]
	// applied represents IP ranges that are actually banned in the FW
	applied *interval.SearchTree[*Rule, netip.Addr]
	// pending represents the IP ranges that have been updated in crowdsec,
	// but are not yet updated in the FW
	pending []iputils.IPRange

	mu sync.Mutex
}

// New creates a new firewall state.
func New(opts Options) *State {
	if opts.Now == nil {
		opts.Now = time.Now
	}

	state := &State{
		opts: opts,
		decisions: interval.NewMultiValueSearchTreeWithOptions[*decisionRule](
			netip.Addr.Compare,
			interval.TreeWithIntervalPoint(),
		),
	}
	state.reset()

	return state
}

// Insert inserts a new decision into crowsec state. If the decision is
// unsupported, this function is a no-op. Duplicate decisions are always added
// to state in case they have different expirations.
func (state *State) Insert(decision *models.Decision) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	rule, err := state.ruleFromDecision(decision)
	if errors.Is(err, errUnsupportedScope) {
		log.Debugf("ignoring decision for '%s': %s", *decision.Value, err)
		return nil
	} else if err != nil {
		return err
	}

	if !rule.ExpiresAt.IsZero() && state.opts.Now().After(rule.ExpiresAt) {
		log.Debugf("not inserting already expired decision for '%s'", *decision.Value)
		return nil
	}

	if err := state.decisions.Insert(rule.First, rule.Last, rule); err != nil {
		return err
	}

	state.pending = append(state.pending, rule.IPRange)

	return nil
}

// Delete deletes an existing decision from crowsec state. If the decision
// doesn't exist in state (e.g. expired) or is unsupported, this function is a
// no-op.
func (state *State) Delete(decision *models.Decision) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	rule, err := state.ruleFromDecision(decision)
	if errors.Is(err, errUnsupportedScope) {
		log.Debugf("ignoring decision for '%s': %s", *decision.Value, err)
		return nil
	} else if err != nil {
		return err
	}

	// Only forget the one decision identified by this ID/UUID.
	deleted, err := state.forget(rule.IPRange, func(other *decisionRule) bool {
		return other.Decision.ID == decision.ID && other.Decision.UUID == decision.UUID
	})
	if err != nil || !deleted {
		return err
	}

	state.pending = append(state.pending, rule.IPRange)

	return nil
}

// ApplyDiff computes the changes the firewall needs to catch up with crowdsec
// and hands them to the apply callback (deletions first).
//
// apply is guaranteed to receive at most BatchSize rules at a time. It must
// apply them atomically as a failed apply is submitted again on the next call.
func (state *State) ApplyDiff(apply func(Diff) error) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	diff, err := state.diff()
	if err != nil {
		return err
	}

	return state.commit(diff, apply)
}

// Rebuild does the same as ApplyDiff, but forgets the rules the firewall is
// known to hold and computes them all again from crowdsec state. The diff only
// contains additions, so the caller must empty the firewall first.
func (state *State) Rebuild(apply func(Diff) error) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.reset()

	first, ok := state.decisions.Min()
	if !ok {
		return nil
	}

	last, _ := state.decisions.MaxEnd()
	rng := iputils.IPRange{
		First: first[0].First,
		Last:  last[0].Last,
	}

	state.pending = []iputils.IPRange{rng}

	toAdd, err := state.mergedRules(rng)
	if err != nil {
		return err
	}

	return state.commit(Diff{ToAdd: toAdd}, apply)
}

// commit applies a diff in chunks.
func (state *State) commit(diff Diff, apply func(Diff) error) error {
	size := state.opts.BatchSize
	if size <= 0 {
		size = max(len(diff.ToDelete), len(diff.ToAdd), 1)
	}

	for batch := range slices.Chunk(diff.ToDelete, size) {
		if err := apply(Diff{ToDelete: batch}); err != nil {
			return err
		}

		for _, rule := range batch {
			if err := state.applied.Delete(rule.First, rule.Last); err != nil {
				return err
			}
		}
	}

	for batch := range slices.Chunk(diff.ToAdd, size) {
		if err := apply(Diff{ToAdd: batch}); err != nil {
			return err
		}

		for _, rule := range batch {
			if err := state.applied.Insert(rule.First, rule.Last, rule); err != nil {
				return err
			}
		}
	}

	state.pending = nil

	return nil
}

// ruleFromDecision parses a decision and returns the firewall rule
// corresponding to it, or errUnsupportedScope if this package cannot handle it.
func (state *State) ruleFromDecision(decision *models.Decision) (*decisionRule, error) {
	switch strings.ToLower(*decision.Scope) {
	case "ip", "range":
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedScope, *decision.Scope)
	}

	rng, err := iputils.ParseIPRange(*decision.Value)
	if err != nil {
		return nil, err
	}

	duration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		duration = state.opts.DefaultExpiration
	}

	var expiresAt time.Time
	if duration != 0 {
		expiresAt = state.opts.Now().Add(duration)
	}

	return &decisionRule{
		Rule: Rule{
			IPRange:   rng,
			ExpiresAt: expiresAt,
		},
		Decision: decision,
	}, nil
}

// forget removes from crowdsec state the rules of a given interval that match
// a predicate. Returns true when anything was removed.
func (state *State) forget(rng iputils.IPRange, matches func(*decisionRule) bool) (bool, error) {
	rules, _ := state.decisions.Find(rng.First, rng.Last)

	kept := slices.DeleteFunc(slices.Clone(rules), matches)
	if len(kept) == len(rules) {
		return false, nil
	}

	if len(kept) == 0 {
		return true, state.decisions.Delete(rng.First, rng.Last)
	}

	return true, state.decisions.Upsert(rng.First, rng.Last, kept...)
}

// reset forgets the rules the firewall holds, so that the next diff is
// computed from scratch.
func (state *State) reset() {
	state.applied = interval.NewSearchTreeWithOptions[*Rule](netip.Addr.Compare, interval.TreeWithIntervalPoint())
	state.pending = nil
}

// diff compares what the firewall holds on the outdated ranges with what the
// decisions say it should hold, and returns the changes necessary to make to
// make both match.
func (state *State) diff() (Diff, error) {
	var diff Diff

	for _, outdatedRange := range state.outdated() {
		wanted, err := state.mergedRules(outdatedRange)
		if err != nil {
			return Diff{}, err
		}

		held, _ := state.applied.AllIntersections(outdatedRange.First, outdatedRange.Last)

		// Drop any entry that already exists exactly as-is in the firewall.
		for len(held) != 0 && len(wanted) != 0 {
			switch {
			case held[0].Equal(wanted[0]):
				held, wanted = held[1:], wanted[1:]
			case wanted[0].First.Less(held[0].First):
				diff.ToAdd = append(diff.ToAdd, wanted[0])
				wanted = wanted[1:]
			default:
				diff.ToDelete = append(diff.ToDelete, held[0])
				held = held[1:]
			}
		}

		diff.ToDelete = append(diff.ToDelete, held...)
		diff.ToAdd = append(diff.ToAdd, wanted...)
	}

	return diff, nil
}

// alignRangeToRules grows a range to the firewall rules that may need a rewrite.
func (state *State) alignRangeToRules(rng iputils.IPRange) iputils.IPRange {
	rules, _ := state.applied.AllIntersections(rng.First, rng.Last)
	for _, rule := range rules {
		rng.Extend(rule.IPRange)
	}

	// If the firewall has any rule just before or after, they may be the
	// result of a previous merge, so we need to invalidate them too.
	if before := rng.First.Prev(); before.IsValid() {
		if rule, found := state.applied.AnyIntersection(before, before); found {
			rng.Extend(rule.IPRange)
		}
	}

	if after := rng.Last.Next(); after.IsValid() {
		if rule, found := state.applied.AnyIntersection(after, after); found {
			rng.Extend(rule.IPRange)
		}
	}

	return rng
}

// outdated returns the IP ranges that must be recomputed, in address order
// and disjoint.
func (state *State) outdated() []iputils.IPRange {
	pending := make([]iputils.IPRange, 0, len(state.pending))
	for _, rng := range state.pending {
		pending = append(pending, state.alignRangeToRules(rng))
	}

	if len(pending) == 0 {
		return nil
	}

	slices.SortFunc(pending, func(left, right iputils.IPRange) int {
		return left.First.Compare(right.First)
	})

	outdatedRanges := pending[:1]

	for _, rng := range pending[1:] {
		last := &outdatedRanges[len(outdatedRanges)-1]
		if last.Last.Less(rng.First) {
			outdatedRanges = append(outdatedRanges, rng)
			continue
		}

		last.Extend(rng)
	}

	return outdatedRanges
}

// mergedRules merges all the crowdsec decisions that overlap with a
// given range and returns that.
func (state *State) mergedRules(rng iputils.IPRange) ([]*Rule, error) {
	now := state.opts.Now()

	decisions, _ := state.decisions.AllIntersections(rng.First, rng.Last)

	boundaries := make([]netip.Addr, 0, 2*len(decisions)+1)
	boundaries = append(boundaries, rng.First)
	alive := decisions[:0]

	// Collect the addresses where a merged rule can start (i.e. where a
	// decision starts, or just after one ends)
	for _, rule := range decisions {
		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			log.Debugf("garbage collecting expired rule %d %s", rule.Decision.ID, rule.Decision.UUID)

			_, err := state.forget(rule.IPRange, func(other *decisionRule) bool { return other == rule })
			if err != nil {
				return nil, err
			}

			continue
		}

		alive = append(alive, rule)

		if rng.First.Less(rule.First) {
			boundaries = append(boundaries, rule.First)
		}

		if rule.Last.Less(rng.Last) {
			boundaries = append(boundaries, rule.Last.Next())
		}
	}

	slices.SortFunc(alive, func(left, right *decisionRule) int {
		return left.First.Compare(right.First)
	})
	slices.SortFunc(boundaries, netip.Addr.Compare)
	boundaries = slices.Compact(boundaries)

	var (
		result    []*Rule
		active    []*decisionRule
		ruleToAdd *Rule
		opened    int
	)

	for _, ip := range boundaries {
		// The decisions starting here now apply, the ones already over do not.
		for opened < len(alive) && alive[opened].First.Compare(ip) <= 0 {
			active = append(active, alive[opened])
			opened++
		}

		active = slices.DeleteFunc(active, func(rule *decisionRule) bool {
			return rule.Last.Less(ip)
		})

		expiresAt := mergedExpiration(active)

		// If the rule has changed, close the current one.
		if ruleToAdd != nil && (len(active) == 0 || !ruleToAdd.ExpiresAt.Equal(expiresAt)) {
			ruleToAdd.Last = ip.Prev()
			result = append(result, ruleToAdd)
			ruleToAdd = nil
		}

		// Finally, open a new rule if necessary.
		if ruleToAdd == nil && len(active) != 0 {
			ruleToAdd = &Rule{
				IPRange:   iputils.IPRange{First: ip},
				ExpiresAt: expiresAt,
			}
		}
	}

	// Closes the last rule.
	if ruleToAdd != nil {
		ruleToAdd.Last = rng.Last
		result = append(result, ruleToAdd)
	}

	return result, nil
}

// mergedExpiration returns the latest expiration among the given rules, the
// zero value meaning that one of them never expires.
func mergedExpiration(rules []*decisionRule) time.Time {
	var latest time.Time

	for _, rule := range rules {
		if rule.ExpiresAt.IsZero() {
			return time.Time{}
		}

		if rule.ExpiresAt.After(latest) {
			latest = rule.ExpiresAt
		}
	}

	return latest
}
