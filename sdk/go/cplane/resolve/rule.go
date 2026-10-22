// Package resolve relates two typed, context-authorized route collections.
package resolve

import (
	"fmt"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
	"net/netip"
)

type State uint8

const (
	Missing State = iota
	Present
	Invalid
	Ambiguous
)

type Value[T comparable] struct {
	State  State
	Value  T
	Reason string
}

func Known[T comparable](v T) Value[T]            { return Value[T]{State: Present, Value: v} }
func Absent[T comparable](reason string) Value[T] { return Value[T]{State: Missing, Reason: reason} }
func Bad[T comparable](reason string) Value[T]    { return Value[T]{State: Invalid, Reason: reason} }

type Field[T comparable, V comparable] struct {
	Name string
	Get  func(T) Value[V]
}
type LeftRef[T comparable, V comparable] struct{ field Field[T, V] }
type RightRef[T comparable, V comparable] struct{ field Field[T, V] }

func Left[T comparable, V comparable](f Field[T, V]) LeftRef[T, V]   { return LeftRef[T, V]{f} }
func Right[T comparable, V comparable](f Field[T, V]) RightRef[T, V] { return RightRef[T, V]{f} }

type Condition[L comparable, R comparable] struct {
	rightKey func(R) (any, string)
	leftKeys func(L, *prefixProbe) (probeKeys, string)
	match    func(L, R) (bool, string)
	valid    bool
}

// Contains carries a validated address; Equal keeps its generic key.
type probeKeys struct {
	values  []any
	address netip.Addr
}

func read[T comparable, V comparable](f Field[T, V], v T) (V, string) {
	var zero V
	if f.Get == nil || f.Name == "" {
		return zero, "invalid field accessor"
	}
	x := f.Get(v)
	if x.State != Present {
		return zero, fmt.Sprintf("%s: state=%d %s", f.Name, x.State, x.Reason)
	}
	return x.Value, ""
}
func Equal[L comparable, R comparable, V comparable](l LeftRef[L, V], r RightRef[R, V]) Condition[L, R] {
	return Condition[L, R]{
		rightKey: func(v R) (any, string) { x, e := read(r.field, v); return x, e },
		leftKeys: func(v L, _ *prefixProbe) (probeKeys, string) {
			x, e := read(l.field, v)
			return probeKeys{values: []any{x}}, e
		},
		match: func(a L, b R) (bool, string) {
			x, e := read(l.field, a)
			if e != "" {
				return false, e
			}
			y, e := read(r.field, b)
			return e == "" && x == y, e
		},
		valid: l.field.Name != "" && r.field.Name != "" && l.field.Get != nil && r.field.Get != nil,
	}
}

// prefixProbe retains only the last address's index buckets within one evaluation.
// It never caches accessor results, matches, or work-budget charges.
type prefixProbe struct {
	address    netip.Addr
	candidates [][]int
}

// Contains indexes the right prefix and probes at most 129 prefix lengths.
func Contains[L comparable, R comparable](r RightRef[R, netip.Prefix], l LeftRef[L, netip.Addr]) Condition[L, R] {
	return Condition[L, R]{
		rightKey: func(v R) (any, string) {
			p, e := read(r.field, v)
			if e == "" && (!p.IsValid() || p.Addr().Is4In6()) {
				e = "invalid prefix"
			}
			return p.Masked(), e
		},
		leftKeys: func(v L, probe *prefixProbe) (probeKeys, string) {
			a, e := read(l.field, v)
			if e != "" {
				return probeKeys{}, e
			}
			if !a.IsValid() || a.Is4In6() {
				return probeKeys{}, "invalid address"
			}
			if probe.address != a {
				*probe = prefixProbe{address: a}
			}
			return probeKeys{address: a}, ""
		},
		match: func(a L, b R) (bool, string) {
			ip, e := read(l.field, a)
			if e != "" {
				return false, e
			}
			p, e := read(r.field, b)
			return e == "" && p.Contains(ip), e
		},
		valid: l.field.Name != "" && r.field.Name != "" && l.field.Get != nil && r.field.Get != nil,
	}
}
func All[L comparable, R comparable](first Condition[L, R], rest ...Condition[L, R]) Condition[L, R] {
	out := first
	out.match = func(l L, r R) (bool, string) {
		for _, c := range append([]Condition[L, R]{first}, rest...) {
			if c.match == nil {
				return false, "invalid predicate"
			}
			ok, e := c.match(l, r)
			if !ok || e != "" {
				return false, e
			}
		}
		return true, ""
	}
	for _, c := range rest {
		out.valid = out.valid && c.valid
	}
	return out
}
func LongestPrefix[R comparable](r RightRef[R, netip.Prefix]) Field[R, int] {
	return Field[R, int]{Name: "longest(" + r.field.Name + ")", Get: func(v R) Value[int] {
		p, e := read(r.field, v)
		if e != "" || !p.IsValid() {
			return Bad[int](e)
		}
		return Known(p.Bits())
	}}
}

type Selector[T comparable] struct {
	Families []string
	Project  func(routes.Entry) Value[T]
}
type Choice uint8

const Unique Choice = 1

type Rule[L comparable, R comparable] struct {
	Name, Context string
	Left          Selector[L]
	Right         Selector[R]
	Match         Condition[L, R]
	Rank          *Field[R, int]
	Choose        Choice
}

type Pair[L comparable, R comparable] struct {
	Left                  L
	Right                 R
	Context               string
	Revision              uint64
	LeftPaths, RightPaths []cplane.BGPPathKey
}
type Issue struct {
	Rule, Code, Reason string
	Key                cplane.BGPPathKey
}
type Limits struct{ MaxRules, MaxWork, MaxIssues int }
type Status struct {
	Ready    bool
	Revision uint64
	Issues   []Issue
}
type evaluator interface {
	evaluate(*routes.View, *budget)
	clear()
}
type Engine struct {
	view   *routes.View
	limits Limits
	rules  map[string]evaluator
	order  []string
	status Status
}
type budget struct {
	remaining, maxIssues int
	exceeded             bool
	issues               []Issue
}

func (b *budget) spend(n int) bool {
	b.remaining -= n
	if b.remaining < 0 {
		b.exceeded = true
		return false
	}
	return true
}
func (b *budget) issue(i Issue) {
	if len(b.issues) < b.maxIssues {
		b.issues = append(b.issues, i)
	}
}
func NewEngine(v *routes.View, limits Limits) (*Engine, error) {
	if v == nil {
		return nil, fmt.Errorf("resolve: nil view")
	}
	if limits.MaxRules == 0 {
		limits.MaxRules = 16
	}
	if limits.MaxWork == 0 {
		limits.MaxWork = 1 << 20
	}
	if limits.MaxIssues == 0 {
		limits.MaxIssues = 128
	}
	if limits.MaxRules < 1 || limits.MaxWork < 1 || limits.MaxIssues < 1 {
		return nil, fmt.Errorf("resolve: positive limits required")
	}
	return &Engine{view: v, limits: limits, rules: map[string]evaluator{}}, nil
}
func (e *Engine) Status() Status {
	s := e.status
	s.Issues = append([]Issue(nil), s.Issues...)
	return s
}
func (e *Engine) Update(events []cplane.Event) []cplane.EventResult {
	results := e.view.Update(events)
	s := e.view.Status()
	e.status = Status{Ready: s.Ready, Revision: s.Revision}
	if !s.Ready {
		for _, r := range e.rules {
			r.clear()
		}
		return results
	}
	b := &budget{remaining: e.limits.MaxWork, maxIssues: e.limits.MaxIssues}
	for _, name := range e.order {
		e.rules[name].evaluate(e.view, b)
		if b.exceeded {
			break
		}
	}
	e.status.Issues = b.issues
	if b.exceeded {
		e.status.Ready = false
		for _, r := range e.rules {
			r.clear()
		}
		results = append(results, e.view.Invalidate(0, "resolve: work budget exceeded"))
	}
	return results
}

type Plan[L comparable, R comparable] struct {
	rule  Rule[L, R]
	pairs []Pair[L, R]
	// Evaluation scratch belongs to the already allocated plan. Its contents
	// are cleared on entry and exit, so no index buckets survive an evaluation.
	probe prefixProbe
}

func (p *Plan[L, R]) Results() []Pair[L, R] {
	out := make([]Pair[L, R], len(p.pairs))
	copy(out, p.pairs)
	for i := range out {
		out[i].LeftPaths = append([]cplane.BGPPathKey(nil), out[i].LeftPaths...)
		out[i].RightPaths = append([]cplane.BGPPathKey(nil), out[i].RightPaths...)
	}
	return out
}
func (p *Plan[L, R]) clear() { p.pairs = nil }
func Register[L comparable, R comparable](e *Engine, r Rule[L, R]) (*Plan[L, R], error) {
	if e == nil || r.Name == "" || e.rules[r.Name] != nil || len(e.rules) >= e.limits.MaxRules {
		return nil, fmt.Errorf("resolve: duplicate/empty name or rule limit")
	}
	if r.Left.Project == nil || r.Right.Project == nil || !r.Match.valid || r.Match.rightKey == nil || r.Match.leftKeys == nil || r.Choose != Unique {
		return nil, fmt.Errorf("resolve: selectors, indexed predicate and Unique required")
	}
	for _, fs := range [][]string{r.Left.Families, r.Right.Families} {
		if len(fs) == 0 {
			return nil, fmt.Errorf("resolve: explicit families required")
		}
		for _, f := range fs {
			if !e.view.Allows(r.Context, f) {
				return nil, fmt.Errorf("resolve: ungranted context/family %q/%q", r.Context, f)
			}
		}
	}
	if r.Rank != nil && (r.Rank.Name == "" || r.Rank.Get == nil) {
		return nil, fmt.Errorf("resolve: invalid rank")
	}
	p := &Plan[L, R]{rule: r}
	e.rules[r.Name] = p
	e.order = append(e.order, r.Name)
	return p, nil
}

type destination struct {
	codec string
	afi   uint16
	safi  uint8
	nlri  string
}

func dest(k cplane.BGPPathKey) destination { return destination{k.Codec, k.AFI, k.SAFI, k.Destination} }

type candidate[T comparable] struct {
	value       T
	destination destination
	keys        []cplane.BGPPathKey
}

func selected(e routes.Entry, ctx string, families []string) bool {
	found := false
	for _, c := range e.Contexts {
		if c == ctx {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, f := range families {
		if e.Family == f {
			return true
		}
	}
	return false
}
func (p *Plan[L, R]) evaluate(v *routes.View, b *budget) {
	p.probe = prefixProbe{}
	defer func() { p.probe = prefixProbe{} }()
	// Keep capacity while ready, but release every previous route/path reference.
	clear(p.pairs)
	p.pairs = p.pairs[:0]
	r := p.rule
	type group struct {
		destination destination
		value       R
	}
	right := []candidate[R]{}
	groups := map[group]int{}
	index := map[any][]int{}
	v.Range(func(entry routes.Entry) {
		if b.exceeded || !selected(entry, r.Context, r.Right.Families) || !b.spend(1) {
			return
		}
		x := r.Right.Project(entry)
		if x.State == Missing {
			return
		}
		if x.State != Present {
			b.issue(Issue{r.Name, "invalid_right", x.Reason, entry.Key})
			return
		}
		g := group{dest(entry.Key), x.Value}
		if i, held := groups[g]; held {
			right[i].keys = append(right[i].keys, entry.Key)
			return
		}
		k, reason := r.Match.rightKey(x.Value)
		if reason != "" {
			b.issue(Issue{r.Name, "invalid_right_field", reason, entry.Key})
			return
		}
		i := len(right)
		groups[g] = i
		right = append(right, candidate[R]{x.Value, g.destination, []cplane.BGPPathKey{entry.Key}})
		index[k] = append(index[k], i)
	})
	v.Range(func(entry routes.Entry) {
		if b.exceeded || !selected(entry, r.Context, r.Left.Families) || !b.spend(1) {
			return
		}
		x := r.Left.Project(entry)
		if x.State == Missing {
			return
		}
		if x.State != Present {
			b.issue(Issue{r.Name, "invalid_left", x.Reason, entry.Key})
			return
		}
		keys, reason := r.Match.leftKeys(x.Value, &p.probe)
		if reason != "" {
			b.issue(Issue{r.Name, "invalid_left_field", reason, entry.Key})
			return
		}
		best, bestRank, ties := -1, 0, 0
		count := len(keys.values)
		prefixes := keys.address.IsValid()
		if prefixes {
			count = keys.address.BitLen() + 1
		}
		for j := 0; j < count; j++ {
			if !b.spend(1) {
				return
			}
			var candidates []int
			if prefixes {
				// Prefixes are visited in order, so length also marks cached
				// empty buckets. The right index is immutable during this walk.
				if j == len(p.probe.candidates) {
					if p.probe.candidates == nil {
						p.probe.candidates = make([][]int, 0, count)
					}
					p.probe.candidates = append(p.probe.candidates, index[netip.PrefixFrom(keys.address, count-1-j).Masked()])
				}
				candidates = p.probe.candidates[j]
			} else {
				candidates = index[keys.values[j]]
			}
			for _, i := range candidates {
				if !b.spend(1) {
					return
				}
				c := right[i]
				ok, why := r.Match.match(x.Value, c.value)
				if why != "" {
					b.issue(Issue{r.Name, "invalid_match", why, entry.Key})
				}
				if !ok {
					continue
				}
				rank := 0
				if r.Rank != nil {
					n, e := read(*r.Rank, c.value)
					if e != "" {
						b.issue(Issue{r.Name, "invalid_rank", e, entry.Key})
						continue
					}
					rank = n
				}
				if best < 0 || rank > bestRank {
					best, bestRank, ties = i, rank, 1
				} else if rank == bestRank {
					ties++
				}
			}
		}
		if best < 0 {
			b.issue(Issue{r.Name, "unresolved", "no matching candidate", entry.Key})
			return
		}
		if ties != 1 {
			b.issue(Issue{r.Name, "ambiguous", "multiple distinct highest-ranked candidates", entry.Key})
			return
		}
		c := right[best]
		p.pairs = append(p.pairs, Pair[L, R]{x.Value, c.value, r.Context, v.Status().Revision, []cplane.BGPPathKey{entry.Key}, append([]cplane.BGPPathKey(nil), c.keys...)})
	})
}
