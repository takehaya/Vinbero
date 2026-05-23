package apply

import (
	"net/netip"
	"sync"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// policyMapOps is the data-plane writer the SR Policy table drives. It is
// satisfied by the BPF sr_policy_map binding (Stage D) and mocked in
// tests. A policy update is one map write keyed by the opaque policyID;
// the per-route service SID is composed onto the transport list in the
// XDP program, not here.
type policyMapOps interface {
	UpsertPolicy(policyID uint32, transport []netip.Addr) error
	DeletePolicy(policyID uint32) error
}

// policyKey is the SR Policy identity (RFC 9256 §2.1). Color and endpoint
// are what overlay routes match against for auto-steering; the
// distinguisher is NOT part of the key -- it distinguishes candidate
// paths within one policy.
type policyKey struct {
	color    uint32
	endpoint netip.Addr
}

// candidateID identifies a candidate path within a policy. Origin
// disambiguates a locally configured path from a BGP-learned one that
// happens to share a distinguisher.
type candidateID struct {
	origin        bgp.Origin
	distinguisher uint32
}

type policyState struct {
	id         uint32
	candidates map[candidateID]bgp.CandidatePath
	// installed is the transport SID list last written to sr_policy_map,
	// or nil when no map entry exists. Used to skip redundant writes.
	installed []netip.Addr
}

// srPolicyTable is the in-memory SR Policy state machine. It aggregates
// candidate paths per {color, endpoint}, selects the active one (RFC 9256
// §2.9), and reflects the result into sr_policy_map with O(1) writes:
// updating or withdrawing a policy touches one map entry regardless of
// how many routes steer onto it. A withdrawn / unusable policy simply
// deletes its map entry; the XDP lookup-miss then falls the referencing
// routes back to their bare service SID.
type srPolicyTable struct {
	mu     sync.Mutex
	mapOps policyMapOps
	nextID uint32
	byKey  map[policyKey]*policyState
	logger *zap.Logger
}

func newSRPolicyTable(mapOps policyMapOps, logger *zap.Logger) *srPolicyTable {
	return &srPolicyTable{
		mapOps: mapOps,
		byKey:  make(map[policyKey]*policyState),
		logger: logger.Named("srpolicy"),
	}
}

// ensureID returns the stable policy_id for a {color, endpoint}, allocating
// one on first use. A route can resolve its policy_id before the SR Policy
// itself arrives: the map entry is absent until then, so the XDP lookup
// misses and the route falls back; when the policy arrives the same id is
// populated and the route is steered without being rewritten.
func (t *srPolicyTable) ensureID(color uint32, endpoint netip.Addr) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ensureState(policyKey{color: color, endpoint: endpoint}).id
}

// apply merges an SR Policy event (one candidate path) into the table and
// reconciles the data plane. The same path serves BGP reception and local
// CRUD; withdraw removes the candidate.
func (t *srPolicyTable) apply(p bgp.SRPolicy, withdraw bool) {
	key := policyKey{color: p.Color, endpoint: p.Endpoint}
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.byKey[key]
	if st == nil {
		if withdraw {
			return // nothing to remove
		}
		st = t.ensureState(key)
	}
	for _, cp := range p.Candidates {
		cid := candidateID{origin: cp.Origin, distinguisher: cp.Distinguisher}
		if withdraw {
			delete(st.candidates, cid)
		} else {
			st.candidates[cid] = cp
		}
	}
	t.reconcile(key, st)
}

// ensureState returns the policyState for key, allocating a stable
// policy_id on first use. Caller holds t.mu.
func (t *srPolicyTable) ensureState(key policyKey) *policyState {
	if st := t.byKey[key]; st != nil {
		return st
	}
	t.nextID++
	st := &policyState{id: t.nextID, candidates: make(map[candidateID]bgp.CandidatePath)}
	t.byKey[key] = st
	return st
}

// reconcile recomputes the active candidate and writes it to the data
// plane only when the installed transport list changed. Caller holds t.mu.
func (t *srPolicyTable) reconcile(key policyKey, st *policyState) {
	best, ok := bestCandidate(st.candidates)
	if !ok {
		// No usable candidate: drop the map entry so referencing routes
		// fall back to their bare service SID (lookup-miss).
		if st.installed != nil {
			if err := t.mapOps.DeletePolicy(st.id); err != nil {
				t.logger.Error("delete sr_policy_map entry",
					zap.Uint32("policy_id", st.id), zap.Error(err))
				return
			}
			st.installed = nil
		}
		return
	}
	if segmentsEqual(st.installed, best.SegmentList) {
		return // active path unchanged; skip a redundant write
	}
	if err := t.mapOps.UpsertPolicy(st.id, best.SegmentList); err != nil {
		t.logger.Error("upsert sr_policy_map entry",
			zap.Uint32("policy_id", st.id), zap.Error(err))
		return
	}
	st.installed = best.SegmentList
	t.logger.Info("SR Policy active path installed",
		zap.Uint32("color", key.color), zap.Stringer("endpoint", key.endpoint),
		zap.Uint32("policy_id", st.id), zap.Int("segments", len(best.SegmentList)))
}

// bestCandidate selects the active candidate path (RFC 9256 §2.9 subset):
// only paths with a non-empty transport list are eligible (an empty list
// would blackhole), and among those the winner is decided by the strict
// order in betterCandidate. ok is false when no candidate is eligible.
func bestCandidate(cands map[candidateID]bgp.CandidatePath) (bgp.CandidatePath, bool) {
	var best bgp.CandidatePath
	found := false
	for _, c := range cands {
		if len(c.SegmentList) == 0 {
			continue
		}
		if !found || betterCandidate(c, best) {
			best, found = c, true
		}
	}
	return best, found
}

// betterCandidate reports whether a should win over b: higher Preference,
// then higher Origin (local > BGP > PCEP, RFC 9256 §2.4 protocol-origin),
// then lower Distinguisher. Candidate identity ({origin, distinguisher})
// is unique within a policy, so this is a strict total order and the
// result is independent of map iteration order.
func betterCandidate(a, b bgp.CandidatePath) bool {
	if a.Preference != b.Preference {
		return a.Preference > b.Preference
	}
	if a.Origin != b.Origin {
		return a.Origin > b.Origin
	}
	return a.Distinguisher < b.Distinguisher
}

func segmentsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
