package apply

import (
	"errors"
	"net/netip"
	"slices"
	"sync"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// localDistinguisher is the distinguisher for operator-defined (local)
// candidate paths. Phase 1e-c supports one local candidate per
// {color, endpoint}, so a fixed value suffices.
const localDistinguisher = 0

// LocalSRPolicy builds an operator-defined SR Policy (origin local) for
// {color, endpoint} with the given transport segments and preference
// (0 -> the RFC default). Pass it to Applier.ApplyLocalSRPolicy.
func LocalSRPolicy(color uint32, endpoint netip.Addr, segments []netip.Addr, preference uint32) bgp.SRPolicy {
	if preference == 0 {
		preference = bgp.SRPolicyDefaultPreference
	}
	return bgp.SRPolicy{
		Color:    color,
		Endpoint: endpoint,
		Candidates: []bgp.CandidatePath{{
			Origin:        bgp.OriginLocal,
			Distinguisher: localDistinguisher,
			Preference:    preference,
			SegmentList:   segments,
		}},
	}
}

// policyMapOps is the data-plane writer the SR Policy table drives. It is
// satisfied by the BPF sr_policy_map binding (Stage D) and mocked in
// tests. A policy update is one map write keyed by the opaque policyID;
// the per-route service SID is composed onto the transport list in the
// XDP program, not here.
type policyMapOps interface {
	UpsertSRPolicy(policyID uint32, transport []netip.Addr) error
	DeleteSRPolicy(policyID uint32) error
	// HighestSRPolicyIDInUse reports the largest policy_id the persisted
	// data plane still refers to, so the allocator can start above it after
	// a restart instead of reusing an id a surviving headend entry points
	// at. Returns 0 when the maps are empty or unpinned.
	HighestSRPolicyIDInUse() (uint32, error)
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
	id   uint32
	refs uint32 // steering routes pointing at this id; gc collects when 0
	// candidates are the candidate paths known for this {color, endpoint}.
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
//
// Each policy_id is reference-counted by the steering routes that stamp it
// (ref/unref). When a key has neither references nor candidate paths it is
// garbage-collected and its id returned to freeIDs for reuse, so churn does
// not leak ids.
type srPolicyTable struct {
	mu      sync.Mutex
	mapOps  policyMapOps
	nextID  uint32
	freeIDs []uint32 // ids freed by gc, handed out before nextID grows
	byKey   map[policyKey]*policyState
	logger  *zap.Logger
}

func newSRPolicyTable(mapOps policyMapOps, logger *zap.Logger) *srPolicyTable {
	t := &srPolicyTable{
		mapOps: mapOps,
		byKey:  make(map[policyKey]*policyState),
		logger: logger.Named("srpolicy"),
	}
	// Start the id space above anything the pinned data plane still refers
	// to. Without this a restart hands a fresh policy an id that a surviving
	// headend entry already points at, and that prefix steers onto the wrong
	// transport until BGP re-advertises it. Allocation at this point is
	// purely nextID++ (freeIDs is empty until the first gc), so raising
	// nextID is enough to keep the two disjoint.
	//
	// A failure here is not fatal: with pinning off there is nothing to
	// collide with, and with pinning on the pre-restart entries keep
	// forwarding correctly on their own ids. Log and continue with an
	// unseeded allocator rather than refuse to build the applier.
	highest, err := mapOps.HighestSRPolicyIDInUse()
	if err != nil {
		t.logger.Error("read policy ids in use; id allocation restarts from 1 "+
			"and may collide with entries that survived a restart", zap.Error(err))
		return t
	}
	if highest > 0 {
		t.nextID = highest
		t.logger.Info("resuming SR Policy id allocation above surviving entries",
			zap.Uint32("highest_in_use", highest))
	}
	return t
}

// reserveID returns the stable policy_id for {color, endpoint}, allocating
// the state on first use WITHOUT taking a reference. The applier stamps a
// headend entry with this id before writing it to the data plane, then
// commits the reference (ref, via steer) only once the write succeeds -- so
// a failed headend write never leaves a dangling reference pinning the id.
func (t *srPolicyTable) reserveID(color uint32, endpoint netip.Addr) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ensureState(policyKey{color: color, endpoint: endpoint}).id
}

// ref reserves the policy_id for {color, endpoint} on behalf of one
// steering route and bumps its reference count. A route can reserve the id
// before the SR Policy itself arrives: the map entry is absent until then,
// so the XDP lookup misses and the route falls back; when the policy
// arrives the same id is populated and the route steers without being
// rewritten.
func (t *srPolicyTable) ref(color uint32, endpoint netip.Addr) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.ensureState(policyKey{color: color, endpoint: endpoint})
	st.refs++
	return st.id
}

// unref releases one steering route's reference and garbage-collects the
// policy when nothing references it and it carries no candidate paths.
func (t *srPolicyTable) unref(color uint32, endpoint netip.Addr) {
	key := policyKey{color: color, endpoint: endpoint}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.byKey[key]
	if st == nil || st.refs == 0 {
		return
	}
	st.refs--
	t.gc(key, st)
}

// idOf returns the policy_id already reserved for {color, endpoint}, or 0
// if none. Used to re-stamp a route that re-advertises unchanged, without
// churning the reference count.
func (t *srPolicyTable) idOf(color uint32, endpoint netip.Addr) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st := t.byKey[policyKey{color: color, endpoint: endpoint}]; st != nil {
		return st.id
	}
	return 0
}

// apply merges an SR Policy event (one candidate path) into the table and
// reconciles the data plane. The same path serves BGP reception and local
// CRUD; withdraw removes the candidate.
func (t *srPolicyTable) apply(p bgp.SRPolicy, withdraw bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.applyLocked(p, withdraw)
}

// applyLocked is apply with t.mu already held, so a caller that must decide and
// mutate atomically (applyLocalCapped) can do so under one lock acquisition.
func (t *srPolicyTable) applyLocked(p bgp.SRPolicy, withdraw bool) {
	key := policyKey{color: p.Color, endpoint: p.Endpoint}
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
	if withdraw {
		// Reap the policy if that removed its last candidate and no route
		// references it; reconcile has already dropped the map entry.
		t.gc(key, st)
	}
}

// ErrSRPolicyLimitReached is returned by applyLocalCapped when a NEW local SR
// Policy would exceed the configured cap.
var ErrSRPolicyLimitReached = errors.New("local SR Policy limit reached")

// applyLocalCapped installs a local SR Policy candidate, rejecting a NEW local
// policy when it would push the local count past max (0 = unlimited). The count
// check and the apply happen under one lock acquisition, so concurrent creates
// cannot both pass an under-cap check and exceed the limit.
func (t *srPolicyTable) applyLocalCapped(p bgp.SRPolicy, max uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if max > 0 && !t.hasLocalLocked(p.Color, p.Endpoint) {
		n := 0
		for _, st := range t.byKey {
			if _, ok := st.candidates[candidateID{origin: bgp.OriginLocal, distinguisher: localDistinguisher}]; ok {
				n++
			}
		}
		if uint32(n) >= max {
			return ErrSRPolicyLimitReached
		}
	}
	t.applyLocked(p, false)
	return nil
}

// hasLocalLocked is hasLocalCandidate with t.mu already held.
func (t *srPolicyTable) hasLocalLocked(color uint32, endpoint netip.Addr) bool {
	st := t.byKey[policyKey{color: color, endpoint: endpoint}]
	if st == nil {
		return false
	}
	_, ok := st.candidates[candidateID{origin: bgp.OriginLocal, distinguisher: localDistinguisher}]
	return ok
}

// ensureState returns the policyState for key, allocating a stable
// policy_id on first use. Caller holds t.mu.
func (t *srPolicyTable) ensureState(key policyKey) *policyState {
	if st := t.byKey[key]; st != nil {
		return st
	}
	st := &policyState{id: t.allocID(key), candidates: make(map[candidateID]bgp.CandidatePath)}
	t.byKey[key] = st
	return st
}

// allocID hands out a policy_id, reusing one freed by gc before drawing a
// fresh one. policy_id is a uint32 (headend_entry.policy_id); the space is
// effectively inexhaustible, so the exhaustion guard is purely defensive --
// on exhaustion it returns 0 so the key simply never steers (safe
// degradation). Caller holds t.mu.
func (t *srPolicyTable) allocID(key policyKey) uint32 {
	if n := len(t.freeIDs); n > 0 {
		id := t.freeIDs[n-1]
		t.freeIDs = t.freeIDs[:n-1]
		return id
	}
	if t.nextID == ^uint32(0) {
		t.logger.Error("SR Policy id space exhausted; key will not steer",
			zap.Uint32("color", key.color), zap.Stringer("endpoint", key.endpoint))
		return 0
	}
	t.nextID++
	return t.nextID
}

// gc drops a policy that has no steering references and no candidate paths,
// returning its id to freeIDs for reuse. Caller holds t.mu.
func (t *srPolicyTable) gc(key policyKey, st *policyState) {
	if st.refs > 0 || len(st.candidates) > 0 {
		return
	}
	if st.installed != nil {
		if err := t.mapOps.DeleteSRPolicy(st.id); err != nil {
			t.logger.Error("gc: delete sr_policy_map entry",
				zap.Uint32("policy_id", st.id), zap.Error(err))
			// Keep the state (and its id) so the stale map entry is never
			// orphaned under a reused id. A later candidate withdraw re-runs
			// reconcile + gc and retries the delete.
			return
		}
		st.installed = nil
	}
	delete(t.byKey, key)
	if st.id != 0 {
		t.freeIDs = append(t.freeIDs, st.id)
	}
}

// reconcile recomputes the active candidate and writes it to the data
// plane only when the installed transport list changed. Caller holds t.mu.
func (t *srPolicyTable) reconcile(key policyKey, st *policyState) {
	best, ok := bestCandidate(st.candidates)
	if !ok {
		// No usable candidate: drop the map entry so referencing routes
		// fall back to their bare service SID (lookup-miss).
		if st.installed != nil {
			if err := t.mapOps.DeleteSRPolicy(st.id); err != nil {
				t.logger.Error("delete sr_policy_map entry",
					zap.Uint32("policy_id", st.id), zap.Error(err))
				return
			}
			st.installed = nil
		}
		return
	}
	if slices.Equal(st.installed, best.SegmentList) {
		return // active path unchanged; skip a redundant write
	}
	if err := t.mapOps.UpsertSRPolicy(st.id, best.SegmentList); err != nil {
		t.logger.Error("upsert sr_policy_map entry",
			zap.Uint32("policy_id", st.id), zap.Error(err))
		return
	}
	// Clone so `installed` does not alias the candidate's slice: the
	// diff-skip above must compare against a stable snapshot.
	st.installed = slices.Clone(best.SegmentList)
	t.logger.Info("SR Policy active path installed",
		zap.Uint32("color", key.color), zap.Stringer("endpoint", key.endpoint),
		zap.Uint32("policy_id", st.id), zap.Int("segments", len(best.SegmentList)))
}

// bestCandidate selects the active candidate path (RFC 9256 §2.9 subset).
// A candidate is eligible only if its transport list is installable: a
// non-empty list (an empty one would blackhole) that still leaves room for
// the route's service SID composed onto the tail. UpsertSRPolicy rejects a
// transport of MaxSegments or longer, so such a candidate could win
// best-path yet never install, silently leaving the policy down -- treat it
// as ineligible here instead. Among eligible candidates the winner is the
// strict order in betterCandidate. ok is false when none is eligible.
func bestCandidate(cands map[candidateID]bgp.CandidatePath) (bgp.CandidatePath, bool) {
	var best bgp.CandidatePath
	found := false
	for _, c := range cands {
		if len(c.SegmentList) == 0 || len(c.SegmentList) >= bpf.MaxSegments {
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

// SRPolicySnapshot is a read-only view of one {color, endpoint} policy,
// returned by the applier for SrPolicyService / vbctl introspection.
type SRPolicySnapshot struct {
	Color      uint32
	Endpoint   netip.Addr
	PolicyID   uint32
	Candidates []CandidateSnapshot
}

// CandidateSnapshot is one candidate path within an SRPolicySnapshot.
// Active marks the path currently installed in the data plane.
type CandidateSnapshot struct {
	Origin        bgp.Origin
	Distinguisher uint32
	Preference    uint32
	SegmentList   []netip.Addr
	Active        bool
}

// list returns a snapshot of every known policy, marking the active
// candidate per key.
func (t *srPolicyTable) list() []SRPolicySnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]SRPolicySnapshot, 0, len(t.byKey))
	for key, st := range t.byKey {
		best, hasBest := bestCandidate(st.candidates)
		snap := SRPolicySnapshot{Color: key.color, Endpoint: key.endpoint, PolicyID: st.id}
		for cid, cp := range st.candidates {
			snap.Candidates = append(snap.Candidates, CandidateSnapshot{
				Origin:        cp.Origin,
				Distinguisher: cp.Distinguisher,
				Preference:    cp.Preference,
				SegmentList:   cp.SegmentList,
				Active:        hasBest && cid.origin == best.Origin && cid.distinguisher == best.Distinguisher,
			})
		}
		out = append(out, snap)
	}
	return out
}

// hasLocalCandidate reports whether key has an operator-defined (local)
// candidate path. Used by SrPolicyDelete to reject removing a policy that
// is only known via BGP.
func (t *srPolicyTable) hasLocalCandidate(color uint32, endpoint netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hasLocalLocked(color, endpoint)
}
