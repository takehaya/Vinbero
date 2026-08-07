package apply

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// fakePolicyMap records the writes the table makes to the data plane.
// deleteErr, when set, makes DeleteSRPolicy fail so the table's
// keep-state-and-retry recovery paths can be exercised.
type fakePolicyMap struct {
	upserts   []upsertCall
	deletes   []uint32
	current   map[uint32][]netip.Addr // id -> last transport written (nil = deleted)
	deleteErr error
	// highestInUse models what a restart would find still referenced in the
	// pinned maps; highestErr models that read failing.
	highestInUse uint32
	highestErr   error
}

type upsertCall struct {
	id        uint32
	transport []netip.Addr
}

func newFakePolicyMap() *fakePolicyMap {
	return &fakePolicyMap{current: map[uint32][]netip.Addr{}}
}

func (f *fakePolicyMap) UpsertSRPolicy(id uint32, transport []netip.Addr) error {
	f.upserts = append(f.upserts, upsertCall{id, transport})
	f.current[id] = transport
	return nil
}

func (f *fakePolicyMap) HighestSRPolicyIDInUse() (uint32, error) {
	return f.highestInUse, f.highestErr
}

func (f *fakePolicyMap) DeleteSRPolicy(id uint32) error {
	f.deletes = append(f.deletes, id)
	if f.deleteErr != nil {
		return f.deleteErr // simulate a data-plane delete failure
	}
	delete(f.current, id)
	return nil
}

func segs(addrs ...string) []netip.Addr {
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func bgpCand(dist, pref uint32, sids ...string) bgp.CandidatePath {
	return bgp.CandidatePath{Origin: bgp.OriginBGP, Distinguisher: dist, Preference: pref, SegmentList: segs(sids...)}
}

func policy(color uint32, endpoint string, cands ...bgp.CandidatePath) bgp.SRPolicy {
	return bgp.SRPolicy{Color: color, Endpoint: netip.MustParseAddr(endpoint), Candidates: cands}
}

func newTestTable() (*srPolicyTable, *fakePolicyMap) {
	fm := newFakePolicyMap()
	return newSRPolicyTable(fm, zap.NewNop()), fm
}

func TestSRPolicyTable_InstallAndWithdraw(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:200:0:1::")), false)

	id := tbl.idOf(100, netip.MustParseAddr("2001:db8::2"))
	if got, ok := fm.current[id]; !ok || len(got) != 1 || got[0] != netip.MustParseAddr("fd00:200:0:1::") {
		t.Fatalf("after install, map[%d] = %v, want [fd00:200:0:1::]", id, got)
	}

	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:200:0:1::")), true)
	if _, ok := fm.current[id]; ok {
		t.Errorf("after withdraw, map[%d] still present", id)
	}
	if len(fm.deletes) != 1 || fm.deletes[0] != id {
		t.Errorf("deletes = %v, want [%d]", fm.deletes, id)
	}
}

// Higher preference wins; withdrawing the active path promotes the runner-up.
func TestSRPolicyTable_PreferenceSelectionAndFailover(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 200, "fd00:2::")), false)

	id := tbl.idOf(100, netip.MustParseAddr("2001:db8::2"))
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:2::") {
		t.Fatalf("active = %v, want higher-preference fd00:2::", got)
	}

	// Withdraw the winner -> the preference-100 path takes over.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 200, "fd00:2::")), true)
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:1::") {
		t.Errorf("after failover active = %v, want fd00:1::", got)
	}
}

// On equal preference a locally configured path outranks a BGP one
// (origin tie-break, RFC 9256 §2.4: local 30 > BGP 20).
func TestSRPolicyTable_LocalBeatsBGPOnTie(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:b9::")), false)
	local := bgp.CandidatePath{Origin: bgp.OriginLocal, Distinguisher: 1, Preference: 100, SegmentList: segs("fd00:10ca::")}
	tbl.apply(policy(100, "2001:db8::2", local), false)

	id := tbl.idOf(100, netip.MustParseAddr("2001:db8::2"))
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:10ca::") {
		t.Errorf("active = %v, want local path fd00:10ca:: on tie", got)
	}
}

// Equal preference and origin -> lowest distinguisher wins, deterministically.
func TestSRPolicyTable_DistinguisherTiebreak(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(5, 100, "fd00:5::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:2::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(9, 100, "fd00:9::")), false)

	id := tbl.idOf(100, netip.MustParseAddr("2001:db8::2"))
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:2::") {
		t.Errorf("active = %v, want lowest-distinguisher fd00:2::", got)
	}
}

// A candidate with an empty transport list is ineligible (would blackhole);
// the eligible lower-preference path is chosen instead.
func TestSRPolicyTable_EmptySegmentListIneligible(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 200 /* empty */)), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:0c::")), false)

	id := tbl.idOf(100, netip.MustParseAddr("2001:db8::2"))
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:0c::") {
		t.Errorf("active = %v, want eligible fd00:0c:: despite lower preference", got)
	}
}

// Re-applying the same active path must not re-write the map (diff-and-skip).
func TestSRPolicyTable_DiffSkip(t *testing.T) {
	tbl, fm := newTestTable()
	p := policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::"))
	tbl.apply(p, false)
	tbl.apply(p, false)
	tbl.apply(p, false)
	if len(fm.upserts) != 1 {
		t.Errorf("upserts = %d, want 1 (redundant writes skipped)", len(fm.upserts))
	}
}

// policy_id is stable across updates and unique per {color, endpoint}.
func TestSRPolicyTable_PolicyIDStability(t *testing.T) {
	tbl, _ := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	a1 := tbl.ref(100, ep)
	b := tbl.ref(200, ep)
	a2 := tbl.ref(100, ep)
	if a1 != a2 {
		t.Errorf("policy_id not stable: %d then %d", a1, a2)
	}
	if a1 == b {
		t.Errorf("distinct keys share policy_id %d", a1)
	}
	// An update to the policy keeps the same id.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	if a3 := tbl.idOf(100, ep); a3 != a1 {
		t.Errorf("policy_id changed after apply: %d -> %d", a1, a3)
	}
}

// A route that reserves its policy_id before the SR Policy arrives is
// steered without being touched once the policy populates the map.
func TestSRPolicyTable_OrderIndependence(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")

	// Route side first: reserve the id; no map entry yet -> XDP falls back.
	id := tbl.ref(100, ep)
	if _, ok := fm.current[id]; ok {
		t.Fatalf("map entry present before SR Policy arrived")
	}
	// SR Policy arrives later for the same key -> same id populated.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	if got, ok := fm.current[id]; !ok || got[0] != netip.MustParseAddr("fd00:1::") {
		t.Errorf("after policy arrival map[%d] = %v, want fd00:1::", id, got)
	}
}

// Withdrawing a key that was never installed is a no-op (no panic, no delete).
func TestSRPolicyTable_WithdrawUnknown(t *testing.T) {
	tbl, fm := newTestTable()
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), true)
	if len(fm.deletes) != 0 || len(fm.upserts) != 0 {
		t.Errorf("withdraw of unknown policy touched the map: upserts=%v deletes=%v", fm.upserts, fm.deletes)
	}
}

// Releasing the last route reference with no candidate path reaps the
// policy and frees its id for reuse by the next distinct key.
func TestSRPolicyTable_RefUnrefReapsAndReusesID(t *testing.T) {
	tbl, _ := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")

	id := tbl.ref(100, ep)
	if id == 0 {
		t.Fatal("ref returned id 0")
	}
	if got := tbl.idOf(100, ep); got != id {
		t.Fatalf("idOf = %d while referenced, want %d", got, id)
	}

	tbl.unref(100, ep)
	if got := tbl.idOf(100, ep); got != 0 {
		t.Errorf("idOf = %d after last unref, want 0 (reaped)", got)
	}
	// The freed id is reused before nextID grows.
	if reused := tbl.ref(200, ep); reused != id {
		t.Errorf("new key got id %d, want reused %d", reused, id)
	}
}

// A policy stays alive while either a candidate path or a route reference
// remains; it is reaped only when both are gone.
func TestSRPolicyTable_NoReapWhileCandidateOrRefRemains(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")

	id := tbl.ref(100, ep)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)

	// Drop the route reference: the candidate path keeps the policy alive.
	tbl.unref(100, ep)
	if got := tbl.idOf(100, ep); got != id {
		t.Fatalf("policy reaped despite live candidate (idOf=%d)", got)
	}
	if _, ok := fm.current[id]; !ok {
		t.Fatalf("map entry %d dropped despite live candidate", id)
	}

	// Withdraw the candidate too: now nothing references it -> reaped.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), true)
	if got := tbl.idOf(100, ep); got != 0 {
		t.Errorf("policy not reaped after candidate withdraw (idOf=%d)", got)
	}
	if _, ok := fm.current[id]; ok {
		t.Errorf("map entry %d still present after reap", id)
	}
}

// A candidate whose transport list is too long to install (>= MaxSegments,
// since the route's service SID composes onto the tail) is ineligible: a
// usable shorter candidate wins instead of the policy silently never
// installing.
func TestSRPolicyTable_TooLongCandidateIneligible(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")

	long := make([]netip.Addr, bpf.MaxSegments) // one too long for UpsertSRPolicy
	for i := range long {
		long[i] = netip.MustParseAddr(fmt.Sprintf("fd00:f::%d", i+1))
	}
	// Higher preference, but uninstallable.
	tbl.apply(bgp.SRPolicy{Color: 100, Endpoint: ep, Candidates: []bgp.CandidatePath{
		{Origin: bgp.OriginBGP, Distinguisher: 1, Preference: 300, SegmentList: long},
	}}, false)
	// Lower preference, but installable.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:200:0:1::")), false)

	id := tbl.idOf(100, ep)
	got, ok := fm.current[id]
	if !ok || len(got) != 1 || got[0] != netip.MustParseAddr("fd00:200:0:1::") {
		t.Errorf("active = %v (ok=%v), want the installable shorter candidate fd00:200:0:1::", got, ok)
	}
}

// When the data-plane delete fails, the table must keep the state (and its
// id) rather than free an id whose stale map entry still steers traffic; a
// later candidate withdraw retries the delete and reaps once it succeeds.
func TestSRPolicyTable_GCDeleteFailureKeepsState(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	id := tbl.ref(100, ep)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	if _, ok := fm.current[id]; !ok {
		t.Fatalf("policy not installed")
	}

	fm.deleteErr = errors.New("boom")
	tbl.unref(100, ep)                                                       // refs->0 (candidate still present -> no gc delete yet)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), true) // withdraw candidate: reconcile + gc both attempt the delete and fail
	if tbl.idOf(100, ep) != id {
		t.Fatalf("state reaped despite delete failure -- id %d could be reused while its map entry persists", id)
	}
	if len(fm.deletes) == 0 {
		t.Errorf("expected at least one delete attempt during the failure window")
	}

	fm.deleteErr = nil
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), true) // retry: delete now succeeds -> reaped
	if tbl.idOf(100, ep) != 0 {
		t.Errorf("state not reaped after the delete succeeded on retry")
	}
}

// reconcile's delete-failure path must keep `installed` intact so the entry
// is not treated as gone while the map still holds it; a later active-path
// change still writes correctly.
func TestSRPolicyTable_ReconcileDeleteFailureKeepsInstalled(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	id := tbl.ref(100, ep) // refs>0 throughout so gc never reaps; isolates reconcile
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)

	fm.deleteErr = errors.New("boom")
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), true) // withdraw -> reconcile delete fails -> installed retained

	fm.deleteErr = nil
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:2::")), false) // new active path must still be written
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:2::") {
		t.Errorf("after a failed delete then a new candidate, active = %v, want fd00:2::", got)
	}
}

// unref on an unknown / unreferenced key is a no-op and must not underflow
// the reference count.
func TestSRPolicyTable_UnrefUnknownIsNoop(t *testing.T) {
	tbl, _ := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	tbl.unref(100, ep) // never referenced
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	tbl.unref(100, ep) // candidate exists but refs == 0
	if got := tbl.idOf(100, ep); got == 0 {
		t.Errorf("policy reaped by spurious unref")
	}
}

// applyLocalCapped rejects a NEW local policy beyond the cap (atomic count +
// apply), allows updating an existing one at the cap, and treats max=0 as
// unlimited. This pins the security-critical cap core directly, not via a
// server-side fake.
func TestSRPolicyTable_LocalCap(t *testing.T) {
	tbl, _ := newTestTable()
	mk := func(color uint32, ep string) bgp.SRPolicy {
		return LocalSRPolicy(color, netip.MustParseAddr(ep), segs("fd00:1::1"), 100)
	}
	if err := tbl.applyLocalCapped(mk(1, "2001:db8::1"), 2); err != nil {
		t.Fatalf("1st local policy under cap: %v", err)
	}
	if err := tbl.applyLocalCapped(mk(2, "2001:db8::2"), 2); err != nil {
		t.Fatalf("2nd local policy under cap: %v", err)
	}
	if err := tbl.applyLocalCapped(mk(3, "2001:db8::3"), 2); !errors.Is(err, ErrSRPolicyLimitReached) {
		t.Fatalf("3rd NEW policy must hit the cap, got %v", err)
	}
	// Updating an existing policy at the cap is allowed (not a new policy).
	if err := tbl.applyLocalCapped(mk(1, "2001:db8::1"), 2); err != nil {
		t.Errorf("update of an existing policy at the cap must be allowed, got %v", err)
	}
	// max=0 is unlimited.
	if err := tbl.applyLocalCapped(mk(9, "2001:db8::9"), 0); err != nil {
		t.Errorf("max=0 must be unlimited, got %v", err)
	}
}

// TestSRPolicyTable_IDsSurviveRestart covers the pinned-map restart hazard.
// sr_policy_map and the headend maps persist across a vinberod restart, but
// the id allocator does not: if it restarted from zero it would hand a new
// policy an id that a surviving headend entry still points at, steering that
// prefix onto an unrelated transport until BGP re-advertised it.
func TestSRPolicyTable_IDsSurviveRestart(t *testing.T) {
	t.Run("allocation starts above surviving ids", func(t *testing.T) {
		fm := newFakePolicyMap()
		fm.highestInUse = 7 // a pre-restart entry still references id 7
		tbl := newSRPolicyTable(fm, zap.NewNop())

		id := tbl.reserveID(10, netip.MustParseAddr("2001:db8::1"))
		if id <= 7 {
			t.Fatalf("first id after restart = %d, want > 7 (would collide with a surviving entry)", id)
		}
	})

	t.Run("no surviving state starts from one", func(t *testing.T) {
		tbl, _ := newTestTable()
		if id := tbl.reserveID(10, netip.MustParseAddr("2001:db8::1")); id != 1 {
			t.Errorf("first id on a clean start = %d, want 1", id)
		}
	})

	t.Run("distinct policies never share an id after restart", func(t *testing.T) {
		fm := newFakePolicyMap()
		fm.highestInUse = 3
		tbl := newSRPolicyTable(fm, zap.NewNop())

		seen := map[uint32]bool{}
		for i := range 5 {
			id := tbl.reserveID(uint32(100+i), netip.MustParseAddr("2001:db8::1"))
			if id <= 3 {
				t.Fatalf("policy %d got id %d, which a surviving entry may reference", i, id)
			}
			if seen[id] {
				t.Fatalf("id %d handed out twice", id)
			}
			seen[id] = true
		}
	})

	t.Run("a failed read degrades instead of blocking startup", func(t *testing.T) {
		fm := newFakePolicyMap()
		fm.highestErr = errors.New("map iterate failed")
		tbl := newSRPolicyTable(fm, zap.NewNop())
		if tbl == nil {
			t.Fatal("newSRPolicyTable must still build a usable table")
		}
		if id := tbl.reserveID(10, netip.MustParseAddr("2001:db8::1")); id == 0 {
			t.Error("table must still allocate ids after a failed read")
		}
	})
}
