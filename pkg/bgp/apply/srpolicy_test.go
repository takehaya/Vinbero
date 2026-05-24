package apply

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// fakePolicyMap records the writes the table makes to the data plane.
type fakePolicyMap struct {
	upserts []upsertCall
	deletes []uint16
	current map[uint16][]netip.Addr // id -> last transport written (nil = deleted)
}

type upsertCall struct {
	id        uint16
	transport []netip.Addr
}

func newFakePolicyMap() *fakePolicyMap {
	return &fakePolicyMap{current: map[uint16][]netip.Addr{}}
}

func (f *fakePolicyMap) UpsertSRPolicy(id uint16, transport []netip.Addr) error {
	f.upserts = append(f.upserts, upsertCall{id, transport})
	f.current[id] = transport
	return nil
}

func (f *fakePolicyMap) DeleteSRPolicy(id uint16) error {
	f.deletes = append(f.deletes, id)
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

	id := tbl.ensureID(100, netip.MustParseAddr("2001:db8::2"))
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
	ep := netip.MustParseAddr("2001:db8::2")
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 200, "fd00:2::")), false)

	id := tbl.ensureID(100, ep)
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
	ep := netip.MustParseAddr("2001:db8::2")
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:b9::")), false)
	local := bgp.CandidatePath{Origin: bgp.OriginLocal, Distinguisher: 1, Preference: 100, SegmentList: segs("fd00:10ca::")}
	tbl.apply(policy(100, "2001:db8::2", local), false)

	id := tbl.ensureID(100, ep)
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:10ca::") {
		t.Errorf("active = %v, want local path fd00:10ca:: on tie", got)
	}
}

// Equal preference and origin -> lowest distinguisher wins, deterministically.
func TestSRPolicyTable_DistinguisherTiebreak(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	tbl.apply(policy(100, "2001:db8::2", bgpCand(5, 100, "fd00:5::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:2::")), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(9, 100, "fd00:9::")), false)

	id := tbl.ensureID(100, ep)
	if got := fm.current[id]; len(got) != 1 || got[0] != netip.MustParseAddr("fd00:2::") {
		t.Errorf("active = %v, want lowest-distinguisher fd00:2::", got)
	}
}

// A candidate with an empty transport list is ineligible (would blackhole);
// the eligible lower-preference path is chosen instead.
func TestSRPolicyTable_EmptySegmentListIneligible(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 200 /* empty */)), false)
	tbl.apply(policy(100, "2001:db8::2", bgpCand(2, 100, "fd00:0c::")), false)

	id := tbl.ensureID(100, ep)
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
	a1 := tbl.ensureID(100, netip.MustParseAddr("2001:db8::2"))
	b := tbl.ensureID(200, netip.MustParseAddr("2001:db8::2"))
	a2 := tbl.ensureID(100, netip.MustParseAddr("2001:db8::2"))
	if a1 != a2 {
		t.Errorf("policy_id not stable: %d then %d", a1, a2)
	}
	if a1 == b {
		t.Errorf("distinct keys share policy_id %d", a1)
	}
	// An update to the policy keeps the same id.
	tbl.apply(policy(100, "2001:db8::2", bgpCand(1, 100, "fd00:1::")), false)
	if a3 := tbl.ensureID(100, netip.MustParseAddr("2001:db8::2")); a3 != a1 {
		t.Errorf("policy_id changed after apply: %d -> %d", a1, a3)
	}
}

// A route that resolves its policy_id before the SR Policy arrives is
// steered without being touched once the policy populates the map.
func TestSRPolicyTable_OrderIndependence(t *testing.T) {
	tbl, fm := newTestTable()
	ep := netip.MustParseAddr("2001:db8::2")

	// Route side first: reserve the id; no map entry yet -> XDP falls back.
	id := tbl.ensureID(100, ep)
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
