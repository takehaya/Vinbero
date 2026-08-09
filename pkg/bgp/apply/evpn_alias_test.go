package apply

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// perESAD builds a per-ES Ethernet A-D advertisement: the PE's declaration
// that it attaches the segment, carrying the Single-Active bit.
func perESAD(pe string, esi [10]byte, singleActive bool) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family: bgp.FamilyEVPN,
		EVPN: &bgp.EVPNRoute{
			Type:         bgp.EVPNRouteTypeEthernetAD,
			RD:           "65000:100",
			ESI:          esi,
			EthernetTag:  bgp.EVPNMaxEthernetTag,
			NextHop:      pe,
			SingleActive: singleActive,
		},
	}
}

// perEVIAD builds a per-EVI Ethernet A-D advertisement carrying the
// aliasing SID, resolved to bd 100 through the import RT.
func perEVIAD(rd, pe, sid string, esi [10]byte) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family: bgp.FamilyEVPN,
		EVPN: &bgp.EVPNRoute{
			Type:    bgp.EVPNRouteTypeEthernetAD,
			RD:      rd,
			RTs:     []string{"65000:100"},
			ESI:     esi,
			NextHop: pe,
			SRv6SID: sid,
		},
	}
}

func withdrawn(ev bgp.RouteEvent) bgp.RouteEvent {
	ev.IsWithdraw = true
	return ev
}

// rt2From builds an RT2 under an explicit RD, so tests can model distinct
// PEs advertising one MAC (each PE uses its own RD).
func rt2From(rd, mac, sid, pe string, esi [10]byte) *bgp.EVPNRoute {
	r := rt2(mac, sid)
	r.RD = rd
	r.SRv6SID = sid
	r.NextHop = pe
	r.ESI = esi
	return r
}

// aliasSegment advertises a two-PE all-active segment (per-ES plus per-EVI
// A-D from both PEs) and returns the applier.
func aliasSegment(t *testing.T, esi [10]byte) (*Applier, *fakeHeadend) {
	t.Helper()
	a, fh := evpnApplier(t)
	a.Apply(perESAD("fd00::2", esi, false))
	a.Apply(perESAD("fd00::3", esi, false))
	a.Apply(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi))
	a.Apply(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi))
	return a, fh
}

// esPeerOf finds the synthetic ES peer installed for bd 100: the only
// bd_peer parked in the ES range.
func esPeerOf(t *testing.T, fh *fakeHeadend) (uint16, *bpf.HeadendEntry) {
	t.Helper()
	var (
		idx   uint16
		entry *bpf.HeadendEntry
	)
	for k, e := range fh.bdPeers {
		if k.bdID != 100 || k.index < bpf.EsPeerIndexBase {
			continue
		}
		if entry != nil {
			t.Fatalf("two ES peers installed (indices %d and %d)", idx, k.index)
		}
		idx, entry = k.index, e
	}
	if entry == nil {
		t.Fatalf("no ES peer in the ES range; peers=%v", fh.bdPeers)
	}
	return idx, entry
}

func TestApplier_EVPNAliasingFormsGroup(t *testing.T) {
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := aliasSegment(t, esi)

	idx, es := esPeerOf(t, fh)
	if es.GroupId < esGroupIDBase {
		t.Errorf("ES peer group id %#x not in the EVPN partition", es.GroupId)
	}
	if es.FloodExclude != 1 {
		t.Errorf("ES peer must be flood-excluded; FloodExclude=%d", es.FloodExclude)
	}
	paths := fh.ecmpGroups[es.GroupId]
	if len(paths) != 2 {
		t.Fatalf("group holds %d members, want 2", len(paths))
	}
	if paths[0].Entry.Segments[0] == paths[1].Entry.Segments[0] {
		t.Errorf("both members carry the same SID")
	}

	// An RT2 learned on the aliased segment points at the ES peer, not at
	// the advertising PE's own bd_peer.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if fdb == nil || fdb.PeerIndex != idx {
		t.Errorf("FDB entry = %+v, want PeerIndex=%d (ES peer)", fdb, idx)
	}
}

func TestApplier_EVPNAliasingRepointsEarlierMacs(t *testing.T) {
	// The RT2 can arrive before the A-D routes; formation must adopt it.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	before := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if before.PeerIndex >= bpf.EsPeerIndexBase {
		t.Fatalf("MAC already on an ES peer before aliasing formed")
	}

	a.Apply(perESAD("fd00::2", esi, false))
	a.Apply(perESAD("fd00::3", esi, false))
	a.Apply(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi))
	a.Apply(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi))

	idx, _ := esPeerOf(t, fh)
	after := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if after == nil || after.PeerIndex != idx {
		t.Errorf("FDB entry = %+v, want repointed to ES peer %d", after, idx)
	}
}

func TestApplier_EVPNAliasingSingleActiveNotAliased(t *testing.T) {
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	a.Apply(perESAD("fd00::2", esi, true))
	a.Apply(perESAD("fd00::3", esi, true))
	a.Apply(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi))
	a.Apply(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi))
	if len(fh.ecmpGroups) != 0 {
		t.Errorf("a single-active segment was aliased: %v", fh.ecmpGroups)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if fdb == nil || fdb.PeerIndex >= bpf.EsPeerIndexBase {
		t.Errorf("FDB entry = %+v, want a per-PE peer index", fdb)
	}
}

func TestApplier_EVPNAliasingNeedsPerESAD(t *testing.T) {
	// A per-EVI A-D alone (no per-ES attachment declared) must not alias.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	a.Apply(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi))
	a.Apply(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi))
	if len(fh.ecmpGroups) != 0 {
		t.Errorf("aliased without any per-ES A-D: %v", fh.ecmpGroups)
	}
	// The attachment arriving later completes the pair.
	a.Apply(perESAD("fd00::2", esi, false))
	a.Apply(perESAD("fd00::3", esi, false))
	if len(fh.ecmpGroups) != 1 {
		t.Errorf("late per-ES A-Ds did not form the group: %v", fh.ecmpGroups)
	}
}

func TestApplier_EVPNMassWithdrawShrinksGroupKeepsMacs(t *testing.T) {
	// RFC 7432 §8.2 with aliasing in place: the departed PE leaves the
	// group, and the segment's MACs stay put -- the surviving PEs still
	// forward for them through the ES peer.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := aliasSegment(t, esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:02", "fd00:2:2:d2::", "fd00::2", esi)})

	a.Apply(withdrawn(perESAD("fd00::2", esi, false)))

	idx, es := esPeerOf(t, fh)
	paths := fh.ecmpGroups[es.GroupId]
	if len(paths) != 1 {
		t.Fatalf("group holds %d members after the withdraw, want 1", len(paths))
	}
	for _, mac := range []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"} {
		fdb := fh.fdb[fdbKey{100, mac}]
		if fdb == nil || fdb.PeerIndex != idx {
			t.Errorf("MAC %s = %+v, want kept on ES peer %d", mac, fdb, idx)
		}
	}
}

func TestApplier_EVPNAliasingDissolveRepointsMacs(t *testing.T) {
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := aliasSegment(t, esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})

	// Both PEs retract their per-EVI A-D: no member is left, so the group
	// and the ES peer go, and the MAC falls back to its advertising PE's
	// own bd_peer.
	a.Apply(withdrawn(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi)))
	a.Apply(withdrawn(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi)))

	if len(fh.ecmpGroups) != 0 {
		t.Errorf("group survived the dissolve: %v", fh.ecmpGroups)
	}
	for k := range fh.bdPeers {
		if k.index >= bpf.EsPeerIndexBase {
			t.Errorf("ES peer at index %d survived the dissolve", k.index)
		}
	}
	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if fdb == nil || fdb.PeerIndex >= bpf.EsPeerIndexBase {
		t.Errorf("FDB entry = %+v, want repointed to a per-PE peer", fdb)
	}
}

func TestApplier_EVPNSharedMacSurvivesOnePEWithdraw(t *testing.T) {
	// The pre-aliasing defect: two PEs advertise one MAC (all-active
	// multi-homing, per-PE RDs), the data-plane key {bd, MAC} is shared,
	// and one PE's RT2 withdrawal deleted it outright. The entry must
	// instead hand off to the surviving contribution.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	r2 := rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)
	r3 := rt2From("65000:100:3", "aa:bb:cc:00:00:01", "fd00:3:3:d2::", "fd00::3", esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r2})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r3})

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r2, IsWithdraw: true})

	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if fdb == nil {
		t.Fatalf("shared-key FDB entry deleted while the other PE still backs it")
	}
	peer := fh.bdPeers[bdPeerKey{100, fdb.PeerIndex}]
	if peer == nil {
		t.Fatalf("FDB points at index %d with no bd_peer behind it", fdb.PeerIndex)
	}
	want := netip.MustParseAddr("fd00:3:3:d2::").As16()
	if peer.Segments[0] != want {
		t.Errorf("survivor peer SID = %v, want fd00:3:3:d2::", peer.Segments[0])
	}

	// The last contribution going away removes the entry for real.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r3, IsWithdraw: true})
	if fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] != nil {
		t.Errorf("FDB entry survived the last contribution's withdrawal")
	}
}

func TestApplier_EVPNDissolveSweepsDepartedPEsMacs(t *testing.T) {
	// PE2 mass-withdraws while PE1 still covers the segment: PE2's MACs are
	// retained on the group. When PE1 later withdraws too and the group
	// dissolves, PE2's MACs must be swept -- pointing them back at PE2,
	// which already declared the segment gone, would re-create the
	// blackhole. PE1's own MAC falls back to PE1's per-PE peer: PE1
	// retracted aliasing (the per-EVI A-D), not its attachment.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := aliasSegment(t, esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:3", "aa:bb:cc:00:00:03", "fd00:3:3:d2::", "fd00::3", esi)})

	// PE2 (fd00::2) withdraws per-ES; its MAC is retained under the group.
	a.Apply(withdrawn(perESAD("fd00::2", esi, false)))
	if fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] == nil {
		t.Fatalf("covered MAC was swept while the group still stood")
	}

	// PE1 (fd00::3) retracts its per-EVI A-D: last member, group dissolves.
	a.Apply(withdrawn(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi)))

	if fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] != nil {
		t.Errorf("departed PE2's MAC survived the dissolve and points at a dead PE")
	}
	pe1 := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:03"}]
	if pe1 == nil || pe1.PeerIndex >= bpf.EsPeerIndexBase {
		t.Errorf("still-attached PE1's MAC = %+v, want per-PE fallback", pe1)
	}
}

func TestApplier_EVPNRT2ESIChangeReindexes(t *testing.T) {
	// The ESI is not part of the RT2 route key: a host joining a segment
	// arrives as a re-advertisement of the same NLRI with a new ESI, and
	// must not be swallowed by the unchanged-route early return.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	single := rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", [10]byte{})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: single})

	joined := rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: joined})

	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if fdb == nil || fdb.Esi != esi {
		t.Fatalf("FDB entry = %+v, want re-installed with the new ESI", fdb)
	}
	// The segment index must now cover it: a per-ES withdraw sweeps it.
	a.Apply(perESWithdraw("fd00::2", esi))
	if fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] != nil {
		t.Errorf("mass withdraw missed the MAC that joined the segment")
	}
}

func TestApplier_EVPNDissolveKeepsESPeerWhenSweepFails(t *testing.T) {
	// If a MAC cannot be moved off the ES peer, tearing the peer down would
	// leave its FDB entry pointing at nothing. The dissolve must stop and
	// keep the programmed state for a retry.
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := aliasSegment(t, esi)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN,
		EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:01", "fd00:2:2:d2::", "fd00::2", esi)})
	idx, _ := esPeerOf(t, fh)

	fh.fdbErr = fmt.Errorf("injected")
	a.Apply(withdrawn(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi)))
	a.Apply(withdrawn(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi)))

	if _, ok := fh.bdPeers[bdPeerKey{100, idx}]; !ok {
		t.Fatalf("ES peer deleted while a MAC still points at it")
	}
	if fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]; fdb == nil || fdb.PeerIndex != idx {
		t.Fatalf("FDB entry = %+v, want left on ES peer %d", fdb, idx)
	}

	// The fault clears and any event for the key retries the dissolve.
	fh.fdbErr = nil
	a.Apply(withdrawn(perESAD("fd00::3", esi, false)))
	if _, ok := fh.bdPeers[bdPeerKey{100, idx}]; ok {
		t.Errorf("ES peer survived the retried dissolve")
	}
	if fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]; fdb == nil || fdb.PeerIndex >= bpf.EsPeerIndexBase {
		t.Errorf("FDB entry = %+v, want repointed to a per-PE peer", fdb)
	}
}

func TestApplier_EVPNAliasingMemberCapAndDedupe(t *testing.T) {
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	// 10 PEs, two of which share an anycast SID: programmed members dedupe
	// to 9 and cap at the data plane's 8.
	for i := range 10 {
		pe := fmt.Sprintf("fd00::%d", i+2)
		sid := fmt.Sprintf("fd00:%d::ad", i+2)
		if i == 9 {
			sid = "fd00:2::ad" // duplicate of the first PE's SID
		}
		a.Apply(perESAD(pe, esi, false))
		a.Apply(perEVIAD(fmt.Sprintf("65000:100:%d", i+2), pe, sid, esi))
	}
	_, es := esPeerOf(t, fh)
	if got := len(fh.ecmpGroups[es.GroupId]); got != bpf.EcmpMaxPaths {
		t.Errorf("group holds %d members, want capped at %d", got, bpf.EcmpMaxPaths)
	}
}
