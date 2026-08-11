package apply

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func vpnEvent(prefix, rd, sid, peer string, withdraw bool) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family:     bgp.FamilyVPNv4,
		Source:     bgp.PathSource{Peer: netip.MustParseAddr(peer)},
		IsWithdraw: withdraw,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: prefix, RD: rd, SRv6SID: sid,
			NextHop: peer,
		},
	}
}

func groupSIDs(t *testing.T, fh *fakeHeadend, groupID uint32) []string {
	t.Helper()
	paths, ok := fh.ecmpGroups[groupID]
	if !ok {
		t.Fatalf("group %d was not installed", groupID)
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = netip.AddrFrom16(p.Entry.DstAddr).String()
	}
	return out
}

// TestVPNGroup_MultiPEAggregation is the defect this table exists to fix.
// Two PEs advertise one prefix under their own RDs. The old code keyed the
// headend entry by prefix under an RD-scoped owner, so the second PE's
// write failed the cross-owner check and its path was dropped entirely.
func TestVPNGroup_MultiPEAggregation(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:2", "fd00:1:1:b::", "fd00::2", false))

	trigger, ok := fh.v4created["10.0.0.0/24"]
	if !ok {
		t.Fatal("trigger entry was not installed")
	}
	if trigger.GroupId == 0 {
		t.Fatal("trigger must reference an ECMP group")
	}
	sids := groupSIDs(t, fh, trigger.GroupId)
	if len(sids) != 2 {
		t.Fatalf("group holds %d paths (%v), want both PEs", len(sids), sids)
	}
	// Deterministic order: the data plane selects by hash modulo the member
	// list, so map iteration order must not leak into path selection.
	if sids[0] >= sids[1] {
		t.Errorf("members are not sorted: %v", sids)
	}
	// The trigger's own segments are the fallback used when the group cannot
	// be resolved, so they must name a real path rather than stay empty.
	if got := netip.AddrFrom16(trigger.DstAddr).String(); got != sids[0] {
		t.Errorf("trigger fallback = %s, want the first member %s", got, sids[0])
	}
}

func TestVPNGroup_WithdrawOnePathKeepsTheRest(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:2", "fd00:1:1:b::", "fd00::2", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", true))

	trigger := fh.v4created["10.0.0.0/24"]
	if trigger == nil {
		t.Fatal("prefix must survive one PE withdrawing")
	}
	if sids := groupSIDs(t, fh, trigger.GroupId); len(sids) != 1 || sids[0] != "fd00:1:1:b::" {
		t.Fatalf("after withdraw group = %v, want only the surviving PE", sids)
	}
	if len(fh.v4deleted) != 0 {
		t.Errorf("prefix was torn down while a path remained: %v", fh.v4deleted)
	}
}

func TestVPNGroup_LastWithdrawTearsDown(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	groupID := fh.v4created["10.0.0.0/24"].GroupId
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", true))

	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != "10.0.0.0/24" {
		t.Errorf("DeleteHeadendV4 = %v, want the prefix torn down", fh.v4deleted)
	}
	if _, still := fh.ecmpGroups[groupID]; still {
		t.Error("group outlived its last path")
	}
}

// One PE re-advertising the same prefix under a second RD is the same
// forwarding outcome; programming it twice would silently double that PE's
// share of the traffic.
func TestVPNGroup_DuplicateSIDsAreDeduped(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:2", "fd00:1:1:a::", "fd00::1", false))

	trigger := fh.v4created["10.0.0.0/24"]
	if sids := groupSIDs(t, fh, trigger.GroupId); len(sids) != 1 {
		t.Fatalf("group holds %v, want one entry for one SID", sids)
	}
}

// ADD-PATH: one peer, one RD, several paths. Without PathSource in the key
// these would overwrite each other and collapse to a single path.
func TestVPNGroup_AddPathFromOnePeer(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	mk := func(pathID uint32, sid string) bgp.RouteEvent {
		ev := vpnEvent("10.0.0.0/24", "65000:1", sid, "fd00::1", false)
		ev.Source.PathID = pathID
		return ev
	}
	a.Apply(mk(1, "fd00:1:1:a::"))
	a.Apply(mk(2, "fd00:1:1:b::"))

	trigger := fh.v4created["10.0.0.0/24"]
	if sids := groupSIDs(t, fh, trigger.GroupId); len(sids) != 2 {
		t.Fatalf("group holds %v, want both ADD-PATH paths", sids)
	}
}

func TestVPNGroup_ProgrammedPathsAreCapped(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	for i := range bpf.EcmpMaxPaths + 4 {
		sid := netip.AddrFrom16([16]byte{0xfd, 0, 0, 1, 0, 1, 0, byte(i + 1)}).String()
		ev := vpnEvent("10.0.0.0/24", "65000:1", sid, "fd00::1", false)
		ev.Source.PathID = uint32(i + 1)
		a.Apply(ev)
	}
	trigger := fh.v4created["10.0.0.0/24"]
	if sids := groupSIDs(t, fh, trigger.GroupId); len(sids) != bpf.EcmpMaxPaths {
		t.Fatalf("programmed %d paths, want the data plane cap of %d", len(sids), bpf.EcmpMaxPaths)
	}
}

// A restart finds the previous run's groups still pinned. Their ids cannot
// be matched back to prefixes, so they are swept rather than left as a new
// generation of orphans, and allocation resumes above anything another
// owner still holds.
func TestVPNGroup_ResetSweepsOwnGroupsAndSkipsOthers(t *testing.T) {
	fh := newFakeHeadend()
	mine := bpf.OwnerBGPVPNGroup(65000)
	fh.ecmpOwners[1] = mine
	fh.ecmpOwners[2] = bpf.OwnerRPC
	fh.ecmpOwners[3] = mine
	fh.ecmpGroups[1] = nil
	fh.ecmpGroups[2] = nil
	fh.ecmpGroups[3] = nil

	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	if _, still := fh.ecmpOwners[1]; still {
		t.Error("group 1 was ours and should have been swept")
	}
	if _, still := fh.ecmpOwners[3]; still {
		t.Error("group 3 was ours and should have been swept")
	}
	if _, kept := fh.ecmpOwners[2]; !kept {
		t.Error("group 2 belongs to another owner and must survive")
	}
	// Allocation must not hand out 2, which another owner still holds.
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	if got := fh.v4created["10.0.0.0/24"].GroupId; got == 2 {
		t.Errorf("allocated group id %d, which another owner holds", got)
	}
}

// A group can exist with no owner recorded -- written by a build that
// predates owner tracking, or one whose owner write was lost. It is not ours
// to sweep, but its id is still occupied, so allocation must step over it.
func TestVPNGroup_ResetSkipsUnownedGroupIDs(t *testing.T) {
	fh := newFakeHeadend()
	fh.ecmpGroups[7] = nil // present in the group table, absent from the owner table

	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	// Not ours to sweep: destroying a group we cannot attribute could take
	// out one another component installed.
	if _, present := fh.ecmpGroups[7]; !present {
		t.Error("swept a group with no recorded owner")
	}
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	if got := fh.v4created["10.0.0.0/24"].GroupId; got == 7 {
		t.Errorf("allocated group id 7, which an unowned group already occupies")
	}
}

// A rolling upgrade finds the pinned headend maps holding entries written by
// the pre-aggregation code, which owned each prefix per RD. The aggregating
// writer's owner is RD-independent, so without a migration path every one of
// those prefixes fails the cross-owner check and never comes back.
func TestVPNGroup_UpgradesOffTheLegacyPerRDOwner(t *testing.T) {
	t.Run("re-advertise replaces a legacy entry", func(t *testing.T) {
		fh := newFakeHeadend()
		fh.v4owners["10.0.0.0/24"] = bpf.OwnerBGPVPN(65000, "65000:1")
		fh.v4created["10.0.0.0/24"] = &bpf.HeadendEntry{}

		a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
		a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))

		trigger := fh.v4created["10.0.0.0/24"]
		if trigger == nil || trigger.GroupId == 0 {
			t.Fatal("legacy entry blocked the aggregating writer")
		}
		if len(fh.v4forced) != 1 {
			t.Errorf("legacy entry was not cleared: forced=%v", fh.v4forced)
		}
	})

	t.Run("withdraw removes a legacy entry", func(t *testing.T) {
		// The prefix was installed before the upgrade and withdrawn before it
		// was ever re-advertised, so nothing is tracked and the old owner is
		// the only thing standing between it and a permanent stale entry.
		fh := newFakeHeadend()
		fh.v4owners["10.0.0.0/24"] = bpf.OwnerBGPVPN(65000, "65000:1")
		fh.v4created["10.0.0.0/24"] = &bpf.HeadendEntry{}

		a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
		a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "", "fd00::1", true))

		if _, still := fh.v4created["10.0.0.0/24"]; still {
			t.Error("legacy entry survived its withdraw")
		}
	})

	t.Run("another owner's entry is left alone", func(t *testing.T) {
		// An operator's RPC-installed entry for the same prefix must not be
		// destroyed by a BGP route; only this node's own legacy shape is
		// cleared.
		fh := newFakeHeadend()
		fh.v4owners["10.0.0.0/24"] = bpf.OwnerRPC
		rpcEntry := &bpf.HeadendEntry{}
		fh.v4created["10.0.0.0/24"] = rpcEntry

		a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
		a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))

		if len(fh.v4forced) != 0 {
			t.Errorf("force-deleted an entry owned by %q", bpf.OwnerRPC)
		}
		if fh.v4created["10.0.0.0/24"] != rpcEntry {
			t.Error("the RPC-owned entry was overwritten")
		}
	})
}

// Two paths can share a SID while carrying different colors. The survivor of
// the dedupe decides the programmed policy id, so it must not depend on map
// iteration order or the group would flap between reconciles.
func TestVPNGroup_DedupeIsDeterministic(t *testing.T) {
	pick := func() string {
		fh := newFakeHeadend()
		a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
		for _, rd := range []string{"65000:3", "65000:1", "65000:2"} {
			ev := vpnEvent("10.0.0.0/24", rd, "fd00:1:1:a::", "fd00::1", false)
			a.Apply(ev)
		}
		d := a.vpnGroups.dests[vpnDestKey{family: bgp.FamilyVPNv4, prefix: "10.0.0.0/24"}]
		ms := d.members()
		if len(ms) != 1 {
			t.Fatalf("expected the shared SID to dedupe to one member, got %d", len(ms))
		}
		// Identify the survivor by the key that still maps to it.
		for k, p := range d.paths {
			if p == ms[0] {
				return k.rd
			}
		}
		t.Fatal("survivor is not one of the tracked paths")
		return ""
	}
	first := pick()
	for range 20 {
		if got := pick(); got != first {
			t.Fatalf("dedupe survivor is not deterministic: %q then %q", first, got)
		}
	}
}
