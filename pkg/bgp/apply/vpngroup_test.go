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
