package apply

import (
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// placeVPN places one received path in vrfs, so the per-VRF bookkeeping can
// be exercised with any set of VRFs.
func placeVPN(a *Applier, ev bgp.RouteEvent, vrfs ...uint32) {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	vr := ev.VPN
	path, _ := selectVPNPath(vr, true)
	a.placeVPNRoute(vpnRouteKey{family: vr.Family, prefix: vr.Prefix, path: vpnPathKey{rd: vr.RD, source: ev.Source}}, path, vrfs)
}

// One path placed in two VRFs gets a trigger and a group in each; moving it
// to one VRF removes it from the other; a withdraw, which carries no RT,
// removes it from every VRF it is in. The same prefix from another PE in a
// third VRF is a group of its own and never mixes with them.
func TestVPNPlacementPerVRF(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	const prefix = "10.0.0.0/24"
	pe1 := vpnEvent(prefix, "65000:1", "fd00:1:1:a::", "fd00::1", false)
	pe2 := vpnEvent(prefix, "65000:2", "fd00:2:2:b::", "fd00::2", false)

	placeVPN(a, pe1, 7, 8)
	placeVPN(a, pe2, 9)
	t7, t8, t9 := fh.v4created["vrf 7 "+prefix], fh.v4created["vrf 8 "+prefix], fh.v4created["vrf 9 "+prefix]
	if t7 == nil || t8 == nil || t9 == nil || fh.v4created[prefix] != nil {
		t.Fatalf("triggers: vrf7 %v vrf8 %v vrf9 %v global %v; want one in each tenant VRF, none global", t7, t8, t9, fh.v4created[prefix])
	}
	if t7.GroupId == t8.GroupId || t8.GroupId == t9.GroupId || t7.GroupId == t9.GroupId {
		t.Fatalf("group ids %d %d %d, want one group per VRF", t7.GroupId, t8.GroupId, t9.GroupId)
	}
	for _, id := range []uint32{t7.GroupId, t8.GroupId} {
		if g := fh.ecmpGroups[id]; len(g) != 1 || g[0].Entry.DstAddr != t7.DstAddr {
			t.Errorf("group %d = %+v, want pe1's path alone", id, g)
		}
	}
	if g := fh.ecmpGroups[t9.GroupId]; len(g) != 1 || g[0].Entry.DstAddr == t7.DstAddr {
		t.Errorf("vrf 9 group = %+v, want pe2's path alone", g)
	}

	placeVPN(a, pe1, 8)
	if fh.v4created["vrf 7 "+prefix] != nil || fh.v4created["vrf 8 "+prefix] == nil {
		t.Fatal("moving the path to vrf 8 alone must remove it from vrf 7 and keep vrf 8")
	}

	withdraw := pe1
	withdraw.IsWithdraw = true
	withdraw.VPN = &bgp.VPNRoute{Family: pe1.VPN.Family, Prefix: prefix, RD: pe1.VPN.RD}
	a.Apply(withdraw)
	if fh.v4created["vrf 8 "+prefix] != nil {
		t.Fatal("a withdraw must remove the path from every VRF it was placed in")
	}
	if fh.v4created["vrf 9 "+prefix] == nil {
		t.Fatal("withdrawing pe1 removed pe2's path in another VRF")
	}
	if len(a.vpnGroups.placed) != 1 {
		t.Errorf("placed = %v, want pe2's path only", a.vpnGroups.placed)
	}
}
