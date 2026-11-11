package apply

import (
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// bindVPN binds vrfName to import the vpnv4 route targets rts.
func bindVPN(t *testing.T, vm *vrfbgp.Manager, vrfName string, rts ...string) {
	t.Helper()
	var fp vrfbgp.FamilyPolicy
	for _, rt := range rts {
		fp.RouteTargets = append(fp.RouteTargets, vrfbgp.RouteTarget{RT: rt, Direction: vrfbgp.DirectionImport})
	}
	if err := vm.Bind(vrfbgp.Binding{VRFName: vrfName, Families: map[bgp.Family]vrfbgp.FamilyPolicy{bgp.FamilyVPNv4: fp}}); err != nil {
		t.Fatalf("Bind %s: %v", vrfName, err)
	}
}

func vpnEventRT(prefix, rd, sid, peer string, rts ...string) bgp.RouteEvent {
	ev := vpnEvent(prefix, rd, sid, peer, false)
	ev.VPN.RTs = rts
	return ev
}

func vpnWithdraw(ev bgp.RouteEvent) bgp.RouteEvent {
	w := ev
	w.IsWithdraw = true
	w.VPN = &bgp.VPNRoute{Family: ev.VPN.Family, Prefix: ev.VPN.Prefix, RD: ev.VPN.RD}
	return w
}

// groupSIDsOf is the service SIDs of the group the trigger at key points at.
func groupSIDsOf(t *testing.T, fh *fakeHeadend, key string) []string {
	t.Helper()
	trigger := fh.v4created[key]
	if trigger == nil {
		t.Fatalf("no trigger %q", key)
	}
	return groupSIDs(t, fh, trigger.GroupId)
}

// The same prefix advertised by two PEs under two tenants' route targets is
// two destinations: each tenant's VRF gets a trigger and a group holding its
// own PE's path only, and nothing is written in the global VRF.
func TestVPNSamePrefixTwoTenantsTwoPEs(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	const prefix = "10.100.0.0/24"
	a.Apply(vpnEventRT(prefix, "65000:11", "fd00:a::1", "fd00::a", "65000:1"))
	a.Apply(vpnEventRT(prefix, "65000:22", "fd00:b::1", "fd00::b", "65000:2"))

	if got := groupSIDsOf(t, fh, vrfKey(t, vm, "tenant-a", prefix)); len(got) != 1 || got[0] != "fd00:a::1" {
		t.Errorf("tenant-a group = %v, want PE A's SID only", got)
	}
	if got := groupSIDsOf(t, fh, vrfKey(t, vm, "tenant-b", prefix)); len(got) != 1 || got[0] != "fd00:b::1" {
		t.Errorf("tenant-b group = %v, want PE B's SID only", got)
	}
	if fh.v4created[prefix] != nil {
		t.Error("a tenant route was written in the global VRF")
	}
}

// A route whose RT two VRFs import is installed in both, and its withdraw,
// which carries no RT, removes it from both. Another PE's path for the same
// prefix that only one VRF imports keeps that VRF's destination.
func TestVPNRouteImportedByTwoVRFs(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:shared")
	bindVPN(t, vm, "tenant-b", "65000:shared", "65000:b")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	const prefix = "10.200.0.0/24"
	shared := vpnEventRT(prefix, "65000:1", "fd00:c::1", "fd00::c", "65000:shared")
	onlyB := vpnEventRT(prefix, "65000:2", "fd00:d::1", "fd00::d", "65000:b")
	a.Apply(shared)
	a.Apply(onlyB)
	keyA, keyB := vrfKey(t, vm, "tenant-a", prefix), vrfKey(t, vm, "tenant-b", prefix)
	if got := groupSIDsOf(t, fh, keyA); len(got) != 1 || got[0] != "fd00:c::1" {
		t.Errorf("tenant-a group = %v, want the shared route only", got)
	}
	if got := groupSIDsOf(t, fh, keyB); len(got) != 2 {
		t.Errorf("tenant-b group = %v, want the shared route and its own", got)
	}

	a.Apply(vpnWithdraw(shared))
	if fh.v4created[keyA] != nil {
		t.Error("the withdraw left the shared route in tenant-a")
	}
	if got := groupSIDsOf(t, fh, keyB); len(got) != 1 || got[0] != "fd00:d::1" {
		t.Errorf("tenant-b group after the withdraw = %v, want its own route only", got)
	}
}

// A binding change moves a route between VRFs when the route is delivered
// again (as the loc-rib replay the change requests does): moving the RT from
// tenant-a to tenant-b takes the route out of tenant-a and puts it in
// tenant-b; removing the last import of it leaves no VRF holding it.
func TestVPNBindingChangeMovesRoute(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:9")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	const prefix = "10.50.0.0/24"
	ev := vpnEventRT(prefix, "65000:5", "fd00:e::1", "fd00::e", "65000:1")
	a.Apply(ev)
	keyA, keyB := vrfKey(t, vm, "tenant-a", prefix), vrfKey(t, vm, "tenant-b", prefix)
	if fh.v4created[keyA] == nil || fh.v4created[keyB] != nil {
		t.Fatal("the route must start in tenant-a only")
	}

	bindVPN(t, vm, "tenant-a", "65000:9")
	bindVPN(t, vm, "tenant-b", "65000:1")
	a.Apply(ev)
	if fh.v4created[keyA] != nil || fh.v4created[keyB] == nil {
		t.Fatalf("after the RT moved: tenant-a %v tenant-b %v, want tenant-b only", fh.v4created[keyA], fh.v4created[keyB])
	}

	bindVPN(t, vm, "tenant-b", "65000:9")
	a.Apply(ev)
	if fh.v4created[keyA] != nil || fh.v4created[keyB] != nil || fh.v4created[prefix] != nil {
		t.Fatal("a route no VRF imports must not stay in any VRF")
	}
	if len(a.vpnGroups.dests) != 0 || len(a.vpnGroups.placed) != 0 {
		t.Errorf("tracking left: dests %v placed %v", a.vpnGroups.dests, a.vpnGroups.placed)
	}
}

func bindMUP(t *testing.T, vm *vrfbgp.Manager, vrfName string, rts ...string) {
	t.Helper()
	var fp vrfbgp.FamilyPolicy
	for _, rt := range rts {
		fp.RouteTargets = append(fp.RouteTargets, vrfbgp.RouteTarget{RT: rt, Direction: vrfbgp.DirectionImport})
	}
	if err := vm.Bind(vrfbgp.Binding{VRFName: vrfName, Families: map[bgp.Family]vrfbgp.FamilyPolicy{bgp.FamilyMUPIPv4: fp}}); err != nil {
		t.Fatalf("Bind %s: %v", vrfName, err)
	}
}

// Two T2ST sessions on the same endpoint and TEID in two VRFs each have a
// gate of their own VRF: withdrawing one leaves the other VRF's gate, and the
// global VRF never gets one.
func TestMUPGatePerVRF(t *testing.T) {
	const endpoint = "192.0.2.100"
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindMUP(t, vm, "vpn-a", "100:1")
	bindMUP(t, vm, "vpn-b", "100:2")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	t2 := func(rd, rt string) bgp.RouteEvent {
		ev := mupT2ST(rd, endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::")
		ev.MUP.RTs = []string{rt}
		return ev
	}
	evA, evB := t2("65100:1", "100:1"), t2("65100:2", "100:2")
	a.Apply(evA)
	a.Apply(evB)
	gateA, gateB := vrfKey(t, vm, "vpn-a", endpoint+"/32"), vrfKey(t, vm, "vpn-b", endpoint+"/32")
	if fh.v4created[gateA] == nil || fh.v4created[gateB] == nil || fh.v4created[endpoint+"/32"] != nil {
		t.Fatalf("gates: vpn-a %v vpn-b %v global %v, want one in each tenant VRF", fh.v4created[gateA], fh.v4created[gateB], fh.v4created[endpoint+"/32"])
	}
	wd := evA
	wd.IsWithdraw = true
	a.Apply(wd)
	if fh.v4created[gateA] != nil || fh.v4created[gateB] == nil {
		t.Fatal("withdrawing vpn-a's session must remove vpn-a's gate and keep vpn-b's")
	}
}

// A binding change moves a T2ST's F-TEID entry and gate to the new VRF, and
// a T1ST's downlink entry too; a session no binding imports any more is
// removed.
func TestMUPBindingChangeMovesSessions(t *testing.T) {
	const (
		endpoint = "192.0.2.100"
		ue       = "10.1.0.1/32"
	)
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindMUP(t, vm, "vpn-a", testRTDirect, testRTInterwork)
	bindMUP(t, vm, "vpn-b", "100:9")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::"))
	a.Apply(mupT1ST("65100:1", ue, "172.16.0.1", 256, 9, "fd00:a:0:1::"))
	idA, _ := vm.VRF().IDForName("vpn-a")
	idB, _ := vm.VRF().IDForName("vpn-b")
	gate := endpoint + "/32"
	if fh.v4created[fakeHeadendKey(idA, gate)] == nil || fh.v4created[fakeHeadendKey(idA, ue)] == nil {
		t.Fatal("the sessions must start in vpn-a")
	}
	if _, ok := fh.mupUplink[mupUplinkKey{idA, endpoint, 0x100, 32}]; !ok {
		t.Fatal("the uplink must start in vpn-a")
	}

	bindMUP(t, vm, "vpn-a", "100:9")
	bindMUP(t, vm, "vpn-b", testRTDirect, testRTInterwork)
	a.ReconcileMUPUplinkInstances()
	if fh.v4created[fakeHeadendKey(idA, gate)] != nil || fh.v4created[fakeHeadendKey(idB, gate)] == nil {
		t.Error("the gate did not move to vpn-b")
	}
	if fh.v4created[fakeHeadendKey(idA, ue)] != nil || fh.v4created[fakeHeadendKey(idB, ue)] == nil {
		t.Error("the downlink did not move to vpn-b")
	}
	if _, ok := fh.mupUplink[mupUplinkKey{idB, endpoint, 0x100, 32}]; !ok {
		t.Error("the uplink did not move to vpn-b")
	}
	if _, ok := fh.mupUplink[mupUplinkKey{idA, endpoint, 0x100, 32}]; ok {
		t.Error("the uplink stayed in vpn-a")
	}

	bindMUP(t, vm, "vpn-b", "100:9")
	a.ReconcileMUPUplinkInstances()
	for _, k := range []string{fakeHeadendKey(idB, gate), fakeHeadendKey(idB, ue), gate, ue} {
		if fh.v4created[k] != nil {
			t.Errorf("%s left after no binding imports the sessions", k)
		}
	}
	if len(fh.mupUplink) != 0 || len(a.mupT1ST) != 0 || len(a.mupT2ST) != 0 {
		t.Errorf("uplinks %v, T1ST %d, T2ST %d left, want none", fh.mupUplink, len(a.mupT1ST), len(a.mupT2ST))
	}
}
