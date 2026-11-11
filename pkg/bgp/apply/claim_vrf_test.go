package apply

import (
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// pluginBehavior is a codepoint outside the standardized space, as an
// operator's own behavior is.
const pluginBehavior = 0xFE01

// ribSource is a route source with a loc-rib, so a test can run the replay a
// binding change requests.
type ribSource struct {
	handler bgp.RouteHandler
	rib     []bgp.RouteEvent
}

func (s *ribSource) Subscribe(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
	s.handler = h
	return func() {}, nil
}

func (s *ribSource) ListRoutes(fam bgp.Family, h bgp.RouteHandler) error {
	for _, ev := range s.rib {
		if ev.Family == fam {
			h(ev)
		}
	}
	return nil
}

// emit delivers ev live and keeps the loc-rib in step with it.
func (s *ribSource) emit(ev bgp.RouteEvent) {
	key := func(e bgp.RouteEvent) [3]string { return [3]string{e.VPN.RD, e.VPN.Prefix, e.Source.String()} }
	kept := s.rib[:0]
	for _, r := range s.rib {
		if key(r) != key(ev) {
			kept = append(kept, r)
		}
	}
	s.rib = kept
	if !ev.IsWithdraw {
		s.rib = append(s.rib, ev)
	}
	s.handler(ev)
}

type claimHarness struct {
	fh     *fakeHeadend
	vm     *vrfbgp.Manager
	claims *demux.ClaimRegistry
	demux  *demux.Demux
	src    *ribSource
}

// claimedApplier wires an applier behind a demux whose registry gives
// pluginBehavior to a plugin, the way the daemon does.
func claimedApplier(t *testing.T, vm *vrfbgp.Manager) *claimHarness {
	t.Helper()
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	src := &ribSource{}
	d := demux.New(src, src, nil)
	claims := demux.NewClaimRegistry([]uint16{0x0013})
	if err := claims.Claim("custom", []uint16{pluginBehavior}); err != nil {
		t.Fatal(err)
	}
	d.SetClaimRegistry(claims)
	d.SetVPNImportResolver(a.ImportVRFs)
	if _, err := d.RegisterBuiltin("applier", nil, a.Apply); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	return &claimHarness{fh: fh, vm: vm, claims: claims, demux: d, src: src}
}

// installed is the service SIDs written for prefix in vrfName, or nil.
func (h *claimHarness) installed(t *testing.T, vrfName, prefix string) []string {
	t.Helper()
	key := vrfKey(t, h.vm, vrfName, prefix)
	if h.fh.v4created[key] == nil {
		return nil
	}
	return groupSIDsOf(t, h.fh, key)
}

func behaving(ev bgp.RouteEvent, behavior uint16) bgp.RouteEvent {
	ev.EndpointBehavior = behavior
	return ev
}

const claimPrefix = "10.100.0.0/24"

// route is a path for claimPrefix from peer under rts; claimed paths carry the
// plugin's behavior, the others End.DT4.
func route(rd, sid, peer string, claimed bool, rts ...string) bgp.RouteEvent {
	behavior := uint16(0x0013)
	if claimed {
		behavior = pluginBehavior
	}
	return behaving(vpnEventRT(claimPrefix, rd, sid, peer, rts...), behavior)
}

// Two tenants use the same prefix. A plugin claims tenant-b's route; tenant-a's
// route for that prefix is another VRF's and still reaches the applier, in
// either order of arrival.
func TestClaimInOneVRFLeavesTheOtherTenant(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	h := claimedApplier(t, vm)
	routeA := route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1")
	routeB := route("65000:22", "fd00:b::1", "fd00::b", true, "65000:2")
	for _, order := range [][]bgp.RouteEvent{{routeA, routeB}, {routeB, routeA}} {
		for _, ev := range order {
			h.src.emit(ev)
		}
		if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
			t.Fatalf("tenant-a = %v: tenant-b's claimed route withheld tenant-a's route for the same prefix", got)
		}
		if got := h.installed(t, "tenant-b", claimPrefix); got != nil {
			t.Fatalf("tenant-b = %v: the claimed route reached the applier", got)
		}
		h.src.emit(vpnWithdraw(routeA))
		h.src.emit(vpnWithdraw(routeB))
	}
}

// Within the claimed route's VRF the claim still withholds every other path of
// the prefix, whatever its RD, and the withdraw of the claimed route gives
// them back to the applier. The other tenant is untouched throughout.
func TestClaimedRouteWithdrawRestoresItsVRF(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	h := claimedApplier(t, vm)
	routeA := route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1")
	ordinaryB := route("65000:21", "fd00:b::1", "fd00::b1", false, "65000:2")
	claimedB := route("65000:22", "fd00:b::2", "fd00::b2", true, "65000:2")
	h.src.emit(routeA)
	h.src.emit(ordinaryB)
	if got := h.installed(t, "tenant-b", claimPrefix); len(got) != 1 {
		t.Fatalf("tenant-b = %v before the claim, want its ordinary route", got)
	}
	h.src.emit(claimedB)
	if got := h.installed(t, "tenant-b", claimPrefix); got != nil {
		t.Fatalf("tenant-b = %v, want the claim to withhold the prefix in its VRF", got)
	}
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 {
		t.Fatalf("tenant-a = %v, want its route kept", got)
	}
	h.src.emit(vpnWithdraw(claimedB))
	if got := h.installed(t, "tenant-b", claimPrefix); len(got) != 1 || got[0] != "fd00:b::1" {
		t.Fatalf("tenant-b = %v after the claimed route's withdraw, want the ordinary route back", got)
	}
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 {
		t.Fatalf("tenant-a = %v, want its route kept", got)
	}
}

// A claimed route two VRFs import takes the prefix in both; a third VRF that
// does not import it keeps its own route.
func TestClaimedRouteImportedByTwoVRFs(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:shared", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:shared", "65000:2")
	bindVPN(t, vm, "tenant-c", "65000:3")
	h := claimedApplier(t, vm)
	h.src.emit(route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1"))
	h.src.emit(route("65000:21", "fd00:b::1", "fd00::b", false, "65000:2"))
	h.src.emit(route("65000:31", "fd00:c::1", "fd00::c", false, "65000:3"))
	claimed := route("65000:99", "fd00:f::1", "fd00::f", true, "65000:shared")
	h.src.emit(claimed)
	for _, vrfName := range []string{"tenant-a", "tenant-b"} {
		if got := h.installed(t, vrfName, claimPrefix); got != nil {
			t.Errorf("%s = %v, want the prefix withheld: it imports the claimed route", vrfName, got)
		}
	}
	if got := h.installed(t, "tenant-c", claimPrefix); len(got) != 1 || got[0] != "fd00:c::1" {
		t.Errorf("tenant-c = %v, want its own route: it does not import the claimed route", got)
	}
	h.src.emit(vpnWithdraw(claimed))
	for _, vrfName := range []string{"tenant-a", "tenant-b", "tenant-c"} {
		if got := h.installed(t, vrfName, claimPrefix); len(got) != 1 {
			t.Errorf("%s = %v after the claimed route's withdraw, want its own route", vrfName, got)
		}
	}
}

// An ordinary route two VRFs import is kept out of the one where a claimed
// route takes the prefix, and stays in the other.
func TestOrdinaryRouteInTwoVRFsLosesOnlyTheClaimedOne(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:shared")
	bindVPN(t, vm, "tenant-b", "65000:shared", "65000:2")
	h := claimedApplier(t, vm)
	shared := route("65000:11", "fd00:a::1", "fd00::a", false, "65000:shared")
	claimedB := route("65000:22", "fd00:b::2", "fd00::b", true, "65000:2")
	for _, order := range [][]bgp.RouteEvent{{shared, claimedB}, {claimedB, shared}} {
		for _, ev := range order {
			h.src.emit(ev)
		}
		if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
			t.Fatalf("tenant-a = %v, want the shared route", got)
		}
		if got := h.installed(t, "tenant-b", claimPrefix); got != nil {
			t.Fatalf("tenant-b = %v, want the shared route kept out where the claim takes the prefix", got)
		}
		h.src.emit(vpnWithdraw(claimedB))
		if got := h.installed(t, "tenant-b", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
			t.Fatalf("tenant-b = %v after the claimed route's withdraw, want the shared route back", got)
		}
		h.src.emit(vpnWithdraw(shared))
	}
}

// A binding change that brings the claimed route into another VRF takes the
// prefix there too once the loc-rib is replayed, and undoing it gives the
// prefix back.
func TestBindingChangeMovesTheClaim(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	h := claimedApplier(t, vm)
	replay := func() {
		t.Helper()
		if err := h.demux.ReplayBuiltin("applier", []bgp.Family{bgp.FamilyVPNv4}); err != nil {
			t.Fatal(err)
		}
	}
	h.src.emit(route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1"))
	h.src.emit(route("65000:22", "fd00:b::2", "fd00::b", true, "65000:2"))
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 {
		t.Fatalf("tenant-a = %v, want its route", got)
	}
	bindVPN(t, vm, "tenant-a", "65000:1", "65000:2")
	replay()
	if got := h.installed(t, "tenant-a", claimPrefix); got != nil {
		t.Fatalf("tenant-a = %v, want the prefix withheld once tenant-a imports the claimed route", got)
	}
	bindVPN(t, vm, "tenant-a", "65000:1")
	replay()
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
		t.Fatalf("tenant-a = %v, want its route back once it no longer imports the claimed route", got)
	}
}

// Unloading the plugin releases its claim (after the refresh, as Unregister
// does). The other tenant's route was never withheld, so it stays through the
// release, and the next event for the prefix re-evaluates the claimed VRF
// without the claim.
func TestClaimReleaseLeavesTheOtherTenant(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	h := claimedApplier(t, vm)
	routeA := route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1")
	ordinaryB := route("65000:21", "fd00:b::1", "fd00::b1", false, "65000:2")
	h.src.emit(routeA)
	h.src.emit(ordinaryB)
	h.src.emit(route("65000:22", "fd00:b::2", "fd00::b2", true, "65000:2"))
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 {
		t.Fatalf("tenant-a = %v while claimed, want its route", got)
	}
	h.demux.RefreshBuiltinClaims()
	h.claims.Release("custom")
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
		t.Fatalf("tenant-a = %v after the release, want its route", got)
	}
	h.src.emit(ordinaryB)
	if got := h.installed(t, "tenant-b", claimPrefix); len(got) == 0 {
		t.Fatal("tenant-b kept the released claim's suppression past the next event")
	}
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
		t.Fatalf("tenant-a = %v after the next event, want its route", got)
	}
}

// With no VRF binding every route is in the global VRF, so a claimed route
// withholds every path of its prefix, as on a single-VRF node.
func TestClaimInTheGlobalVRFWithholdsThePrefix(t *testing.T) {
	h := claimedApplier(t, vrfbgp.NewManager())
	ordinary := route("65000:11", "fd00:a::1", "fd00::a", false)
	h.src.emit(ordinary)
	if h.fh.v4created[claimPrefix] == nil {
		t.Fatal("ordinary route was not installed in the global VRF")
	}
	claimed := route("65000:22", "fd00:b::2", "fd00::b", true)
	h.src.emit(claimed)
	if h.fh.v4created[claimPrefix] != nil {
		t.Fatal("a claimed route in the global VRF left another path of its prefix installed")
	}
	h.src.emit(vpnWithdraw(claimed))
	if h.fh.v4created[claimPrefix] == nil {
		t.Fatal("the claimed route's withdraw did not give the prefix back")
	}
}

// A plugin registering after the routes arrived claims them through the
// loc-rib rescan. The rescan takes the prefix from the applier in the claimed
// route's VRF and leaves the other tenant's route installed.
func TestClaimRescanLeavesTheOtherTenant(t *testing.T) {
	vm := vrfbgp.NewManager()
	bindVPN(t, vm, "tenant-a", "65000:1")
	bindVPN(t, vm, "tenant-b", "65000:2")
	h := claimedApplier(t, vm)
	h.claims.Release("custom")
	h.src.emit(route("65000:11", "fd00:a::1", "fd00::a", false, "65000:1"))
	h.src.emit(route("65000:21", "fd00:b::1", "fd00::b1", false, "65000:2"))
	h.src.emit(route("65000:22", "fd00:b::2", "fd00::b2", true, "65000:2"))
	if got := h.installed(t, "tenant-b", claimPrefix); len(got) != 2 {
		t.Fatalf("tenant-b = %v before the claim, want both of its routes", got)
	}
	if err := h.claims.Claim("custom", []uint16{pluginBehavior}); err != nil {
		t.Fatal(err)
	}
	h.demux.RetractClaimedFromBuiltins()
	if got := h.installed(t, "tenant-b", claimPrefix); got != nil {
		t.Fatalf("tenant-b = %v after the rescan, want the prefix withheld", got)
	}
	if got := h.installed(t, "tenant-a", claimPrefix); len(got) != 1 || got[0] != "fd00:a::1" {
		t.Fatalf("tenant-a = %v after the rescan, want its route", got)
	}
}
