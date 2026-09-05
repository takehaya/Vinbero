package demux

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestRetractionClearsBuiltinStateWithoutDeliveryHistory(t *testing.T) {
	for _, observed := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent-replay", true: "reserved-before-start"}[observed], func(t *testing.T) {
			route := vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)
			src := &fakeSource{rib: map[bgp.Family][]bgp.RouteEvent{bgp.FamilyVPNv4: {route}}}
			d := claimedDemux(t, src)
			// The applier inherited this entry from another process or replay.
			installed := true
			if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) { installed = !ev.IsWithdraw }); err != nil {
				t.Fatal(err)
			}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			defer d.Stop()
			if observed {
				src.emit(route)
			}
			d.RetractClaimedFromBuiltins()
			if installed {
				t.Fatal("explicit retraction left inherited built-in state installed")
			}
		})
	}
}

func TestUnseenOrdinaryWithdrawReachesBuiltin(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var got collector
	if _, err := d.RegisterBuiltin("applier", nil, got.handle); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))
	if got.len() != 1 || !got.got[0].IsWithdraw {
		t.Fatal("unseen withdrawal was lost")
	}
}

func TestClaimedUpdateRetractsBuiltinState(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var installed bool
	if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) { installed = !ev.IsWithdraw }); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0x0013))
	if !installed {
		t.Fatal("ordinary route was not delivered")
	}
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	if installed {
		t.Fatal("claimed UPDATE left built-in state installed")
	}
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))
	if installed {
		t.Fatal("withdraw left built-in state installed")
	}
}

func TestMixedPathsWithholdTheForwardingPrefix(t *testing.T) {
	for _, rd := range []string{"65000:1", "65000:2"} {
		t.Run(rd, func(t *testing.T) {
			src := &fakeSource{}
			d := claimedDemux(t, src)
			installed := make(map[routePath]bool)
			if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) {
				path := routePath{nlriKey(ev), ev.Source}
				if ev.IsWithdraw {
					delete(installed, path)
				} else {
					installed[path] = true
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			defer d.Stop()
			src.emit(vpnEventFrom("192.0.2.1", "65000:1", "10.0.0.0/24", 0x0013))
			if len(installed) != 1 {
				t.Fatal("ordinary path was not installed")
			}
			src.emit(vpnEventFrom("192.0.2.2", rd, "10.0.0.0/24", 0xFE01))
			if len(installed) != 0 {
				t.Fatal("ordinary path was not retracted")
			}
			// Refreshing the ordinary path cannot bypass the prefix claim.
			src.emit(vpnEventFrom("192.0.2.1", "65000:1", "10.0.0.0/24", 0x0013))
			if len(installed) != 0 {
				t.Fatal("ordinary UPDATE bypassed a claimed sibling")
			}
			src.emit(vpnWithdrawFrom("192.0.2.2", rd, "10.0.0.0/24"))
			if len(installed) != 1 {
				t.Fatal("surviving ordinary path was not replayed")
			}
			src.emit(vpnWithdrawFrom("192.0.2.1", "65000:1", "10.0.0.0/24"))
			if len(installed) != 0 {
				t.Fatal("last ordinary path was not withdrawn")
			}
		})
	}
}

func TestClaimedUpdateRetractsIndependentReplay(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	installed := false
	handler := func(ev bgp.RouteEvent) { installed = !ev.IsWithdraw }
	if _, err := d.RegisterBuiltin("applier", nil, handler); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	d.BuiltinSnapshotHandler(handler)(vpnEvent("65000:1", "10.0.0.0/24", 0x0013))
	if !installed {
		t.Fatal("independent replay did not install the route")
	}
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	if installed {
		t.Fatal("claimed UPDATE left the independently replayed route installed")
	}
}

type interleavedLister struct {
	*fakeSource
	duringList func()
}

func (s *interleavedLister) ListRoutes(family bgp.Family, handler bgp.RouteHandler) error {
	if family == bgp.FamilyVPNv4 && s.duringList != nil {
		update := s.duringList
		s.duringList = nil
		update()
	}
	return s.fakeSource.ListRoutes(family, handler)
}

func TestRetractionScanCannotOverwriteLiveChanges(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "withdraw"}[withdraw], func(t *testing.T) {
			route := vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)
			src := &fakeSource{rib: map[bgp.Family][]bgp.RouteEvent{bgp.FamilyVPNv4: {route}}}
			lister := &interleavedLister{fakeSource: src}
			d := claimedDemux(t, src)
			d.lister = lister
			installed := false
			if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) { installed = !ev.IsWithdraw }); err != nil {
				t.Fatal(err)
			}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			defer d.Stop()
			src.emit(route)
			lister.duringList = func() {
				current := route
				current.EndpointBehavior = 0x0013
				current.IsWithdraw = withdraw
				src.emit(current)
			}
			d.RetractClaimedFromBuiltins()
			if installed == withdraw {
				t.Fatal("retraction scan undid the live change")
			}
			// A stale claimed path must not suppress an ordinary sibling.
			src.emit(vpnEventFrom("192.0.2.2", "65000:2", "10.0.0.0/24", 0x0013))
			if !installed {
				t.Fatal("stale snapshot path suppressed the ordinary route")
			}
		})
	}
}
