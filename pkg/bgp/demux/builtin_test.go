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
			var got collector
			if _, err := d.RegisterBuiltin("applier", nil, got.handle); err != nil {
				t.Fatal(err)
			}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			defer d.Stop()
			src.emit(vpnEventFrom("192.0.2.1", "65000:1", "10.0.0.0/24", 0x0013))
			src.emit(vpnEventFrom("192.0.2.2", rd, "10.0.0.0/24", 0xFE01))
			if got.len() != 2 || !got.got[1].IsWithdraw {
				t.Fatal("ordinary path was not retracted")
			}
			// Refreshing the ordinary path cannot bypass the prefix claim.
			src.emit(vpnEventFrom("192.0.2.1", "65000:1", "10.0.0.0/24", 0x0013))
			if got.len() != 2 {
				t.Fatal("ordinary UPDATE bypassed a claimed sibling")
			}
			src.emit(vpnWithdrawFrom("192.0.2.2", rd, "10.0.0.0/24"))
			if got.len() != 3 || got.got[2].IsWithdraw {
				t.Fatal("surviving ordinary path was not replayed")
			}
			src.emit(vpnWithdrawFrom("192.0.2.1", "65000:1", "10.0.0.0/24"))
			if got.len() != 4 || !got.got[3].IsWithdraw {
				t.Fatal("last ordinary path was not withdrawn")
			}
		})
	}
}
