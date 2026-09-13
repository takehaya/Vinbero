package demux

import (
	"reflect"
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func assertDeliveryActions(t *testing.T, got []bgp.RouteEvent, want ...bgp.RouteEvent) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actions = %+v, want %+v", got, want)
	}
}

func withdrawal(ev bgp.RouteEvent) bgp.RouteEvent {
	ev.IsWithdraw = true
	return ev
}

// VPN forwarding keys collapse RDs; other families continue to use the full
// NLRI identity. Extracting the reducer must not turn their unrelated paths
// into siblings or change the order of synthetic cleanup actions.
func TestBuiltinDeliveryStateFamilyGrouping(t *testing.T) {
	for _, family := range []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6, bgp.FamilyEVPN, bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6} {
		t.Run(string(family), func(t *testing.T) {
			state := newBuiltinDeliveryState(forwardingKey)
			claimed := func(code uint16) bool { return code == 0xFE01 }
			route := func(rd string, behavior uint16) bgp.RouteEvent {
				ev := peerEvent(family, "192.0.2.1")
				ev.EndpointBehavior = behavior
				prefix := "10.0.0.0/24"
				if family == bgp.FamilyVPNv6 || family == bgp.FamilyMUPIPv6 {
					prefix = "2001:db8::/64"
				}
				switch family {
				case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
					ev.VPN = &bgp.VPNRoute{Family: family, RD: rd, Prefix: prefix}
				case bgp.FamilyEVPN:
					ev.EVPN = &bgp.EVPNRoute{Type: bgp.EVPNRouteTypeMACIP, RD: rd, MAC: "02:00:00:00:00:01"}
				default:
					ev.MUP = &bgp.MUPRoute{Type: bgp.MUPRouteTypeISD, RD: rd, Prefix: prefix}
				}
				return ev
			}
			ordinary, private := route("65000:1", 0x0013), route("65000:2", 0xFE01)
			assertDeliveryActions(t, state.handle(ordinary, false, claimed), ordinary)
			got := state.handle(private, false, claimed)
			if ordinary.VPN != nil {
				assertDeliveryActions(t, got, withdrawal(ordinary), withdrawal(private))
			} else {
				assertDeliveryActions(t, got, withdrawal(private))
			}
			gone := withdrawal(private)
			gone.EndpointBehavior = 0
			got = state.handle(gone, true, claimed)
			if ordinary.VPN != nil {
				assertDeliveryActions(t, got, ordinary)
			} else {
				assertDeliveryActions(t, got)
			}
			assertDeliveryActions(t, state.handle(withdrawal(ordinary), false, claimed), withdrawal(ordinary))
			if len(state.groups) != 0 {
				t.Fatal("withdrawals left retained groups")
			}
		})
	}
}

// Claim release performs no replay by itself, but reevaluating a sibling can
// deliver the retained private path even when that private path has not changed.
func TestReleasedClaimReplaysPrivatePathOnSiblingEvent(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "withdraw"}[withdraw], func(t *testing.T) {
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
			ordinary := vpnEvent("65000:1", "10.0.0.0/24", 0x0013)
			private := vpnEvent("65000:2", "10.0.0.0/24", 0xFE01)
			src.emit(ordinary)
			src.emit(private)
			before := got.len()
			d.claims.Release("acl-prefix")
			if got.len() != before {
				t.Fatal("claim release replayed without a route event")
			}
			if withdraw {
				ordinary.IsWithdraw, ordinary.EndpointBehavior = true, 0
			}
			src.emit(ordinary)
			if !slices.ContainsFunc(got.got[before:], func(ev bgp.RouteEvent) bool {
				return !ev.IsWithdraw && ev.EndpointBehavior == private.EndpointBehavior && ev.VPN.RD == private.VPN.RD
			}) {
				t.Fatal("sibling event did not replay the retained private path")
			}
		})
	}
}

func TestBuiltinCleanupDispatchPrecedesPluginUpdate(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var trace []string
	if _, err := d.Register("plugin", nil, func(bgp.RouteEvent) { trace = append(trace, "plugin") }); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) {
		if ev.IsWithdraw {
			trace = append(trace, "withdraw")
		} else {
			trace = append(trace, "advertise")
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0x0013))
	trace = nil
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	if !slices.Equal(trace, []string{"withdraw", "plugin"}) {
		t.Fatalf("dispatch order = %v, want cleanup before plugin update", trace)
	}
}

func TestBuiltinDeliveryScanDoesNotKeepWithdrawnPaths(t *testing.T) {
	state := newBuiltinDeliveryState(forwardingKey)
	claimed := func(code uint16) bool { return code == 0xFE01 }
	scan := state.beginScan()
	route := vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)
	state.handle(route, false, claimed)
	state.handle(withdrawal(route), true, claimed)
	assertDeliveryActions(t, state.retract(scan, route, claimed))
	state.endScan(scan)
	if len(state.groups) != 0 || len(state.scans) != 0 {
		t.Fatal("completed scan retained withdrawn paths or scan history")
	}
}
