package cplane_test

import (
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func routeEvent(route cplane.Route) cplane.Event {
	return cplane.Event{Kind: cplane.EventRoute, Route: route}
}
func viewCount(v *cplane.RouteView) int {
	n := 0
	v.Range(func(cplane.PathKey, cplane.Route) { n++ })
	return n
}

func TestRouteViewSeparatesInputIdentityFromForwardingPrefix(t *testing.T) {
	base := cplane.Route{Family: "vpnv4", RD: "65000:1", Prefix: "10.0.0.7/24", Peer: "192.0.2.1", EndpointBehavior: 0xfe01, SRv6SID: "fc00::1"}
	v := cplane.RouteView{}
	v.Update([]cplane.Event{routeEvent(base)})
	alternatives := []cplane.Route{base, base, base}
	alternatives[0].RD = "65000:2"
	alternatives[1].Peer = "192.0.2.2"
	alternatives[2].PathID = 1
	for _, route := range alternatives {
		v.Update([]cplane.Event{routeEvent(route)})
	}
	if viewCount(&v) != 4 {
		t.Fatal("RD, peer or path ID collapsed distinct paths")
	}
	base.Prefix, base.Withdraw, base.EndpointBehavior = "10.0.0.0/24", true, 0
	v.Update([]cplane.Event{routeEvent(base)})
	if viewCount(&v) != 3 {
		t.Fatal("withdrawal did not match exactly one canonical input path")
	}
	v.Range(func(key cplane.PathKey, route cplane.Route) {
		if key.Prefix != "10.0.0.0/24" || route.Prefix != key.Prefix {
			t.Fatal("noncanonical prefix retained")
		}
	})
}

func TestRouteViewAcceptsOnlySupportedPrefixFamilies(t *testing.T) {
	for _, tt := range []struct {
		family, prefix string
		valid          bool
	}{
		{"vpnv4", "10.0.0.7/24", true}, {"ipv4_unicast", "10.0.0.7/24", true},
		{"vpnv6", "2001:db8::7/64", true}, {"ipv6_unicast", "2001:db8::7/64", true},
		{"vpnv4", "2001:db8::/64", false}, {"vpnv6", "10.0.0.0/24", false},
		{"vpnv6", "::ffff:10.0.0.1/128", false}, {"vpnv4", "bad", false},
		{"evpn", "10.0.0.0/24", false}, {"mup", "10.0.0.0/24", false},
	} {
		v := cplane.RouteView{}
		v.Update([]cplane.Event{routeEvent(cplane.Route{Family: tt.family, Prefix: tt.prefix})})
		if got := viewCount(&v) == 1; got != tt.valid {
			t.Fatalf("%s %s accepted=%v", tt.family, tt.prefix, got)
		}
	}
}

func TestReplayAndApplyAcknowledgementAreIndependent(t *testing.T) {
	v := cplane.RouteView{}
	v.Update([]cplane.Event{routeEvent(cplane.Route{Family: "vpnv4", Prefix: "10.0.0.0/24"})})
	if !v.Pending() {
		t.Fatal("new route not pending")
	}
	// A failed apply does not acknowledge the view; Pending remains true.
	if !v.Pending() {
		t.Fatal("pending state was consumed by reading it")
	}
	v.Applied()
	if v.Pending() {
		t.Fatal("successful apply not acknowledged")
	}
	v.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: "mac"}})
	if viewCount(&v) != 1 || v.Replaying() {
		t.Fatal("unrelated source cleared BGP routes")
	}
	v.Update([]cplane.Event{{Kind: cplane.EventStartOfReplay, ReplaySource: cplane.BGPSource}})
	v.Applied() // Cannot acknowledge an incomplete replay.
	if v.Pending() || !v.Replaying() || viewCount(&v) != 0 {
		t.Fatal("replay start applied an empty view")
	}
	v.Update([]cplane.Event{{Kind: cplane.EventEndOfReplay, ReplaySource: cplane.BGPSource}})
	if !v.Pending() || v.Replaying() {
		t.Fatal("empty replay did not request pruning")
	}
}

func TestRouteViewRemovesAnUpdatedPathRejectedByItsPolicy(t *testing.T) {
	v := cplane.RouteView{Accept: func(r cplane.Route) bool { return r.Color == 42 }}
	route := cplane.Route{Family: "vpnv4", Prefix: "10.0.0.0/24", Color: 42}
	v.Update([]cplane.Event{routeEvent(route)})
	v.Applied()
	route.Color = 7
	v.Update([]cplane.Event{routeEvent(route)})
	if viewCount(&v) != 0 || !v.Pending() {
		t.Fatal("rejected replacement left the old route")
	}
}
