package apply

import (
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A route whose peer signalled a uSID-shaped SID Structure is installed
// with H.Encaps.Red (the data plane then emits no SRH for the single-SID
// case); a classic or structure-less route keeps H.Encaps.
func TestApplier_USIDRouteUsesReducedEncap(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.20.0.0/24", RD: "65000:20",
			SRv6SID: "fd00:aaaa:b002:d004::", NextHop: "2001:db8::2",
			SIDStructure: bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16},
		},
	})
	entry, ok := fh.v4created["10.20.0.0/24"]
	if !ok {
		t.Fatal("uSID route was not installed")
	}
	if entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED) {
		t.Errorf("mode = %d, want H_ENCAPS_RED", entry.Mode)
	}

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.21.0.0/24", RD: "65000:21",
			SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::2",
			SIDStructure: bgp.SIDStructure{LocatorBlockLen: 40, LocatorNodeLen: 24, FunctionLen: 16, ArgumentLen: 48},
		},
	})
	if entry := fh.v4created["10.21.0.0/24"]; entry == nil ||
		entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
		t.Errorf("classic route mode = %v, want H_ENCAPS", entry)
	}

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.22.0.0/24", RD: "65000:22",
			SRv6SID: "fd00:1:1:b::", NextHop: "2001:db8::2",
		},
	})
	if entry := fh.v4created["10.22.0.0/24"]; entry == nil ||
		entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
		t.Errorf("structure-less route mode = %v, want H_ENCAPS", entry)
	}
}

// A BGP UPDATE is an implicit replace: when a later update for the same
// NLRI arrives with no usable SID (e.g. its SID information failed RFC
// 9252 Sec.7 validation on decode), the previously installed path must be
// torn down rather than left serving stale state.
func TestApplier_EmptySIDUpdateReplacesInstalledPath(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	route := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.30.0.0/24", RD: "65000:30",
		SRv6SID: "fd00:aaaa:b002:d004::", NextHop: "2001:db8::2",
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &route})
	if _, ok := fh.v4created["10.30.0.0/24"]; !ok {
		t.Fatal("route was not installed")
	}

	replaced := route
	replaced.SRv6SID = ""
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &replaced})
	found := false
	for _, p := range fh.v4deleted {
		if p == "10.30.0.0/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("empty-SID update left the previous path installed (deleted=%v)", fh.v4deleted)
	}
}

// The import-RT filter also participates in replacement: a route imported
// earlier must not survive a replacement UPDATE whose RTs no longer match
// any VRF import filter.
func TestApplier_RTMismatchUpdateReplacesInstalledPath(t *testing.T) {
	fh := newFakeHeadend()
	vb := vrfbgp.NewManager()
	if err := vb.Bind(vrfbgp.Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:30"}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vb, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	route := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.31.0.0/24", RD: "65000:31",
		RTs: []string{"65000:30"}, SRv6SID: "fd00:aaaa:b002:d004::", NextHop: "2001:db8::2",
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &route})
	if _, ok := fh.v4created["10.31.0.0/24"]; !ok {
		t.Fatal("route was not installed")
	}

	replaced := route
	replaced.RTs = []string{"65000:99"}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &replaced})
	found := false
	for _, p := range fh.v4deleted {
		if p == "10.31.0.0/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("RT-mismatch update left the previous path installed (deleted=%v)", fh.v4deleted)
	}
}

// Re-advertising the same {prefix, RD, source, SID, next hop} with a newly
// uSID-shaped SID Structure must reprogram the entry: the reduced flag is
// part of the member fingerprint, so the flavor flip cannot be skipped as
// an unchanged reconcile.
func TestApplier_StructureFlipReprogramsToReducedEncap(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	route := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.32.0.0/24", RD: "65000:32",
		SRv6SID: "fd00:aaaa:b002:d004::", NextHop: "2001:db8::2",
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &route})
	entry := fh.v4created["10.32.0.0/24"]
	if entry == nil || entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
		t.Fatalf("initial install = %+v, want H_ENCAPS", entry)
	}

	usid := route
	usid.SIDStructure = bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &usid})
	entry = fh.v4created["10.32.0.0/24"]
	if entry == nil || entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED) {
		t.Errorf("after structure flip entry = %+v, want H_ENCAPS_RED", entry)
	}
}
