package gobgp

import (
	"context"
	"errors"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// TestEncodeVPNPath_RoundTrip is the core symmetry check: a VPNRoute
// encoded for advertisement must decode back to the same fields, so the
// advertise and receive paths agree on the wire representation.
func TestEncodeVPNPath_RoundTrip(t *testing.T) {
	want := bgp.VPNRoute{
		Family:  bgp.FamilyVPNv4,
		Prefix:  "10.0.0.0/24",
		RD:      "65000:100",
		RTs:     []string{"65000:100"},
		SRv6SID: "fd00:1:1:a::",
		NextHop: "2001:db8::1",
	}
	path, err := encodeVPNPath(want)
	if err != nil {
		t.Fatalf("encodeVPNPath: %v", err)
	}
	got := decodeVPNRoute(path, bgp.FamilyVPNv4)
	if got.Prefix != want.Prefix {
		t.Errorf("Prefix round-trip: got %q, want %q", got.Prefix, want.Prefix)
	}
	if got.RD != want.RD {
		t.Errorf("RD round-trip: got %q, want %q", got.RD, want.RD)
	}
	if got.SRv6SID != want.SRv6SID {
		t.Errorf("SRv6SID round-trip: got %q, want %q", got.SRv6SID, want.SRv6SID)
	}
	if got.NextHop != want.NextHop {
		t.Errorf("NextHop round-trip: got %q, want %q", got.NextHop, want.NextHop)
	}
	if len(got.RTs) != 1 || got.RTs[0] != "65000:100" {
		t.Errorf("RTs round-trip: got %v, want [65000:100]", got.RTs)
	}
}

func TestEncodeVPNPath_VPNv6Behavior(t *testing.T) {
	// VPNv6 must advertise End.DT6, VPNv4 End.DT4.
	if got := vpnEndpointBehavior(bgp.FamilyVPNv6); got != gobgppkt.END_DT6 {
		t.Errorf("VPNv6 behavior = %v, want END_DT6", got)
	}
	if got := vpnEndpointBehavior(bgp.FamilyVPNv4); got != gobgppkt.END_DT4 {
		t.Errorf("VPNv4 behavior = %v, want END_DT4", got)
	}
}

func TestEncodeUnicastPath(t *testing.T) {
	path, err := encodeUnicastPath(bgp.UnicastRoute{
		Prefix: "2001:db8:dead::/64", NextHop: "fd00:f1b::2",
	})
	if err != nil {
		t.Fatalf("encodeUnicastPath: %v", err)
	}
	if path.Family != gobgppkt.RF_IPv6_UC {
		t.Errorf("family = %v, want RF_IPv6_UC", path.Family)
	}
	if got := decodeNextHop(path.Attrs); got != "fd00:f1b::2" {
		t.Errorf("encoded nexthop = %q, want fd00:f1b::2", got)
	}
}

func TestVinberoFamilyToAPI(t *testing.T) {
	tests := []struct {
		in   bgp.Family
		want gobgppkt.Family
	}{
		{bgp.FamilyVPNv4, gobgppkt.RF_IPv4_VPN},
		{bgp.FamilyVPNv6, gobgppkt.RF_IPv6_VPN},
		{bgp.FamilyIPv6Unicast, gobgppkt.RF_IPv6_UC},
		{bgp.FamilySRPolicyIPv6, gobgppkt.RF_SR_POLICY_IPv6},
	}
	for _, tc := range tests {
		got, err := vinberoFamilyToAPI(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("vinberoFamilyToAPI(%q) = (%v,%v), want (%v,nil)", tc.in, got, err, tc.want)
		}
	}
	if _, err := vinberoFamilyToAPI(bgp.Family("bogus")); err == nil {
		t.Error("vinberoFamilyToAPI of an unknown family should error")
	}
}

func TestAdvertise_BeforeStartRejected(t *testing.T) {
	s := newTestSession(t)
	err := s.Advertise(context.Background(), bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:1", NextHop: "2001:db8::1",
	})
	if !errors.Is(err, bgp.ErrSessionNotStarted) {
		t.Errorf("Advertise before Start: got %v, want ErrSessionNotStarted", err)
	}
}

// TestAdvertiseWithdraw drives a real in-process BgpServer: Advertise
// installs the path into the local RIB (no peer needed), Withdraw
// removes it, and a second Withdraw is a no-op.
func TestAdvertiseWithdraw(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	vr := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		RTs: []string{"65000:100"}, SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	if err := s.Advertise(context.Background(), vr); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	key := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100"}
	if err := s.Withdraw(context.Background(), key); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	// A previously-withdrawn (or never-advertised) route withdraws as a no-op.
	if err := s.Withdraw(context.Background(), key); err != nil {
		t.Errorf("second Withdraw should be a no-op, got %v", err)
	}
}

func TestAdvertiseUnicast(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	if err := s.AdvertiseUnicast(context.Background(), bgp.UnicastRoute{
		Prefix: "2001:db8:dead::/64", NextHop: "fd00:f1b::2",
	}); err != nil {
		t.Fatalf("AdvertiseUnicast: %v", err)
	}
}
