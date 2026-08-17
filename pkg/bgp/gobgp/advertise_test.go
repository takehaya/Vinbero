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
	if got := vpnEndpointBehavior(bgp.VPNRoute{Family: bgp.FamilyVPNv6}); got != gobgppkt.END_DT6 {
		t.Errorf("VPNv6 behavior = %v, want END_DT6", got)
	}
	if got := vpnEndpointBehavior(bgp.VPNRoute{Family: bgp.FamilyVPNv4}); got != gobgppkt.END_DT4 {
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

// TestAdvertise_ReAdvertiseSupersedesPath checks that re-advertising the
// same route replaces the tracked path instead of orphaning it: gobgp
// mints a fresh UUID per AddPath, and addAndTrack must delete the prior
// path so the RIB and the advertised map do not accumulate orphans. If
// the superseded-path delete failed, the second Advertise would error.
func TestAdvertise_ReAdvertiseSupersedesPath(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	vr := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	if err := s.Advertise(context.Background(), vr); err != nil {
		t.Fatalf("first Advertise: %v", err)
	}
	key := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100"}
	s.advMu.Lock()
	first := s.advertised[key]
	s.advMu.Unlock()

	if err := s.Advertise(context.Background(), vr); err != nil {
		t.Fatalf("re-Advertise: %v", err)
	}
	s.advMu.Lock()
	second, ok := s.advertised[key]
	n := len(s.advertised)
	s.advMu.Unlock()

	if !ok {
		t.Fatal("re-advertised route is no longer tracked")
	}
	if n != 1 {
		t.Errorf("advertised map holds %d entries, want 1 (no orphan)", n)
	}
	if first == second {
		t.Error("re-advertise must record a fresh gobgp path UUID")
	}
	// The superseded path is gone; one Withdraw fully removes the route.
	if err := s.Withdraw(context.Background(), key); err != nil {
		t.Fatalf("Withdraw after re-advertise: %v", err)
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

// A plugin advertising a behavior it implements itself names the codepoint
// on the route. It is not checked against the behaviors vinbero knows,
// because an unrecognized one is exactly the point.
func TestVPNEndpointBehaviorOverride(t *testing.T) {
	r := bgp.VPNRoute{Family: bgp.FamilyVPNv4, EndpointBehavior: 0xFE01}
	if got := vpnEndpointBehavior(r); uint16(got) != 0xFE01 {
		t.Fatalf("behavior = %#x, want the route's own %#x", uint16(got), 0xFE01)
	}
	// Zero still means the family default, so ordinary routes are
	// unaffected.
	if got := vpnEndpointBehavior(bgp.VPNRoute{Family: bgp.FamilyVPNv4}); got != gobgppkt.END_DT4 {
		t.Fatalf("behavior = %v, want End.DT4 for a route naming none", got)
	}
}

// gobgp keeps one local path per NLRI, so everything originating through
// one session shares it: the exporter, the operator's RPC and any
// control-plane plugin. A plugin withdrawing a route it did not advertise
// would delete one that is still wanted, and the producer that owns it
// would go on believing it is advertised.
func TestWithdraw_LeavesAnotherProducersRouteAlone(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	vr := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	// Advertised by vinbero's own machinery, which names nothing.
	if err := s.Advertise(context.Background(), vr); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	key := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100"}

	plugin := s.AsProducer("cplane-plugins")
	if err := plugin.Withdraw(context.Background(), key); err != nil {
		t.Fatalf("Withdraw by another producer: %v", err)
	}
	s.advMu.Lock()
	_, still := s.advertised[key]
	s.advMu.Unlock()
	if !still {
		t.Fatal("a plugin's withdraw deleted a route vinbero advertised")
	}

	// Its own route it may withdraw.
	plugged := vr
	plugged.Prefix = "10.9.0.0/24"
	if err := plugin.Advertise(context.Background(), plugged); err != nil {
		t.Fatalf("plugin Advertise: %v", err)
	}
	ownKey := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.9.0.0/24", RD: "65000:100"}
	if err := plugin.Withdraw(context.Background(), ownKey); err != nil {
		t.Fatalf("plugin Withdraw: %v", err)
	}
	s.advMu.Lock()
	_, gone := s.advertised[ownKey]
	s.advMu.Unlock()
	if gone {
		t.Error("a plugin could not withdraw the route it advertised")
	}
}

// One NLRI carries one local path, so a second producer cannot take a
// route over: doing so discards the first producer's UUID, and the second
// one's withdraw would then remove a route the first still believes it is
// advertising.
func TestAdvertise_RefusesAnotherProducersRoute(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	vr := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	if err := s.Advertise(context.Background(), vr); err != nil {
		t.Fatalf("Advertise: %v", err)
	}
	key := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100"}
	s.advMu.Lock()
	first := s.advertised[key]
	s.advMu.Unlock()

	plugin := s.AsProducer("cplane-plugins")
	if err := plugin.Advertise(context.Background(), vr); err == nil {
		t.Fatal("a second producer took over a route another one advertises")
	}
	s.advMu.Lock()
	after, still := s.advertised[key]
	holder := s.producers[key]
	s.advMu.Unlock()
	if !still || after != first {
		t.Error("the refused advertise disturbed the route it could not take")
	}
	if holder != "" {
		t.Errorf("the route is recorded against %q, want the producer that advertised it", holder)
	}
	// The original producer can still withdraw its own route.
	if err := s.Withdraw(context.Background(), key); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
}

// Two producers advertising the same new NLRI at once must not both get
// through: the second would overwrite the first's path and UUID, and the
// first would go on believing it is advertising.
func TestAdvertise_ConcurrentProducersCannotBothClaimAKey(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)

	vr := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	plugin := s.AsProducer("cplane-plugins")

	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, adv := range []interface {
		Advertise(context.Context, bgp.VPNRoute) error
	}{s, plugin} {
		go func(a interface {
			Advertise(context.Context, bgp.VPNRoute) error
		}) {
			<-start
			errs <- a.Advertise(context.Background(), vr)
		}(adv)
	}
	close(start)

	var failures int
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("%d of 2 concurrent advertises failed, want exactly 1 refused", failures)
	}

	key := bgp.RouteKey{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100"}
	s.advMu.Lock()
	_, live := s.advertised[key]
	s.advMu.Unlock()
	if !live {
		t.Error("the winner's route is not tracked")
	}
}
