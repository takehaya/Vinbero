package apply

import (
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/prober"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

type fakeProber struct {
	registered   map[uint32][]prober.Target
	unregistered []uint32
}

func newFakeProber() *fakeProber {
	return &fakeProber{registered: map[uint32][]prober.Target{}}
}

func (f *fakeProber) Register(groupID uint32, targets []prober.Target) {
	f.registered[groupID] = targets
}

func (f *fakeProber) Unregister(groupID uint32) {
	delete(f.registered, groupID)
	f.unregistered = append(f.unregistered, groupID)
}

func TestProberWiring_VPNGroupRegistersNextHops(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	fp := newFakeProber()
	a.SetProber(fp)

	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:2", "fd00:1:1:b::", "fd00::2", false))

	trigger := fh.v4created["10.0.0.0/24"]
	targets := fp.registered[trigger.GroupId]
	if len(targets) != 2 {
		t.Fatalf("registered %d targets, want both PEs: %+v", len(targets), targets)
	}
	// Members are SID-sorted; the probe destinations must be their PEs'
	// next hops, and a single-segment member yields no transport SRH.
	if targets[0].Dst != netip.MustParseAddr("fd00::1") || targets[1].Dst != netip.MustParseAddr("fd00::2") {
		t.Errorf("probe destinations = %v / %v", targets[0].Dst, targets[1].Dst)
	}
	for _, tg := range targets {
		if len(tg.Segments) != 0 {
			t.Errorf("single-segment member carries transport segments: %v", tg.Segments)
		}
	}

	// The last path withdrawing retires the group and the registration.
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", true))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:2", "fd00:1:1:b::", "fd00::2", true))
	if len(fp.registered) != 0 {
		t.Errorf("registrations survived the retire: %v", fp.registered)
	}
	if len(fp.unregistered) == 0 {
		t.Errorf("Unregister was never called")
	}
}

func TestProberWiring_EVPNSegmentRegistersPEs(t *testing.T) {
	esi := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	a, fh := evpnApplier(t)
	fp := newFakeProber()
	a.SetProber(fp)

	a.Apply(perESAD("fd00::2", esi, false))
	a.Apply(perESAD("fd00::3", esi, false))
	a.Apply(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi))
	a.Apply(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi))

	_, es := esPeerOf(t, fh)
	targets := fp.registered[es.GroupId]
	if len(targets) != 2 {
		t.Fatalf("registered %d targets, want both member PEs: %+v", len(targets), targets)
	}
	if targets[0].Dst != netip.MustParseAddr("fd00::2") || targets[1].Dst != netip.MustParseAddr("fd00::3") {
		t.Errorf("probe destinations = %v / %v", targets[0].Dst, targets[1].Dst)
	}

	// Dissolving the segment unregisters it.
	a.Apply(withdrawn(perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", esi)))
	a.Apply(withdrawn(perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", esi)))
	if len(fp.registered) != 0 {
		t.Errorf("registrations survived the dissolve: %v", fp.registered)
	}
}

// coloredVPNEvent is a VPNv4 advertisement steered onto {color, nh}.
func coloredVPNEvent(prefix, rd, sid, nh string, color uint32) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: prefix, RD: rd,
		SRv6SID: sid, Color: color, NextHop: nh,
	}}
}

func TestProberWiring_SteeredMemberEmbedsPolicyTransport(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	fp := newFakeProber()
	a.SetProber(fp)

	endpoint := netip.MustParseAddr("fd00::2")
	transport := []netip.Addr{
		netip.MustParseAddr("fd00:ee::1"),
		netip.MustParseAddr("fd00:ee::2"),
	}
	a.ApplyLocalSRPolicy(LocalSRPolicy(100, endpoint, transport, 0), false)
	a.Apply(coloredVPNEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::2", 100))

	trigger := fh.v4created["10.0.0.0/24"]
	targets := fp.registered[trigger.GroupId]
	if len(targets) != 1 {
		t.Fatalf("registered %d targets, want 1", len(targets))
	}
	// The probe must walk the policy's waypoints -- the same ones the XDP
	// program prepends -- minus the transport's own terminal segment: that
	// one lands on the endpoint, whose End would refuse to forward to its
	// own loopback (the probe's next hop), permanently failing the path.
	if !slices.Equal(targets[0].Segments, transport[:1]) {
		t.Errorf("probe segments = %v, want the non-terminal transport %v", targets[0].Segments, transport[:1])
	}
	if targets[0].Dst != endpoint {
		t.Errorf("probe dst = %v, want the PE %v", targets[0].Dst, endpoint)
	}
}

func TestProberWiring_PolicyTransportChangeReprobes(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	fp := newFakeProber()
	a.SetProber(fp)

	endpoint := netip.MustParseAddr("fd00::2")

	// Route first: the policy is only reserved, so the probe goes straight
	// to the PE.
	a.Apply(coloredVPNEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::2", 100))
	trigger := fh.v4created["10.0.0.0/24"]
	if got := fp.registered[trigger.GroupId]; len(got) != 1 || len(got[0].Segments) != 0 {
		t.Fatalf("pre-policy registration = %+v, want one bare target", got)
	}

	// The policy arriving over BGP must re-register the group's targets with
	// the non-terminal transport embedded, without any route event.
	transport := []netip.Addr{netip.MustParseAddr("fd00:ee::1"), netip.MustParseAddr("fd00:ee::2")}
	a.Apply(bgp.RouteEvent{SRPolicy: &bgp.SRPolicy{
		Color: 100, Endpoint: endpoint,
		Candidates: []bgp.CandidatePath{{
			Origin: bgp.OriginBGP, Distinguisher: 1,
			Preference: bgp.SRPolicyDefaultPreference, SegmentList: transport,
		}},
	}})
	if got := fp.registered[trigger.GroupId]; len(got) != 1 || !slices.Equal(got[0].Segments, transport[:1]) {
		t.Fatalf("post-policy registration = %+v, want transport %v", got, transport[:1])
	}

	// A local candidate replacing the active path (the RPC goroutine's
	// entry point) must reprobe too.
	better := []netip.Addr{netip.MustParseAddr("fd00:ee::9"), netip.MustParseAddr("fd00:ee::a")}
	a.ApplyLocalSRPolicy(LocalSRPolicy(100, endpoint, better, 300), false)
	if got := fp.registered[trigger.GroupId]; len(got) != 1 || !slices.Equal(got[0].Segments, better[:1]) {
		t.Fatalf("post-replace registration = %+v, want transport %v", got, better[:1])
	}

	// Withdrawing every candidate empties the transport: the data plane
	// falls back to the bare service SID and the probe must follow it.
	a.ApplyLocalSRPolicy(LocalSRPolicy(100, endpoint, better, 300), true)
	a.Apply(bgp.RouteEvent{IsWithdraw: true, SRPolicy: &bgp.SRPolicy{
		Color: 100, Endpoint: endpoint,
		Candidates: []bgp.CandidatePath{{Origin: bgp.OriginBGP, Distinguisher: 1}},
	}})
	if got := fp.registered[trigger.GroupId]; len(got) != 1 || len(got[0].Segments) != 0 {
		t.Fatalf("post-withdraw registration = %+v, want one bare target", got)
	}
}

func TestProberWiring_UnparseableNextHopIsUnprobeable(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	fp := newFakeProber()
	a.SetProber(fp)

	ev := vpnEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::1", false)
	ev.VPN.NextHop = ""
	a.Apply(ev)

	trigger := fh.v4created["10.0.0.0/24"]
	targets := fp.registered[trigger.GroupId]
	if len(targets) != 1 {
		t.Fatalf("registered %d targets, want 1", len(targets))
	}
	if targets[0].Dst.IsValid() {
		t.Errorf("a member with no next hop must register an unprobeable target, got dst %v", targets[0].Dst)
	}
}

var _ = bgp.FamilyVPNv4 // keep the import stable if assertions above change
