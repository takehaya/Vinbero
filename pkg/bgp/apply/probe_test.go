package apply

import (
	"net/netip"
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
