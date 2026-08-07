package gobgp

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestApiFamilyToVinbero(t *testing.T) {
	tests := []struct {
		name string
		in   gobgppkt.Family
		want bgp.Family
		ok   bool
	}{
		{"vpnv4", gobgppkt.RF_IPv4_VPN, bgp.FamilyVPNv4, true},
		{"vpnv6", gobgppkt.RF_IPv6_VPN, bgp.FamilyVPNv6, true},
		{"ipv6-uc", gobgppkt.RF_IPv6_UC, bgp.FamilyIPv6Unicast, true},
		{"sr-policy-v6", gobgppkt.RF_SR_POLICY_IPv6, bgp.FamilySRPolicyIPv6, true},
		{"ipv4-uc-unconsumed", gobgppkt.RF_IPv4_UC, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := apiFamilyToVinbero(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Errorf("apiFamilyToVinbero(%v) = (%q, %v), want (%q, %v)",
					tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestPathToRouteEvent(t *testing.T) {
	t.Run("vpnv6-withdraw", func(t *testing.T) {
		ev, ok := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, Withdrawal: true})
		if !ok {
			t.Fatal("pathToRouteEvent returned ok=false for VPNv6")
		}
		if ev.Family != bgp.FamilyVPNv6 {
			t.Errorf("family = %q, want vpnv6", ev.Family)
		}
		if !ev.IsWithdraw {
			t.Error("IsWithdraw = false, want true")
		}
		if ev.VPN == nil {
			t.Error("VPN sub-struct must be populated for a VPN family")
		}
		if ev.Unicast != nil {
			t.Error("Unicast must be nil for a VPN family")
		}
	})

	t.Run("ipv6-unicast", func(t *testing.T) {
		ev, ok := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_UC})
		if !ok {
			t.Fatal("pathToRouteEvent returned ok=false for IPv6 unicast")
		}
		if ev.Unicast == nil {
			t.Error("Unicast sub-struct must be populated")
		}
		if ev.VPN != nil {
			t.Error("VPN must be nil for a unicast family")
		}
	})

	t.Run("unconsumed-family-skipped", func(t *testing.T) {
		if _, ok := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv4_UC}); ok {
			t.Error("pathToRouteEvent should skip families Vinbero does not consume")
		}
	})
}

// TestPathToRouteEventSource covers the path identity the ECMP aggregation
// depends on. Two PEs advertising one prefix reach the receiver as two
// events that differ only in Source, so dropping it (as the conversion did
// before) makes them indistinguishable and collapses them to one path.
func TestPathToRouteEventSource(t *testing.T) {
	peerA := netip.MustParseAddr("fd00::a")
	peerB := netip.MustParseAddr("fd00::b")

	t.Run("peer address and path id are carried", func(t *testing.T) {
		ev, ok := pathToRouteEvent(&apiutil.Path{
			Family: gobgppkt.RF_IPv6_VPN, PeerAddress: peerA, RemoteID: 7,
		})
		if !ok {
			t.Fatal("pathToRouteEvent returned ok=false")
		}
		if ev.Source.Peer != peerA {
			t.Errorf("Source.Peer = %v, want %v", ev.Source.Peer, peerA)
		}
		if ev.Source.PathID != 7 {
			t.Errorf("Source.PathID = %d, want 7", ev.Source.PathID)
		}
		if ev.Source.IsLocal() {
			t.Error("a path learned from a peer must not report IsLocal")
		}
	})

	t.Run("distinct peers yield distinct sources", func(t *testing.T) {
		a, _ := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, PeerAddress: peerA})
		b, _ := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, PeerAddress: peerB})
		if a.Source == b.Source {
			t.Fatal("two PEs must not share a PathSource; ECMP cannot separate them")
		}
	})

	t.Run("add-path ids separate paths from one peer", func(t *testing.T) {
		a, _ := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, PeerAddress: peerA, RemoteID: 1})
		b, _ := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, PeerAddress: peerA, RemoteID: 2})
		if a.Source == b.Source {
			t.Fatal("ADD-PATH ids from one peer must produce distinct sources")
		}
	})

	t.Run("locally originated path has no peer", func(t *testing.T) {
		// gobgp leaves PeerAddress invalid for a path this node originated.
		// ListRoutes relies on exactly this to skip its own advertisements.
		ev, ok := pathToRouteEvent(&apiutil.Path{Family: gobgppkt.RF_IPv6_VPN})
		if !ok {
			t.Fatal("pathToRouteEvent returned ok=false")
		}
		if !ev.Source.IsLocal() {
			t.Errorf("Source %v should report IsLocal", ev.Source)
		}
		if got := ev.Source.String(); got != "local" {
			t.Errorf("String() = %q, want %q", got, "local")
		}
	})
}

func TestFamiliesToAfiSafisAddPaths(t *testing.T) {
	fams := []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6}

	t.Run("off by default", func(t *testing.T) {
		out, err := familiesToAfiSafis(fams, false)
		if err != nil {
			t.Fatalf("familiesToAfiSafis: %v", err)
		}
		for i, as := range out {
			if as.AddPaths != nil {
				t.Errorf("family %d: AddPaths set while disabled", i)
			}
		}
	})

	t.Run("receive enabled for every family, send left off", func(t *testing.T) {
		out, err := familiesToAfiSafis(fams, true)
		if err != nil {
			t.Fatalf("familiesToAfiSafis: %v", err)
		}
		if len(out) != len(fams) {
			t.Fatalf("got %d afi-safis, want %d", len(out), len(fams))
		}
		for i, as := range out {
			if as.AddPaths == nil || !as.AddPaths.Config.GetReceive() {
				t.Errorf("family %d: ADD-PATH receive not enabled", i)
			}
			// Vinbero originates one path per NLRI; negotiating send would
			// advertise a capability it never uses.
			if as.AddPaths != nil && as.AddPaths.Config.GetSendMax() != 0 {
				t.Errorf("family %d: SendMax = %d, want 0", i, as.AddPaths.Config.GetSendMax())
			}
		}
	})
}

func TestSubscribe_BeforeStartRejected(t *testing.T) {
	s := newTestSession(t)
	_, err := s.Subscribe("", func(bgp.RouteEvent) {})
	if !errors.Is(err, bgp.ErrSessionNotStarted) {
		t.Errorf("Subscribe before Start: got %v, want ErrSessionNotStarted", err)
	}
}

func TestSubscribe_CancelIsSafe(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	cancel, err := s.Subscribe("", func(bgp.RouteEvent) {})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// cancel tears down the watcher; calling it twice must not panic
	// (context.CancelFunc is idempotent).
	cancel()
	cancel()
}
