package gobgp

import (
	"errors"
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
