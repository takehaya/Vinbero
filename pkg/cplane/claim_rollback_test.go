package cplane

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/cplane/native"
)

type rollbackRouteFeed struct {
	mu      sync.Mutex
	handler bgp.RouteHandler
}

func (f *rollbackRouteFeed) Subscribe(_ bgp.Family, handler bgp.RouteHandler) (func(), error) {
	f.mu.Lock()
	f.handler = handler
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.handler = nil
		f.mu.Unlock()
	}, nil
}

func (f *rollbackRouteFeed) emit(event bgp.RouteEvent) {
	f.mu.Lock()
	handler := f.handler
	f.mu.Unlock()
	if handler != nil {
		handler(event)
	}
}

type failingClaimSource struct {
	*demux.Demux
	beforeFailure func()
	failure       error
}

func (s *failingClaimSource) RegisterQuiet(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error) {
	if s.beforeFailure != nil {
		s.beforeFailure()
		return nil, s.failure
	}
	return s.Demux.RegisterQuiet(name, families, handler)
}

func TestFailedRegistrationRestoresBuiltinLiveClaims(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw bool
		upgrade  bool
	}{
		{name: "new claim restores surviving route"},
		{name: "new claim does not resurrect withdrawn route", withdraw: true},
		{name: "failed upgrade restores old claim and retracts route", upgrade: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			feed := &rollbackRouteFeed{}
			claims := demux.NewClaimRegistry(nil)
			d := demux.New(feed, nil, nil)
			d.SetClaimRegistry(claims)
			t.Cleanup(d.Stop)
			type pathKey struct {
				prefix string
				source bgp.PathSource
			}
			installed := make(map[pathKey]bool)
			if _, err := d.RegisterBuiltin("builtin", []bgp.Family{bgp.FamilyVPNv4}, func(event bgp.RouteEvent) {
				key := pathKey{event.VPN.Prefix, event.Source}
				if event.IsWithdraw {
					delete(installed, key)
				} else {
					installed[key] = true
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := d.Start(); err != nil {
				t.Fatal(err)
			}
			subscribeErr := errors.New("injected subscription failure")
			source := &failingClaimSource{Demux: d, failure: subscribeErr}
			m, err := NewManager(ManagerConfig{
				Source: source, Claims: claims, AllowNative: true, Headend: newFakeHeadendOps(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close(ctx) })
			reg := Registration{
				Name: "observer", Backend: BackendNative, NativeID: native.BGPObserver,
				// Keep plugin delivery independent of the VPN built-in collector.
				Families: []bgp.Family{bgp.FamilyEVPN}, Behaviors: []uint16{0xFE01},
			}
			if tc.upgrade {
				if err := m.Register(ctx, reg); err != nil {
					t.Fatal(err)
				}
				reg.Behaviors = nil
			}
			m.mu.Lock()
			old := m.plugins[reg.Name]
			m.mu.Unlock()
			control := bgp.RouteEvent{
				Family: bgp.FamilyVPNv4, Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")},
				VPN: &bgp.VPNRoute{RD: "65000:1", Prefix: "10.20.0.0/24"}, EndpointBehavior: 0x0013,
			}
			private := control
			private.VPN = &bgp.VPNRoute{RD: "65000:1", Prefix: "10.21.0.0/24"}
			private.EndpointBehavior = 0xFE01
			controlKey := pathKey{control.VPN.Prefix, control.Source}
			privateKey := pathKey{private.VPN.Prefix, private.Source}
			feed.emit(control)
			if !maps.Equal(installed, map[pathKey]bool{controlKey: true}) {
				t.Fatalf("initial built-in set: %v", installed)
			}
			source.beforeFailure = func() {
				if claims.IsClaimed(0xFE01) == tc.upgrade {
					t.Fatal("live event did not occur under the tentative claims")
				}
				feed.emit(private)
				if installed[privateKey] != tc.upgrade {
					t.Fatalf("tentative claim delivered the wrong built-in set: %v", installed)
				}
				if tc.withdraw {
					private.IsWithdraw, private.EndpointBehavior = true, 0
					feed.emit(private)
				}
			}
			if err := m.Register(ctx, reg); !errors.Is(err, subscribeErr) {
				t.Fatalf("registration error = %v, want subscription failure", err)
			}
			want := map[pathKey]bool{controlKey: true}
			if !tc.upgrade && !tc.withdraw {
				want[privateKey] = true
			}
			if !maps.Equal(installed, want) {
				t.Fatalf("built-in state after rollback = %v, want %v", installed, want)
			}
			var wantClaims []uint16
			if tc.upgrade {
				wantClaims = []uint16{0xFE01}
			}
			if got := claims.Claims(reg.Name); !slices.Equal(got, wantClaims) {
				t.Fatalf("claims after rollback = %v, want %v", got, wantClaims)
			}
			m.mu.Lock()
			current := m.plugins[reg.Name]
			m.mu.Unlock()
			if current != old {
				t.Fatal("failed registration replaced the running plugin")
			}
			if old != nil {
				if _, err := old.inst.HandleEvents(ctx, nil); err != nil {
					t.Fatalf("old plugin no longer callable after rollback: %v", err)
				}
			}
		})
	}
}
