package cplane

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/native"
)

// Real shared controllers and guest decoding exercise admission before an
// existing instance is replaced. Forwarding and advertisement sinks are fake;
// this test does not claim packet continuity during a successful replacement.
func TestCDplaneMalformedConfigPreservesRunningInstance(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			reg := Registration{Name: "custom-cdplane-behavior", Backend: backend,
				Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope()}
			if backend == BackendNative {
				reg.NativeID, reg.NativeVersion = native.CustomCDplaneBehavior, native.ImplementationVersion
			} else {
				var err error
				reg.Module, err = os.ReadFile("../../out/cplane-custom-cdplane-behavior.wasm")
				if err != nil {
					if os.Getenv("VINBERO_CPLANE_PARITY") == "1" || !os.IsNotExist(err) {
						t.Fatal(err)
					}
					t.Skip("build out/cplane-custom-cdplane-behavior.wasm to test the WASM backend")
				}
			}
			reg.Config = []byte(fmt.Sprintf(`{"schema_version":1,"routing":{"locator":"main","slot":33,
				"prefix":"10.7.0.0/24","vrf":%q,"decap_vrf":%q,"next_hop":"2001:db8::1",
				"headend_prefixes":["10.2.0.0/24"]},"endpoint":{"allowed_underlay_prefix":"2001:db8::2/128"}}`, testVRF, testVRF))
			src, claims := newFakeSource(), newFakeClaims()
			headend, sids, grants := newFakeHeadendOps(), newFakeSIDOps(), newFakeGrantOps()
			alloc, adv := &fakeAllocator{}, &fakeAdvertiser{}
			sids.grants = grants
			m, err := NewManager(ManagerConfig{AllowNative: true,
				Source: src, Claims: claims, Headend: headend, Advertiser: adv,
				Locators: alloc, SIDFunctions: sids, EndtVRFGrants: grants,
				ResolveVRF:  func(string) (uint32, error) { return 7, nil },
				EncapSource: testEncapSource, LocatorInfo: testLocators(), VRFBindings: testBindings()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close(ctx) })
			if err := m.Register(ctx, reg); err != nil {
				t.Fatal(err)
			}
			if !src.emit(reg.Name, customBehaviorRoute("10.2.0.0/24", "fd00:2::100")) {
				t.Fatal("missing source subscription")
			}
			waitDelivered(t, m, reg.Name)
			if advertised, withdrawn := adv.counts(); advertised != 1 || withdrawn != 0 ||
				sids.count() != 1 || grants.count() != 1 || headend.countV4() != 1 {
				t.Fatalf("initial state: advertised=%d withdrawn=%d SID=%d grants=%d headend=%d",
					advertised, withdrawn, sids.count(), grants.count(), headend.countV4())
			}
			owner := bpf.OwnerPluginBundle(reg.Name)
			for prefix := range mustEntries(t, sids) {
				if got, ok, err := sids.GetSidFunctionOwner(prefix); err != nil || !ok || got != owner {
					t.Fatalf("initial SID owner: %q %t %v", got, ok, err)
				}
			}
			if got, ok, err := headend.GetHeadendV4Owner("10.2.0.0/24"); err != nil || !ok || got != owner {
				t.Fatalf("initial headend owner: %q %t %v", got, ok, err)
			}

			// Copy values, not map pointers, so an in-place rewrite cannot mutate
			// the oracle. Operation histories also detect remove-and-reinstall.
			type state struct {
				SID                          map[string]bpf.SidFunctionEntry
				SIDOwners                    map[string]bpf.OwnerTag
				Headend                      map[string]bpf.HeadendEntry
				HeadendOwners                map[string]bpf.OwnerTag
				Grants                       map[uint32]uint32
				SIDOps, HeadendOps, GrantOps []string
				Advertisements               []bgp.VPNRoute
				Withdrawals                  []bgp.RouteKey
				Released                     int
			}
			snapshot := func() state {
				s := state{SID: map[string]bpf.SidFunctionEntry{}, Headend: map[string]bpf.HeadendEntry{}}
				sids.mu.Lock()
				for key, value := range sids.entries {
					s.SID[key] = *value
				}
				s.SIDOwners, s.SIDOps = maps.Clone(sids.owners), append([]string(nil), sids.ops...)
				sids.mu.Unlock()
				headend.mu.Lock()
				for key, value := range headend.v4 {
					s.Headend[key] = *value
				}
				s.HeadendOwners, s.HeadendOps = maps.Clone(headend.owner4), append([]string(nil), headend.writes...)
				headend.mu.Unlock()
				grants.mu.Lock()
				s.Grants, s.GrantOps = maps.Clone(grants.grants), append([]string(nil), grants.ops...)
				grants.mu.Unlock()
				adv.mu.Lock()
				s.Advertisements, s.Withdrawals = append([]bgp.VPNRoute(nil), adv.advertise...), append([]bgp.RouteKey(nil), adv.withdrawn...)
				adv.mu.Unlock()
				s.Released = alloc.releasedCount()
				return s
			}
			before := snapshot()
			stats, ok := m.StatsFor(reg.Name)
			if !ok || stats.Since.IsZero() || stats.Dead || stats.OutputFailure != "" {
				t.Fatalf("initial stats: %+v", stats)
			}
			m.mu.Lock()
			old := m.plugins[reg.Name]
			m.mu.Unlock()
			for _, invalid := range [][]byte{
				append(append([]byte(nil), reg.Config...), '{'),
				[]byte(`{"schema_version":1,"routing":{},"unknown":true}`),
				append(append([]byte(nil), reg.Config...), []byte(` {}`)...),
			} {
				bad := reg
				bad.Config, bad.Behaviors = invalid, []uint16{0xFE02}
				if err := m.Register(ctx, bad); err == nil {
					t.Fatalf("accepted invalid JSON: %s", invalid)
				}
				waitDelivered(t, m, reg.Name)
				after, ok := m.StatsFor(reg.Name)
				m.mu.Lock()
				current := m.plugins[reg.Name]
				m.mu.Unlock()
				if !ok || current != old || !after.Since.Equal(stats.Since) || after.Dead || after.OutputFailure != "" {
					t.Fatalf("invalid config replaced or damaged the old instance: %+v", after)
				}
				if got := claims.Claims(reg.Name); !reflect.DeepEqual(got, reg.Behaviors) {
					t.Fatalf("failed registration did not restore claims: %v", got)
				}
				if got := snapshot(); !reflect.DeepEqual(got, before) {
					t.Fatalf("invalid config changed owned state or rewrote it: before=%+v after=%+v", before, got)
				}
			}
			// The retained instance still processes live input after rejection.
			if !src.emit(reg.Name, customBehaviorRoute("10.2.0.0/24", "fd00:2::200")) {
				t.Fatal("rejection removed the source subscription")
			}
			waitDelivered(t, m, reg.Name)
			entry, ok := headend.getV4("10.2.0.0/24")
			if !ok || entry.NumSegments != 1 || netip.AddrFrom16(entry.Segments[0]).String() != "fd00:2::200" {
				t.Fatalf("old instance stopped processing routes: %+v", entry)
			}
		})
	}
}
