package cplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func TestCompositionBackendSharedGateArbitration(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			reg := compositionBackendRegistration(t, backend)
			f := newServiceFake()
			src := &compositionSource{newFakeSource()}
			src.rib = mupFixture(t)
			scope, _ := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
			m, e := NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: f, ForwardingMaps: f, ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close(context.Background())
			caps, _ := wasm.ParseCapabilities([]string{"headend", "mup"})
			policy := compositionPolicy()
			policy.Contexts[0].DelegateEvpn = false
			policy.Contexts[0].BridgeDomain = 0
			e = m.Register(context.Background(), Registration{Backend: reg.Backend, NativeID: reg.NativeID, NativeVersion: reg.NativeVersion, Name: "composition", Module: reg.Module, Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`), Capabilities: caps, Scope: scope, Input: policy})
			if e != nil {
				t.Fatal(e)
			}
			if !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("initial idle")
			}
			if f.v4["10.0.0.1/32"] == nil {
				t.Fatal("initial forwarding absent")
			}
			rt, _ := gp.ParseRouteTarget("65000:7")
			ext := gp.NewPathAttributeExtendedCommunities([]gp.ExtendedCommunityInterface{rt, gp.NewMUPExtended(0, 0)})
			n := gp.NewMUPType1SessionTransformedRoute(gp.NewRouteDistinguisherTwoOctetAS(65000, 8), netip.MustParsePrefix("192.0.2.1/32"), netip.MustParseAddr("0.0.1.0"), 9, netip.MustParseAddr("172.16.0.1"), nil)
			r := nativeInput(t, n, ext)
			collision := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: netip.MustParseAddr(r.Peer)}, MUP: &bgp.MUPRoute{Type: bgp.MUPRouteType(3), RD: "65000:8"}, BGPPath: &bgp.EncodedBGPPath{Codec: r.BgpPath.Codec, AFI: uint16(r.BgpPath.Afi), SAFI: uint8(r.BgpPath.Safi), NLRI: r.BgpPath.Nlri, RouteKey: r.BgpPath.RouteKey, Attributes: r.BgpPath.Attributes}}
			if !src.emit("composition", collision) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("collision idle")
			}
			withdraw := src.rib[0]
			withdraw.IsWithdraw = true
			if !src.emit("composition", withdraw) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("withdraw idle")
			}
			st, _ := m.StatsFor("composition")
			t.Logf("outputFailure=%q desired=%d applied=%d obsolete=%v", st.OutputFailure, st.DesiredRevision, st.AppliedRevision, f.v4["10.0.0.1/32"] != nil)
			if st.OutputFailure != "" || st.DesiredRevision != st.AppliedRevision || f.v4["10.0.0.1/32"] != nil || len(f.uplinks) != 0 {
				t.Fatal("cross-type ambiguity retained withdrawn ST1 forwarding")
			}
			collision.IsWithdraw = true
			if !src.emit("composition", collision) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("recovery idle")
			}
			st, _ = m.StatsFor("composition")
			if st.OutputFailure != "" || len(f.uplinks) != 1 || f.v4["192.0.2.1/32"] == nil {
				t.Fatalf("removing headend claimant did not recover uplink: %+v", st)
			}

		})
	}
}
