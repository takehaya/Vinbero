package cplane

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	sdk "github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"google.golang.org/protobuf/proto"
)

func nativeInput(t *testing.T, n gp.NLRI, attrs ...gp.PathAttributeInterface) *v1.PluginRoute {
	t.Helper()
	p, err := gobgppath.Encode(gp.RF_MUP_IPv4, n, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return &v1.PluginRoute{Family: "mup_ipv4", Peer: "192.0.2.254", BgpPath: &v1.PluginBGPPath{Codec: p.Codec, Afi: uint32(p.AFI), Safi: uint32(p.SAFI), Nlri: p.NLRI, RouteKey: []byte(n.String()), Attributes: p.Attributes}}
}
func rtAttribute(rt string) gp.PathAttributeInterface {
	ec, e := gp.ParseRouteTarget(rt)
	if e != nil {
		panic(e)
	}
	return gp.NewPathAttributeExtendedCommunities([]gp.ExtendedCommunityInterface{ec})
}
func inputRoute(t *testing.T, rt string) *v1.PluginRoute {
	return nativeInput(t, gp.NewMUPInterworkSegmentDiscoveryRoute(gp.NewRouteDistinguisherTwoOctetAS(65000, 7), netip.MustParsePrefix("172.16.0.0/24")), rtAttribute(rt))
}
func inputBatch(r *v1.PluginRoute) *v1.PluginEventBatch {
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Sequence: 1, Route: r}}}
}
func TestInputCatalogAndFiltering(t *testing.T) {
	policy := compositionPolicy()
	policy.Contexts = append(policy.Contexts, proto.Clone(policy.Contexts[0]).(*v1.CplaneInputContext))
	policy.Contexts[1].Name = "shared"
	p, e := parseInputPolicy(policy, nil)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := p.configure([]byte("payload"))
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := sdk.DecodeInputConfig(wire, sdk.FeatureBGPPath|sdk.FeatureInputContexts)
	if e != nil || string(catalog.Payload) != "payload" || len(catalog.Contexts) != 2 {
		t.Fatalf("catalog %+v %v", catalog, e)
	}
	d := &inputDelivery{policy: p}
	r := inputRoute(t, "65000:8")
	out, e := d.prepare(inputBatch(r))
	if e != nil || len(out.Events) != 0 {
		t.Fatal("unauthorized payload delivered")
	}
	r = inputRoute(t, "65000:7")
	out, e = d.prepare(inputBatch(r))
	if e != nil || len(out.Events) != 1 || !reflect.DeepEqual(out.Events[0].Route.Contexts, []string{"mobile", "shared"}) {
		t.Fatalf("memberships %+v %v", out, e)
	}
	if len(r.Contexts) != 0 {
		t.Fatal("mutated source")
	}
	changed := inputRoute(t, "65000:8")
	out, e = d.prepare(inputBatch(changed))
	if e != nil || len(out.Events) != 1 {
		t.Fatal(e)
	}
	tombstone := out.Events[0].Route
	if !tombstone.IsWithdraw || len(tombstone.BgpPath.Nlri) != 0 || len(tombstone.BgpPath.Attributes) != 0 || len(tombstone.Contexts) != 0 {
		t.Fatal("membership loss exposed forbidden payload")
	}
	if _, ok := inputSDKRoute(tombstone).BGPKey(); !ok {
		t.Fatal("tombstone lost opaque identity")
	}
	out, e = d.prepare(inputBatch(changed))
	if e != nil || len(out.Events) != 0 {
		t.Fatal("unknown forbidden path emitted")
	}
}
func TestInputPolicyBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		change func(*v1.CplaneInputPolicy)
	}{{"version", func(p *v1.CplaneInputPolicy) { p.Version = 2 }}, {"duplicate", func(p *v1.CplaneInputPolicy) { p.Contexts = append(p.Contexts, p.Contexts[0]) }}, {"rt", func(p *v1.CplaneInputPolicy) { p.Contexts[0].Grants[0].RouteTargets = nil }}, {"unicast-peer", func(p *v1.CplaneInputPolicy) {
		p.Contexts[0].Grants[0] = &v1.CplaneInputGrant{Families: []string{"ipv6_unicast"}, Prefixes: []string{"::/0"}}
	}}, {"teid", func(p *v1.CplaneInputPolicy) { p.Contexts[0].TeidPrefixes = []string{"0/33"} }}, {"family", func(p *v1.CplaneInputPolicy) { p.Contexts[0].Grants[0].Families = []string{"typo"} }}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := compositionPolicy()
			tt.change(p)
			if _, e := parseInputPolicy(p, nil); e == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	p := compositionPolicy()
	p.MaxPaths = 1
	parsed, e := parseInputPolicy(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	d := &inputDelivery{policy: parsed}
	if _, e = d.prepare(inputBatch(inputRoute(t, "65000:7"))); e != nil {
		t.Fatal(e)
	}
	r := inputRoute(t, "65000:7")
	r.BgpPath.RouteKey = []byte("second")
	if _, e = d.prepare(inputBatch(r)); e == nil {
		t.Fatal("host path limit ignored")
	}
	r.BgpPath.RouteKey = nil
	if _, e = d.prepare(inputBatch(r)); e == nil {
		t.Fatal("missing host key accepted")
	}
}
func TestInputDelegationTarget(t *testing.T) {
	p, e := parseInputPolicy(compositionPolicy(), nil)
	if e != nil {
		t.Fatal(e)
	}
	r := inputRoute(t, "65000:7")
	ev := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: netip.MustParseAddr(r.Peer)}, MUP: &bgp.MUPRoute{Type: 4}, BGPPath: &bgp.EncodedBGPPath{Codec: r.BgpPath.Codec, AFI: uint16(r.BgpPath.Afi), SAFI: uint8(r.BgpPath.Safi), NLRI: r.BgpPath.Nlri, RouteKey: r.BgpPath.RouteKey, Attributes: r.BgpPath.Attributes}}
	if p.delegates(ev, func(bgp.RouteEvent) (string, uint16, bool) { return "red", 0, true }) {
		t.Fatal("withheld another VRF")
	}
	if !p.delegates(ev, func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }) {
		t.Fatal("did not delegate global input")
	}
	ev.MUP.Type = 1
	if p.delegates(ev, func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }) {
		t.Fatal("discovery route delegated")
	}
}

type compositionSource struct{ *fakeSource }

func (*compositionSource) SetDelegation(string, func(bgp.RouteEvent) bool) {}
func mupFixture(t *testing.T) []bgp.RouteEvent {
	return mupFixtureWithTEID(t, 256)
}

func mupFixtureWithTEID(t *testing.T, value uint32) []bgp.RouteEvent {
	t.Helper()
	a := netip.MustParseAddr
	p := netip.MustParsePrefix
	rd := gp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	var teid [4]byte
	binary.BigEndian.PutUint32(teid[:], value)
	sid := func(b gp.SRBehavior) gp.PathAttributeInterface {
		return gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(a("fd00:a:0:100::"), b, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
	}
	ec, _ := gp.ParseRouteTarget("65000:7")
	ext := gp.NewPathAttributeExtendedCommunities([]gp.ExtendedCommunityInterface{ec, gp.NewMUPExtended(0, 0)})
	ns := []gp.NLRI{gp.NewMUPType1SessionTransformedRoute(rd, p("10.0.0.1/32"), netip.AddrFrom4(teid), 9, a("172.16.0.1"), nil), gp.NewMUPInterworkSegmentDiscoveryRoute(rd, p("172.16.0.0/24")), gp.NewMUPType2SessionTransformedRoute(rd, 64, a("192.0.2.1"), netip.AddrFrom4(teid)), gp.NewMUPDirectSegmentDiscoveryRoute(rd, a("192.0.2.2"))}
	var out []bgp.RouteEvent
	for i, n := range ns {
		attrs := []gp.PathAttributeInterface{ext}
		if i == 1 {
			attrs = append(attrs, sid(gp.ENDM_GTP4E))
		}
		if i == 3 {
			attrs = append(attrs, sid(gp.END_DT4))
		}
		r := nativeInput(t, n, attrs...)
		out = append(out, bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: a(r.Peer)}, MUP: &bgp.MUPRoute{Type: bgp.MUPRouteType(i + 1), RD: "65000:7"}, BGPPath: &bgp.EncodedBGPPath{Codec: r.BgpPath.Codec, AFI: uint16(r.BgpPath.Afi), SAFI: uint8(r.BgpPath.Safi), NLRI: r.BgpPath.Nlri, RouteKey: r.BgpPath.RouteKey, Attributes: r.BgpPath.Attributes}})
	}
	return out
}
func TestCompositionBackendReplayAndWithdraw(t *testing.T) {
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
			if e = m.Register(context.Background(), Registration{Backend: reg.Backend, NativeID: reg.NativeID, NativeVersion: reg.NativeVersion, Name: "composition", Module: reg.Module, Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`), Capabilities: caps, Scope: scope, Input: func() *v1.CplaneInputPolicy {
				p := compositionPolicy()
				p.Contexts[0].DelegateEvpn = false
				p.Contexts[0].BridgeDomain = 0
				return p
			}()}); e != nil {
				t.Fatal(e)
			}
			if !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("WASM did not become idle")
			}
			st, _ := m.StatsFor("composition")
			if !st.InputReady || st.OutputFailure != "" || st.AppliedRevision == 0 || len(f.uplinks) != 1 || f.v4["10.0.0.1/32"] == nil {
				t.Fatalf("WASM outputs failed: %+v uplinks=%v v4=%v", st, f.uplinks, f.v4)
			}
			initial := *f.v4["10.0.0.1/32"]
			duplicate := src.rib[0]
			duplicate.Source.Peer = netip.MustParseAddr("192.0.2.253")
			if !src.emit("composition", duplicate) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("equivalent supporter idle")
			}
			st, _ = m.StatsFor("composition")
			if st.OutputFailure != "" || st.AppliedRevision != st.DesiredRevision || f.v4["10.0.0.1/32"] == nil {
				t.Fatalf("duplicate supporter blocked real host apply: %+v", st)
			}
			conflicting := mupFixtureWithTEID(t, 512)[0]
			conflicting.Source = duplicate.Source
			if !src.emit("composition", conflicting) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("conflicting supporter idle")
			}
			st, _ = m.StatsFor("composition")
			if st.OutputFailure != "" || st.AppliedRevision != st.DesiredRevision || f.v4["10.0.0.1/32"] != nil || len(f.uplinks) != 1 {
				t.Fatalf("conflict did not retract only the ambiguous output: %+v", st)
			}
			withdraw := src.rib[0]
			withdraw.IsWithdraw = true
			if !src.emit("composition", withdraw) || !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("remaining supporter idle")
			}
			if current := f.v4["10.0.0.1/32"]; current == nil || *current == initial {
				t.Fatal("surviving changed supporter did not recover forwarding")
			}
			withdraw = conflicting
			withdraw.IsWithdraw = true
			if !src.emit("composition", withdraw) {
				t.Fatal("no subscription")
			}
			if !m.WaitIdle("composition", 5*time.Second) {
				t.Fatal("withdraw idle")
			}
			if f.v4["10.0.0.1/32"] != nil {
				t.Fatal("withdraw did not remove downlink")
			}
			if e = m.Unregister(context.Background(), "composition"); e != nil {
				t.Fatal(e)
			}
			if len(f.uplinks) != 0 || len(f.v4) != 0 {
				t.Fatal("WASM unregister leaked")
			}

		})
	}
}

func TestInputPolicyStoreRoundTrip(t *testing.T) {
	store := newTestStore(t)
	r := storedRegistration(t)
	r.Families = nil
	r.Input = compositionPolicy()
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := store.List()
	if err != nil || len(got) != 1 || !proto.Equal(got[0].Input, r.Input) {
		t.Fatalf("input authority not persisted: %+v %v", got, err)
	}
}
func TestUnrestoredForwardingCannotBeForgottenOrDelegated(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	src := &compositionSource{newFakeSource()}
	m, err := NewManager(ManagerConfig{Source: src, Headend: f, ForwardingMaps: f, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Forget("compose"); err == nil {
		t.Fatal("forgot owned forwarding inventory")
	}
	policy, err := parseInputPolicy(compositionPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := ParseScope(ScopeSpec{HeadendPrefixes: []string{"0.0.0.0/0"}})
	caps, _ := wasm.ParseCapabilities([]string{"mup", "evpn", "headend"})
	if err = m.checkInputRegistration(Registration{Name: "other", Input: policy.spec, Capabilities: caps, Scope: scope}, policy); err == nil {
		t.Fatal("stole unrestored delegation")
	}
	if err = m.Unregister(context.Background(), "compose"); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 0 || len(f.peers) != 0 || len(f.fdb) != 0 {
		t.Fatal("cannot clean missing WASM inventory")
	}
}

func TestCompositionObserverWASMHasNoWriteImports(t *testing.T) {
	mod, err := os.ReadFile("../../out/cplane-route-composition-observer.wasm")
	if err != nil {
		t.Skip("make cplane-route-composition-observer")
	}
	src := newFakeSource()
	src.rib = mupFixture(t)
	m, err := NewManager(ManagerConfig{Source: src, Headend: newFakeHeadendOps()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	policy := compositionPolicy()
	policy.Contexts[0].DelegateMupTypes = nil
	policy.Contexts[0].DelegateEvpn = false
	policy.Contexts[0].BridgeDomain = 0
	if err = m.Register(context.Background(), Registration{Name: "observe", Module: mod, Input: policy, Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7}`)}); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle("observe", 5*time.Second) {
		t.Fatal("observer replay")
	}
	st, _ := m.StatsFor("observe")
	if !st.InputReady || st.AppliedRevision != 0 || st.HeadendEntries != 0 {
		t.Fatalf("observer wrote: %+v", st)
	}
}

func TestInputAuthorityRequiresNewManifestVersion(t *testing.T) {
	store := newTestStore(t)
	r := storedRegistration(t)
	r.Families = nil
	r.Input = compositionPolicy()
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	m, err := store.readManifest(r.Name)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != contextManifestVersion {
		t.Fatal("old daemon could silently ignore input policy")
	}
	m.Version = storeManifestVersion
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(store.manifestPath(r.Name), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.List(); err == nil {
		t.Fatal("legacy version carrying context authority accepted")
	}
}
