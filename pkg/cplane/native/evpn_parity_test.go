package native

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
	"google.golang.org/protobuf/proto"
)

func evpnConfiguration(payload string) []byte {
	var b, ctx wire.Encoder
	b.Uint(1, 1)
	b.Bytes(2, []byte(payload))
	b.String(3, cplane.BGPPathCodec)
	ctx.String(1, "l2")
	ctx.String(2, "evpn")
	b.Message(4, ctx)
	return b
}
func evpnRoute(t *testing.T, imet bool, rdNumber uint32, remote, sid string) *v1.PluginEvent {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, rdNumber)
	var n *bgp.EVPNNLRI
	var err error
	behavior := bgp.END_DT2U
	if imet {
		n, err = bgp.NewEVPNMulticastEthernetTagRoute(rd, 0, netip.MustParseAddr("192.0.2.1"))
		behavior = bgp.END_DT2M
	} else {
		n, err = bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, "02:00:00:00:00:01", netip.Addr{}, []uint32{0})
	}
	if err != nil {
		t.Fatal(err)
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr(remote))
	if err != nil {
		t.Fatal(err)
	}
	sidAttr := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L2Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), behavior)))
	raw, err := n.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	path := &v1.PluginBGPPath{Codec: cplane.BGPPathCodec, Afi: bgp.AFI_L2VPN, Safi: bgp.SAFI_EVPN, Nlri: raw, RouteKey: []byte(n.String())}
	for _, attr := range []bgp.PathAttributeInterface{mp, sidAttr} {
		a, err := attr.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		path.Attributes = append(path.Attributes, a)
	}
	return &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Route: &v1.PluginRoute{Family: "evpn", Peer: "192.0.2.254", Contexts: []string{"l2"}, BgpPath: path}}
}
func evpnModule(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "out", "cplane-evpn-imet.wasm"))
	if err != nil {
		if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
			t.Fatal("make cplane-evpn-imet: ", err)
		}
		t.Skip("make cplane-evpn-imet: ", err)
	}
	return raw
}
func TestEVPNIMETEncodedParity(t *testing.T) {
	instances := make([]eventInstance, 2)
	ops := []*sharedOps{{}, {}}
	for i := range instances {
		cfg := wasm.Config{Name: EVPNIMET, Ops: ops[i], ConfigBlob: evpnConfiguration(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}}
		var err error
		if i == 0 {
			instances[i], err = Instantiate(context.Background(), Config{Config: cfg, Implementation: EVPNIMET, Version: ImplementationVersion})
		} else {
			cfg.Module = evpnModule(t)
			instances[i], err = wasm.Instantiate(context.Background(), cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		inst := instances[i]
		t.Cleanup(func() { _ = inst.Close(context.Background()) })
	}
	check := func(n int) {
		t.Helper()
		if !reflect.DeepEqual(ops[0].Calls, ops[1].Calls) {
			t.Fatalf("native/WASM transactions differ: %+v / %+v", ops[0].Calls, ops[1].Calls)
		}
		var last *v1.PluginApplyChunk
		for _, call := range ops[0].Calls {
			if call.Method == "put" {
				chunk := new(v1.PluginApplyChunk)
				if err := proto.Unmarshal(call.Data, chunk); err != nil {
					t.Fatal(err)
				}
				last = chunk
			}
		}
		if last == nil || len(last.EvpnForwards) != n {
			t.Fatalf("expected %d static MACs, last=%+v", n, last)
		}
		if n == 1 {
			e := last.EvpnForwards[0]
			if e.Context != "l2" || e.Mac != "02:00:00:00:00:01" || e.SrcAddr != "fd00:feed::1" || e.RemoteSrc != "2001:db8::1" || e.Flood || !reflect.DeepEqual(e.Segments, []string{"fd00:2::1"}) {
				t.Fatalf("unexpected forwarding: %+v", e)
			}
		}
	}
	start := &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, ReplaySource: cplane.BGPSource}
	end := &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, ReplaySource: cplane.BGPSource}
	mac := evpnRoute(t, false, 7, "2001:db8::1", "fd00:2::1")
	imet := evpnRoute(t, true, 8, "2001:db8::1", "fd00:3::1")
	sharedDeliver(t, instances, start, mac, end)
	check(0)
	sharedDeliver(t, instances, imet)
	check(1)
	ambiguous := evpnRoute(t, true, 9, "2001:db8::1", "fd00:3::2")
	sharedDeliver(t, instances, ambiguous)
	check(0)
	ambiguous.Route.IsWithdraw = true
	sharedDeliver(t, instances, ambiguous)
	check(1)
	invalid := evpnRoute(t, true, 8, "fe80::1", "fd00:3::1")
	sharedDeliver(t, instances, invalid)
	check(0)
	sharedDeliver(t, instances, imet)
	check(1)
	denied := proto.Clone(imet).(*v1.PluginEvent)
	denied.Route.Contexts = nil
	sharedDeliver(t, instances, denied)
	check(0)
	for _, o := range ops {
		o.failCommit = true
	}
	sharedDeliver(t, instances, imet)
	check(1)
	for _, o := range ops {
		o.failCommit = false
	}
	for _, inst := range instances {
		if err := inst.Tick(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	check(1)
	imet.Route.IsWithdraw = true
	sharedDeliver(t, instances, imet)
	check(0)
	sharedDeliver(t, instances, start, mac, end)
	check(0)
	sharedDeliver(t, instances, start, end)
	check(0)
}
func TestEVPNIMETAdmission(t *testing.T) {
	descriptor, ok := Lookup(EVPNIMET)
	if !ok || !descriptor.Write || len(descriptor.Identity) != 64 {
		t.Fatal(descriptor)
	}
	for _, payload := range []string{`{}`, `{"context":"missing","source":"fd00:feed::1"}`} {
		ops := &sharedOps{}
		_, err := Instantiate(context.Background(), Config{Config: wasm.Config{Name: EVPNIMET, Ops: ops, ConfigBlob: evpnConfiguration(payload), Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}}, Implementation: EVPNIMET, Version: ImplementationVersion})
		if !errors.Is(err, wasm.ErrAdmission) || len(ops.Calls) != 0 {
			t.Fatalf("admission %v calls %+v", err, ops.Calls)
		}
	}
	_, err := Instantiate(context.Background(), Config{Config: wasm.Config{Name: EVPNIMET, Ops: &sharedOps{}}, Implementation: EVPNIMET, Version: ImplementationVersion})
	if !errors.Is(err, wasm.ErrAdmission) {
		t.Fatal("accepted without write capability")
	}
}
