package native

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"google.golang.org/protobuf/proto"
)

type eventInstance interface {
	HandleEvents(context.Context, []byte) ([]byte, error)
	Tick(context.Context, int64) error
	Close(context.Context) error
}

func parityModule(t testing.TB, observer bool) []byte {
	t.Helper()
	name := "cplane-route-composition.wasm"
	if observer {
		name = "cplane-route-composition-observer.wasm"
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "out", name))
	if err != nil {
		if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
			t.Fatal("build fresh parity artifacts with make cplane-route-composition cplane-route-composition-observer: ", err)
		}
		t.Skip("build parity artifacts with make cplane-route-composition cplane-route-composition-observer")
	}
	return data
}

func parityInstances(t testing.TB, observer bool, mutate func(*wasm.Config)) ([]eventInstance, []*recorder) {
	t.Helper()
	instances := make([]eventInstance, 2)
	recorders := []*recorder{{}, {}}
	for index, r := range recorders {
		cfg := config(r, observer)
		if mutate != nil {
			mutate(&cfg.Config)
		}
		var err error
		if index == 0 {
			instances[index], err = Instantiate(context.Background(), cfg)
		} else {
			cfg.Module = parityModule(t, observer)
			instances[index], err = wasm.Instantiate(context.Background(), cfg.Config)
		}
		if err != nil {
			t.Fatal(err)
		}
		instance := instances[index]
		t.Cleanup(func() { _ = instance.Close(context.Background()) })
	}
	return instances, recorders
}

func parityRoute(t testing.TB, n *bgp.MUPNLRI, attrs ...bgp.PathAttributeInterface) *v1.PluginEvent {
	t.Helper()
	raw, err := n.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	path := &v1.PluginBGPPath{Codec: cplane.BGPPathCodec, Afi: uint32(n.Afi), Safi: 85, Nlri: raw, RouteKey: []byte(n.String())}
	for _, attr := range attrs {
		raw, err := attr.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		path.Attributes = append(path.Attributes, raw)
	}
	return &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Route: &v1.PluginRoute{Family: "mup_ipv4", Peer: "192.0.2.254", Contexts: []string{"mobile"}, BgpPath: path}}
}

func parityRoutes(t testing.TB, teid uint32) []*v1.PluginEvent {
	t.Helper()
	a := netip.MustParseAddr
	p := netip.MustParsePrefix
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	var rawTEID [4]byte
	binary.BigEndian.PutUint32(rawTEID[:], teid)
	sid := func(behavior bgp.SRBehavior) bgp.PathAttributeInterface {
		return bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, bgp.NewSRv6InformationSubTLV(a("fd00:a:0:100::"), behavior, bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
	}
	direct := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0)})
	return []*v1.PluginEvent{
		parityRoute(t, bgp.NewMUPType1SessionTransformedRoute(rd, p("10.0.0.1/32"), netip.AddrFrom4(rawTEID), 9, a("172.16.0.1"), nil)),
		parityRoute(t, bgp.NewMUPInterworkSegmentDiscoveryRoute(rd, p("172.16.0.0/24")), sid(bgp.ENDM_GTP4E)),
		parityRoute(t, bgp.NewMUPType2SessionTransformedRoute(rd, 64, a("192.0.2.1"), netip.AddrFrom4(rawTEID)), direct),
		parityRoute(t, bgp.NewMUPDirectSegmentDiscoveryRoute(rd, a("192.0.2.2")), direct, sid(bgp.END_DT4)),
	}
}

func TestWASMNativeEncodedParity(t *testing.T) {
	for _, observer := range []bool{false, true} {
		name := "write"
		if observer {
			name = "observe"
		}
		t.Run(name, func(t *testing.T) {
			instances, rs := parityInstances(t, observer, nil)
			compare := func() {
				t.Helper()
				if !reflect.DeepEqual(rs[0], rs[1]) {
					t.Fatalf("host transactions differ:\nnative=%+v\nwasm=%+v", rs[0], rs[1])
				}
			}
			sequence := uint64(0)
			deliver := func(events ...*v1.PluginEvent) {
				t.Helper()
				for _, e := range events {
					sequence++
					e.Sequence = sequence
				}
				encoded, err := proto.Marshal(&v1.PluginEventBatch{Events: events})
				if err != nil {
					t.Fatal(err)
				}
				var previous []byte
				for k, i := range instances {
					out, err := i.HandleEvents(context.Background(), encoded)
					if err != nil {
						t.Fatalf("backend %d: %v", k, err)
					}
					if k == 0 {
						previous = out
					} else if !bytes.Equal(previous, out) {
						t.Fatalf("event statuses differ: %x != %x", previous, out)
					}
				}
				compare()
			}
			tick := func() {
				t.Helper()
				for _, i := range instances {
					if err := i.Tick(context.Background(), 123); err != nil {
						t.Fatal(err)
					}
				}
				compare()
			}
			start := func() *v1.PluginEvent {
				return &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, ReplaySource: cplane.BGPSource}
			}
			end := func() *v1.PluginEvent {
				return &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, ReplaySource: cplane.BGPSource}
			}
			initial := parityRoutes(t, 256)
			deliver(start())
			deliver(initial...)
			tick()
			if rs[0].commits != 0 {
				t.Fatal("incomplete replay wrote outputs")
			}
			deliver(end())
			tick()
			if !observer {
				if rs[0].commits != 1 {
					t.Fatal("initial desired set absent")
				}
				var chunk v1.PluginApplyChunk
				if err := proto.Unmarshal(rs[0].chunks[0], &chunk); err != nil || len(chunk.ForwardingHeadends) != 1 || len(chunk.MupUplinks) != 1 {
					t.Fatalf("MUP builders missing: %+v %v", &chunk, err)
				}
			}
			failure := errors.New("injected apply failure")
			for _, r := range rs {
				r.failure = failure
			}
			changed := parityRoutes(t, 512)[0]
			changed.Route.BgpPath.RouteKey = initial[0].Route.BgpPath.RouteKey
			deliver(changed)
			tick()
			newer := parityRoutes(t, 768)[0]
			newer.Route.BgpPath.RouteKey = initial[0].Route.BgpPath.RouteKey
			deliver(newer)
			for _, r := range rs {
				r.failure = nil
			}
			tick()
			tick()
			reflected := proto.Clone(newer).(*v1.PluginEvent)
			reflected.Route.Peer = "192.0.2.253"
			deliver(reflected)
			withdrawal := proto.Clone(newer).(*v1.PluginEvent)
			withdrawal.Route.IsWithdraw = true
			deliver(withdrawal)
			isdWithdraw := proto.Clone(initial[1]).(*v1.PluginEvent)
			isdWithdraw.Route.IsWithdraw = true
			deliver(isdWithdraw)
			deliver(&v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE})
			tick()
			deliver(start(), end())
			tick()
			if observer && rs[0].begins != 0 {
				t.Fatal("observer used write transport")
			}
		})
	}
}

func TestWASMNativeAdmissionParity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observer bool
		mutate   func(*wasm.Config)
	}{
		{"observer cannot promote", true, func(c *wasm.Config) { c.ConfigBlob = configuration(false) }},
		{"write profile needs grant", false, func(c *wasm.Config) { c.Capabilities = nil }},
		{"malformed config", false, func(c *wasm.Config) { c.ConfigBlob = []byte{0xff} }},
		{"config exceeds buffer", false, func(c *wasm.Config) { c.Limits.MaxBufferBytes = len(c.ConfigBlob) - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config(&recorder{}, tc.observer)
			tc.mutate(&cfg.Config)
			if i, err := Instantiate(context.Background(), cfg); err == nil {
				_ = i.Close(context.Background())
				t.Fatal("native accepted invalid config")
			}
			cfg.Module = parityModule(t, tc.observer)
			if i, err := wasm.Instantiate(context.Background(), cfg.Config); err == nil {
				_ = i.Close(context.Background())
				t.Fatal("WASM accepted invalid config")
			}
		})
	}
	// A successfully linked observer with no grants proves its artifact has no
	// apply_* imports; its configure envelope still cannot promote it to writing.
	instances, rs := parityInstances(t, true, func(c *wasm.Config) { c.Capabilities = nil })
	for _, i := range instances {
		if _, err := i.HandleEvents(context.Background(), replay()); err != nil {
			t.Fatal(err)
		}
	}
	if rs[0].begins+rs[1].begins != 0 {
		t.Fatal("observer wrote")
	}
}

func TestWASMNativeEventBufferParity(t *testing.T) {
	limit := len(configuration(false))
	limit += limit % 2
	for _, tc := range []struct {
		name      string
		batch     []byte
		wantError bool
	}{
		{"exact limit", bytes.Repeat([]byte{0x10, 0x00}, limit/2), false},
		{"over limit", make([]byte, limit+1), true},
		{"malformed", []byte{0xff}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unknown scalar fields exercise the full buffer without mutating the View.
			instances, _ := parityInstances(t, false, func(c *wasm.Config) { c.Limits.MaxBufferBytes = limit })
			for k, i := range instances {
				_, err := i.HandleEvents(context.Background(), tc.batch)
				if (err != nil) != tc.wantError {
					t.Fatalf("backend %d: %v", k, err)
				}
			}
		})
	}
}
