package native

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
	"google.golang.org/protobuf/proto"
)

type sharedCall struct {
	Method string
	Value  uint64
	Data   []byte
}

type sharedOps struct {
	Calls      []sharedCall
	Logs       []sharedLog
	next       uint64
	failCommit bool
	refuse     map[uint32]bool
}

type sharedLog struct {
	Level   int32
	Message string
}

func (o *sharedOps) Log(level int32, message string) {
	o.Logs = append(o.Logs, sharedLog{level, message})
}
func (o *sharedOps) ApplyBegin(kind uint32) (uint64, error) {
	o.Calls = append(o.Calls, sharedCall{Method: "begin", Value: uint64(kind)})
	if o.refuse[kind] {
		return 0, errors.New("kind unavailable")
	}
	o.next++
	return o.next, nil
}
func (o *sharedOps) ApplyPut(id uint64, data []byte) error {
	o.Calls = append(o.Calls, sharedCall{Method: "put", Value: id, Data: append([]byte(nil), data...)})
	return nil
}
func (o *sharedOps) ApplyCommit(id uint64) error {
	o.Calls = append(o.Calls, sharedCall{Method: "commit", Value: id})
	if o.failCommit {
		return errors.New("injected commit failure")
	}
	return nil
}
func (o *sharedOps) ApplyAbort(id uint64) {
	o.Calls = append(o.Calls, sharedCall{Method: "abort", Value: id})
}

func sharedModule(t *testing.T, id string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "out", "cplane-bgp-observer.wasm")
	if id == CustomBehavior {
		path = filepath.Join("..", "..", "..", "sdk", "examples", "cplane-custom-behavior", "plugin.wasm")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
			t.Fatal("build fresh artifacts with make cplane-example cplane-bgp-observer: ", err)
		}
		t.Skip("build shared controller artifacts: ", err)
	}
	return raw
}

func sharedInstances(t *testing.T, id string, config []byte) ([]eventInstance, []*sharedOps) {
	t.Helper()
	instances := make([]eventInstance, 2)
	ops := []*sharedOps{{}, {}}
	for index := range instances {
		cfg := wasm.Config{Name: id, Ops: ops[index], ConfigBlob: config}
		if id == CustomBehavior {
			cfg.Capabilities = wasm.Capabilities{wasm.CapHeadend: {}}
		}
		var err error
		if index == 0 {
			instances[index], err = Instantiate(context.Background(), Config{Config: cfg, Implementation: id, Version: ImplementationVersion})
		} else {
			cfg.Module = sharedModule(t, id)
			instances[index], err = wasm.Instantiate(context.Background(), cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		instance := instances[index]
		t.Cleanup(func() { _ = instance.Close(context.Background()) })
	}
	return instances, ops
}

func sharedDeliver(t *testing.T, instances []eventInstance, events ...*v1.PluginEvent) []byte {
	t.Helper()
	raw, err := proto.Marshal(&v1.PluginEventBatch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for index, instance := range instances {
		out, err := instance.HandleEvents(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			previous = out
		} else if !bytes.Equal(previous, out) {
			t.Fatalf("event statuses differ: %x != %x", previous, out)
		}
	}
	return previous
}

func sharedCompare(t *testing.T, ops []*sharedOps) {
	t.Helper()
	if !reflect.DeepEqual(ops[0], ops[1]) {
		t.Fatalf("native/WASM transcripts differ:\nnative=%+v\nwasm=%+v", ops[0], ops[1])
	}
}

func sharedTick(t *testing.T, instances []eventInstance, ops []*sharedOps) {
	t.Helper()
	for _, instance := range instances {
		if err := instance.Tick(context.Background(), 123); err != nil {
			t.Fatal(err)
		}
	}
	sharedCompare(t, ops)
}

func TestCustomBehaviorEncodedParity(t *testing.T) {
	var config wire.Encoder
	config.String(9, "10.0.0.0/8")
	instances, ops := sharedInstances(t, CustomBehavior, config)
	sharedCompare(t, ops)
	if len(ops[0].Calls) != 4 || ops[0].Calls[0].Value != uint64(cplane.Advertise) || ops[0].Calls[2].Value != uint64(cplane.LocalSIDs) {
		t.Fatal("configure cleanup order changed")
	}
	marker := func(kind v1.PluginEventKind) *v1.PluginEvent {
		return &v1.PluginEvent{Kind: kind, ReplaySource: cplane.BGPSource}
	}
	route := func(peer, sid string) *v1.PluginEvent {
		return &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Route: &v1.PluginRoute{
			Family: "vpnv4", Rd: "65000:7", Peer: peer, Prefix: "10.0.0.0/24", Srv6Sid: sid, EndpointBehavior: 0xfe01}}
	}
	first := route("192.0.2.1", "fd00:1::1")
	sharedDeliver(t, instances, marker(v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY), first)
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != 4 {
		t.Fatal("incomplete replay submitted headends")
	}
	sharedDeliver(t, instances, marker(v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY))
	sharedCompare(t, ops)
	var output v1.PluginApplyChunk
	if err := proto.Unmarshal(ops[0].Calls[len(ops[0].Calls)-2].Data, &output); err != nil || len(output.HeadendEntries) != 1 || output.HeadendEntries[0].Segments[0] != "fd00:1::1" {
		t.Fatalf("missing expected initial headend: %+v %v", &output, err)
	}
	for _, o := range ops {
		o.failCommit = true
	}
	sharedDeliver(t, instances, route("192.0.2.2", "fd00:2::1"))
	sharedCompare(t, ops)
	for _, o := range ops {
		o.failCommit = false
	}
	sharedTick(t, instances, ops)
	before := len(ops[0].Calls)
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != before {
		t.Fatal("successful desired set retried")
	}
	// Attribute loss replaces the same key; the second peer must survive.
	replacement := route("192.0.2.1", "")
	replacement.Route.EndpointBehavior = 0
	sharedDeliver(t, instances, replacement)
	sharedCompare(t, ops)
	output.Reset()
	if err := proto.Unmarshal(ops[0].Calls[len(ops[0].Calls)-2].Data, &output); err != nil || len(output.HeadendEntries) != 1 || output.HeadendEntries[0].Segments[0] != "fd00:2::1" {
		t.Fatal("remaining path did not replace the lost attribute path")
	}
	withdraw := route("192.0.2.2", "")
	withdraw.Route.EndpointBehavior, withdraw.Route.IsWithdraw = 0, true
	sharedDeliver(t, instances, withdraw)
	sharedDeliver(t, instances, marker(v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY), marker(v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY))
	sharedCompare(t, ops)
}

func TestBGPObserverEncodedParity(t *testing.T) {
	// The observer ignores its opaque payload, including non-envelope bytes.
	instances, ops := sharedInstances(t, BGPObserver, []byte{0xff})
	first := parityRoutes(t, 256)[0]
	first.Sequence = 7
	bad := proto.Clone(first).(*v1.PluginEvent)
	bad.Sequence, bad.Route.BgpPath.Nlri = 8, []byte{0xff}
	out := sharedDeliver(t, instances, first, bad, &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY})
	sharedTick(t, instances, ops)
	var status v1.PluginEventStatus
	if err := proto.Unmarshal(out, &status); err != nil || len(status.Results) != 1 || status.Results[0].Sequence != 8 || status.Results[0].Disposition != v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE {
		t.Fatalf("observer did not quarantine malformed NLRI: %+v %v", &status, err)
	}
	if len(ops[0].Calls) != 0 || len(ops[0].Logs) != 1 {
		t.Fatal("observer wrote host state or failed to log its route")
	}
	first.Route.IsWithdraw = true
	sharedDeliver(t, instances, first)
	sharedCompare(t, ops)
}

func TestCustomSenderEncodedParity(t *testing.T) {
	var config wire.Encoder
	config.String(2, "main")
	config.String(3, "10.7.0.0/24")
	config.String(4, "vpn-a")
	config.Uint(5, 33)
	config.String(7, "2001:db8::1")
	instances, ops := sharedInstances(t, CustomBehavior, config)
	sharedCompare(t, ops)
	if len(ops[0].Calls) != 3 || ops[0].Calls[0].Value != uint64(cplane.LocalSIDs) {
		t.Fatal("sender did not request its local SID during configure")
	}
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != 6 {
		t.Fatal("missing SID notification was not retried")
	}
	allocated := &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID,
		LocalSid: &v1.PluginLocalSidAllocated{Name: "self", Sid: "fd00:100::1", Locator: "main"}}
	sharedDeliver(t, instances, allocated)
	sharedCompare(t, ops)
	var output v1.PluginApplyChunk
	if err := proto.Unmarshal(ops[0].Calls[len(ops[0].Calls)-2].Data, &output); err != nil || len(output.AdvertisedRoutes) != 1 || output.AdvertisedRoutes[0].Srv6Sid != "fd00:100::1" {
		t.Fatalf("sender did not advertise allocated SID: %+v %v", &output, err)
	}
	before := len(ops[0].Calls)
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != before {
		t.Fatal("successful sender declaration retried")
	}
}

func TestCustomNativeInstancesHaveIndependentConfiguration(t *testing.T) {
	ops := []*sharedOps{{}, {}}
	instances := make([]eventInstance, 2)
	for i := range instances {
		var payload wire.Encoder
		payload.Uint(1, uint64(0xfe01+i))
		cfg := Config{Config: wasm.Config{Name: "independent", Ops: ops[i], ConfigBlob: payload,
			Capabilities: wasm.Capabilities{wasm.CapHeadend: {}}}, Implementation: CustomBehavior, Version: ImplementationVersion}
		instance, err := Instantiate(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		instances[i] = instance
		t.Cleanup(func() { _ = instance.Close(context.Background()) })
	}
	event := &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Route: &v1.PluginRoute{
		Family: "vpnv4", Rd: "65000:7", Peer: "192.0.2.1", Prefix: "10.0.0.0/24", Srv6Sid: "fd00:1::1", EndpointBehavior: 0xfe01}}
	sharedDeliver(t, instances, event)
	if len(ops[0].Calls) != 7 || len(ops[1].Calls) != 4 {
		t.Fatal("native instances shared route/config state")
	}
	event.Route.EndpointBehavior = 0xfe02
	sharedDeliver(t, instances, event)
	if len(ops[0].Calls) != 9 || len(ops[1].Calls) != 7 {
		t.Fatal("other instance overwrote the first instance's config")
	}
}

func TestCustomKindRefusalEncodedParity(t *testing.T) {
	instances, ops := sharedInstances(t, CustomBehavior, nil)
	for _, o := range ops {
		o.refuse = map[uint32]bool{uint32(cplane.HeadendV4): true}
	}
	sharedDeliver(t, instances, &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
		Route: &v1.PluginRoute{Family: "vpnv4", Rd: "65000:7", Prefix: "10.0.0.0/24", Srv6Sid: "fd00:1::1", EndpointBehavior: 0xfe01}})
	sharedCompare(t, ops)
	before := len(ops[0].Calls)
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != before {
		t.Fatal("unavailable kind was retried")
	}
}

func TestNewControllersAdmissionBeforeWrites(t *testing.T) {
	for _, id := range []string{CustomBehavior, BGPObserver} {
		d, ok := Lookup(id)
		if !ok || len(d.Identity) != 64 || d.Write != (id == CustomBehavior) {
			t.Fatalf("descriptor: %+v", d)
		}
	}
	for _, config := range []Config{
		{Config: wasm.Config{Name: "test", Ops: &sharedOps{}}, Implementation: CustomBehavior, Version: ImplementationVersion},
		{Config: wasm.Config{Name: "test", Ops: &sharedOps{}, ConfigBlob: []byte{0xff}, Capabilities: wasm.Capabilities{wasm.CapHeadend: {}}}, Implementation: CustomBehavior, Version: ImplementationVersion},
	} {
		for _, backend := range []string{"native", "wasm"} {
			config.Ops = &sharedOps{}
			var err error
			if backend == "native" {
				_, err = Instantiate(context.Background(), config)
			} else {
				config.Module = sharedModule(t, CustomBehavior)
				_, err = wasm.Instantiate(context.Background(), config.Config)
			}
			if err == nil {
				t.Fatalf("%s accepted a forbidden or malformed configuration", backend)
			}
			if backend == "native" && !errors.Is(err, wasm.ErrAdmission) {
				t.Fatalf("native configuration error lost admission classification: %v", err)
			}
			if len(config.Ops.(*sharedOps).Calls) != 0 {
				t.Fatal("rejected configure wrote declarations")
			}
		}
	}
}
