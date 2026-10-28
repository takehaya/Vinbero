package native

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/cdplanecontroller"
	"google.golang.org/protobuf/proto"
)

const cdplaneSenderConfig = `{"schema_version":1,"routing":{"locator":"main","prefix":"10.7.0.0/24","vrf":"blue","slot":32,"next_hop":"2001:db8::1","decap_vrf":"blue"},"endpoint":{"allowed_underlay_prefix":"2001:db8:ff::1/128"}}`

func TestCustomCDplaneSenderEncodedParity(t *testing.T) {
	instances, ops := sharedInstances(t, CustomCDplaneBehavior, []byte(cdplaneSenderConfig))
	sharedCompare(t, ops)
	if len(ops[0].Calls) != 3 || ops[0].Calls[0].Value != uint64(cplane.LocalSIDs) {
		t.Fatal("sender did not declare its endpoint during configure")
	}
	var chunk v1.PluginApplyChunk
	if err := proto.Unmarshal(ops[0].Calls[1].Data, &chunk); err != nil {
		t.Fatal(err)
	}
	wantAux, err := cdplanecontroller.EncodeEndpointAux(netip.MustParsePrefix("2001:db8:ff::1/128"))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.LocalSids) != 1 || !bytes.Equal(chunk.LocalSids[0].AuxRaw, wantAux) || chunk.LocalSids[0].DecapVrf != "blue" {
		t.Fatalf("missing expected endpoint policy or VRF grant: %+v", &chunk)
	}
	for _, op := range ops {
		op.failCommit = true
	}
	sharedTick(t, instances, ops)
	for _, op := range ops {
		op.failCommit = false
	}
	sharedTick(t, instances, ops)
	sharedDeliver(t, instances, &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID,
		LocalSid: &v1.PluginLocalSidAllocated{Name: "self", Sid: "fd00:100::1", Locator: "main"}})
	sharedCompare(t, ops)
	chunk.Reset()
	if err := proto.Unmarshal(ops[0].Calls[len(ops[0].Calls)-2].Data, &chunk); err != nil || len(chunk.AdvertisedRoutes) != 1 || chunk.AdvertisedRoutes[0].Srv6Sid != "fd00:100::1" {
		t.Fatalf("sender did not advertise its allocated SID: %+v %v", &chunk, err)
	}
	before := len(ops[0].Calls)
	sharedTick(t, instances, ops)
	if len(ops[0].Calls) != before {
		t.Fatal("successful sender continued retrying")
	}
}

func TestCustomCDplaneReceiverEncodedParity(t *testing.T) {
	instances, ops := sharedInstances(t, CustomCDplaneBehavior, []byte(`{"schema_version":1,"routing":{"headend_prefixes":["10.7.0.0/16"]}}`))
	sharedCompare(t, ops)
	sharedDeliver(t, instances,
		&v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
			Route: &v1.PluginRoute{Family: "vpnv4", Prefix: "10.7.1.0/24", Srv6Sid: "fd00:100::1", EndpointBehavior: 0xfe01}},
		&v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
			Route: &v1.PluginRoute{Family: "vpnv4", Prefix: "10.8.1.0/24", Srv6Sid: "fd00:200::1", EndpointBehavior: 0xfe01}})
	sharedCompare(t, ops)
	var chunk v1.PluginApplyChunk
	if err := proto.Unmarshal(ops[0].Calls[len(ops[0].Calls)-2].Data, &chunk); err != nil || len(chunk.HeadendEntries) != 1 || chunk.HeadendEntries[0].TriggerPrefix != "10.7.1.0/24" {
		t.Fatalf("receiver did not apply its configured routing filter: %+v %v", &chunk, err)
	}
}

func TestCustomCDplaneRejectedConfigurationParity(t *testing.T) {
	for _, data := range []string{`null`, `{"schema_version":2,"routing":{}}`, `{"schema_version":1,"routing":{},"typo":true}`, cdplaneSenderConfig + `{}`} {
		for _, backend := range []string{"native", "wasm"} {
			t.Run(backend+"/"+data, func(t *testing.T) {
				op := &sharedOps{}
				cfg := wasm.Config{Name: "invalid", Ops: op, ConfigBlob: []byte(data), Capabilities: wasm.Capabilities{wasm.CapLocalSID: {}}}
				var err error
				if backend == "native" {
					_, err = Instantiate(context.Background(), Config{Config: cfg, Implementation: CustomCDplaneBehavior, Version: ImplementationVersion})
					if !errors.Is(err, wasm.ErrAdmission) {
						t.Fatalf("configure error lost admission classification: %v", err)
					}
				} else {
					cfg.Module = sharedModule(t, CustomCDplaneBehavior)
					_, err = wasm.Instantiate(context.Background(), cfg)
				}
				if err == nil || len(op.Calls) != 0 {
					t.Fatalf("invalid JSON accepted or wrote declarations: %v %+v", err, op.Calls)
				}
			})
		}
	}
}
