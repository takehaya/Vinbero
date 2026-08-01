package server

import (
	"context"
	"net/netip"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// newLiveSidServer builds a SidFunctionServer backed by a real BPF map
// collection. Requires sudo (the CI Unit Test job runs `go test -exec
// "sudo -E"`); loading is skipped with a clear message otherwise.
func newLiveSidServer(t *testing.T) (*SidFunctionServer, *bpf.MapOperations) {
	t.Helper()
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mapOps := bpf.NewMapOperations(objs)
	return NewSidFunctionServer(mapOps, nil, nil, nil), mapOps
}

func adProxy(prefix string, ifaceIn, oif uint32) *v1.SidFunction {
	in := ifaceIn
	return &v1.SidFunction{
		Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
		TriggerPrefix: prefix,
		Oif:           oif,
		IfaceIn:       &in,
		InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
	}
}

func createSid(t *testing.T, s *SidFunctionServer, sf *v1.SidFunction) {
	t.Helper()
	resp, err := s.SidFunctionCreate(context.Background(),
		connect.NewRequest(&v1.SidFunctionCreateRequest{SidFunctions: []*v1.SidFunction{sf}}))
	if err != nil {
		t.Fatalf("SidFunctionCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 0 {
		t.Fatalf("SidFunctionCreate errors: %v", resp.Msg.Errors)
	}
}

// TestSidFunctionCircuitLifecycle covers the server-level proxy circuit
// lifecycle: bind on create, orphan cleanup when a re-create moves or
// drops the circuit, and unbind (with ad_cache cleanup) on delete.
func TestSidFunctionCircuitLifecycle(t *testing.T) {
	s, mapOps := newLiveSidServer(t)
	const prefix = "fc00:2::10/128"

	t.Run("create binds the circuit", func(t *testing.T) {
		createSid(t, s, adProxy(prefix, 5, 5))
		if _, err := mapOps.GetServiceIngress(5, 0); err != nil {
			t.Fatalf("circuit not bound after create: %v", err)
		}
	})

	t.Run("re-create on a new circuit unbinds the old one", func(t *testing.T) {
		createSid(t, s, adProxy(prefix, 6, 6))
		if _, err := mapOps.GetServiceIngress(6, 0); err != nil {
			t.Fatalf("new circuit not bound: %v", err)
		}
		if _, err := mapOps.GetServiceIngress(5, 0); err == nil {
			t.Fatalf("old circuit was orphaned (still bound after the SID moved)")
		}
	})

	t.Run("re-create as a non-proxy action unbinds the circuit", func(t *testing.T) {
		createSid(t, s, &v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END,
			TriggerPrefix: prefix,
		})
		if _, err := mapOps.GetServiceIngress(6, 0); err == nil {
			t.Fatalf("circuit survived the SID becoming a non-proxy action")
		}
	})

	t.Run("delete unbinds the circuit", func(t *testing.T) {
		createSid(t, s, adProxy(prefix, 7, 7))
		resp, err := s.SidFunctionDelete(context.Background(),
			connect.NewRequest(&v1.SidFunctionDeleteRequest{TriggerPrefixes: []string{prefix}}))
		if err != nil {
			t.Fatalf("SidFunctionDelete: %v", err)
		}
		if len(resp.Msg.Errors) != 0 {
			t.Fatalf("delete errors: %v", resp.Msg.Errors)
		}
		// The chained ad_cache delete is covered by pkg/bpf's
		// TestServiceIngressLifecycle; here we assert the server-level
		// unbind on delete.
		if _, err := mapOps.GetServiceIngress(7, 0); err == nil {
			t.Fatalf("circuit survived delete")
		}
	})
}

// TestSidFunctionFlushOwnerScope verifies that an RPC flush does not
// unbind the return circuit of a proxy SID owned by another writer (a
// BGP-owned SID), which the previous all-owner collection did — stealing
// a live SID's circuit and leaking its decapsulated traffic.
func TestSidFunctionFlushOwnerScope(t *testing.T) {
	s, mapOps := newLiveSidServer(t)

	// An RPC-owned proxy SID (will be flushed).
	createSid(t, s, adProxy("fc00:2::20/128", 8, 8))

	// A BGP-owned proxy SID installed directly (survives an RPC flush).
	bgpEntry := &bpf.SidFunctionEntry{Action: uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD)}
	svc := &bpf.SidAuxService{IfaceOut: 9, IfaceIn: 9, InnerType: bpf.SvcInnerIPv4}
	bgpOwner := bpf.OwnerBGPVPN(65000, "65000:100")
	if err := mapOps.CreateSidFunction("fc00:2::21/128", bgpEntry, bpf.NewSidAuxService(svc), bgpOwner); err != nil {
		t.Fatalf("create BGP SID: %v", err)
	}
	if _, err := mapOps.CreateServiceIngress(9, 0, &bpf.ServiceIngressEntry{
		Behavior: bpf.SvcRetAD, InnerTypeMask: bpf.SvcInnerIPv4,
		Sid: netip.MustParseAddr("fc00:2::21").As16(),
	}); err != nil {
		t.Fatalf("bind BGP circuit: %v", err)
	}

	if _, err := s.SidFunctionFlush(context.Background(),
		connect.NewRequest(&v1.SidFunctionFlushRequest{})); err != nil {
		t.Fatalf("SidFunctionFlush: %v", err)
	}

	if _, err := mapOps.GetServiceIngress(8, 0); err == nil {
		t.Fatalf("RPC-owned circuit survived the flush")
	}
	if _, err := mapOps.GetServiceIngress(9, 0); err != nil {
		t.Fatalf("BGP-owned circuit was unbound by an RPC flush: %v", err)
	}
}
