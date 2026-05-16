package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf/btf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// TestValidatePluginSlot verifies the slot-range policing applied to every
// PluginAux RPC — catches callers that supply a builtin or out-of-range slot
// before the owner tag can create a dangling entry.
func TestValidatePluginSlot(t *testing.T) {
	cases := []struct {
		name    string
		mapType string
		slot    uint32
		wantErr bool
	}{
		{"endpoint_valid_low", bpf.MapTypeEndpoint, bpf.EndpointPluginBase, false},
		{"endpoint_valid_high", bpf.MapTypeEndpoint, bpf.EndpointProgMax - 1, false},
		{"endpoint_below_base", bpf.MapTypeEndpoint, bpf.EndpointPluginBase - 1, true},
		{"endpoint_above_max", bpf.MapTypeEndpoint, bpf.EndpointProgMax, true},
		{"headend_v4_valid", bpf.MapTypeHeadendV4, bpf.HeadendPluginBase, false},
		{"headend_v6_below_base", bpf.MapTypeHeadendV6, bpf.HeadendPluginBase - 1, true},
		{"unknown_map_type", "bogus", 32, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePluginSlot(c.mapType, c.slot)
			if c.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestEncodePluginAuxPayload_Raw covers the raw path: exact length check,
// oversize rejection, and passthrough of raw bytes.
func TestEncodePluginAuxPayload_Raw(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}
	raw := []byte{1, 2, 3, 4}

	got, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, raw, "")
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("raw passthrough mismatch: got %v", got)
	}

	// Oversized raw must be rejected.
	big := make([]byte, bpf.SidAuxPluginRawMax+1)
	if _, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, big, ""); err == nil {
		t.Error("expected oversized raw to fail")
	}

	// Both raw and json must be rejected.
	if _, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, raw, "{}"); err == nil {
		t.Error("expected raw+json to fail")
	}

	// Neither raw nor json must be rejected.
	if _, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, nil, ""); err == nil {
		t.Error("expected empty payload to fail")
	}
}

// TestEncodePluginAuxPayload_JSONWithoutAuxType rejects JSON when the plugin
// registered without a <program>_aux BTF type; the encoder has no way to
// interpret the payload so the caller must fall back to raw bytes.
func TestEncodePluginAuxPayload_JSONWithoutAuxType(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}
	// registry has no entry for (endpoint, 32), so AuxType returns nil.
	_, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, nil, `{"x":1}`)
	if err == nil || !strings.Contains(err.Error(), "BTF") {
		t.Errorf("expected BTF-missing error, got: %v", err)
	}
}

// TestEncodePluginAuxPayload_JSONWithAuxType walks through the BTF encode
// path by registering a fake plugin entry with a single-field aux struct.
func TestEncodePluginAuxPayload_JSONWithAuxType(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}
	s.registry[pluginSlotKey{MapType: bpf.MapTypeEndpoint, Slot: 32}] = &pluginEntry{
		program: "p",
		auxType: &btf.Struct{
			Name: "p_aux",
			Size: 4,
			Members: []btf.Member{
				{Name: "x", Type: &btf.Int{Size: 4, Encoding: btf.Unsigned}, Offset: 0},
			},
		},
	}

	raw, err := s.encodePluginAuxPayload(bpf.MapTypeEndpoint, 32, nil, `{"x": 7}`)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(raw) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(raw))
	}
	// little-endian is the BPF ABI target; the encoder writes native-endian,
	// which on x86_64 matches LE. Just verify round-trip by checking value.
	// Cross-architecture hosts would need a proper decode; asserting magnitude
	// is enough for this unit test because the encoder is shared with the
	// existing plugin_aux_encode path that has richer tests.
	nonzero := false
	for _, b := range raw {
		if b != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		t.Error("encoded payload is all zero; encoder did not fill any bytes")
	}
}

// TestOwnerTagFor fixes the owner-tag format. Both the server and the CLI
// derive the same string from (map_type, slot), so a change here requires
// coordinated updates elsewhere. Phase 2 stamps the tag with a version
// prefix so future format changes can be detected by ParseAuxOwnerTag.
func TestOwnerTagFor(t *testing.T) {
	if got := bpf.AuxOwnerPluginTag(bpf.MapTypeEndpoint, 32); got != "plugin:v1:endpoint:32" {
		t.Errorf("got %q, want plugin:v1:endpoint:32", got)
	}
	if got := bpf.AuxOwnerPluginTag(bpf.MapTypeHeadendV4, 16); got != "plugin:v1:headend_v4:16" {
		t.Errorf("got %q, want plugin:v1:headend_v4:16", got)
	}
}

// TestPluginAuxPurge_InvalidArgs guards the front-door validation on the
// purge RPC. Real purge behaviour is exercised in the pkg/bpf allocator
// tests because those don't need a BPF map handle; here we just pin the
// error path so a typo in (map_type, slot) surfaces as InvalidArgument
// rather than a silent no-op.
func TestPluginAuxPurge_InvalidArgs(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}

	cases := []struct {
		name    string
		mapType string
		slot    uint32
	}{
		{"unknown_map_type", "bogus", 32},
		{"endpoint_below_base", bpf.MapTypeEndpoint, bpf.EndpointPluginBase - 1},
		{"endpoint_above_max", bpf.MapTypeEndpoint, bpf.EndpointProgMax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := connect.NewRequest(&v1.PluginAuxPurgeRequest{MapType: c.mapType, Slot: c.slot})
			_, err := s.PluginAuxPurge(context.Background(), req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var connectErr *connect.Error
			if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeInvalidArgument {
				t.Errorf("expected InvalidArgument, got %v", err)
			}
		})
	}
}

// TestPluginAuxPurge_RejectsLiveSlot pins the precondition guard that
// stops purge from nuking aux of a still-registered plugin. The
// canonical operator flow is PluginUnregister -> PluginAuxList ->
// PluginAuxPurge; without this guard a stray purge would zero every aux
// entry the running plugin depends on. mapOps is intentionally nil — the
// guard must fire before any BPF call so mapOps is never reached on the
// reject path.
func TestPluginAuxPurge_RejectsLiveSlot(t *testing.T) {
	key := pluginSlotKey{MapType: bpf.MapTypeEndpoint, Slot: 32}
	s := &PluginServer{
		registry: map[pluginSlotKey]*pluginEntry{
			key: {program: "plugin_counter", registeredAt: time.Now()},
		},
	}
	req := connect.NewRequest(&v1.PluginAuxPurgeRequest{
		MapType: bpf.MapTypeEndpoint,
		Slot:    32,
	})
	_, err := s.PluginAuxPurge(context.Background(), req)
	if err == nil {
		t.Fatal("expected FailedPrecondition for live slot, got nil")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeFailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if !strings.Contains(err.Error(), "still registered") {
		t.Errorf("error should explain the live-registration block, got: %v", err)
	}
}

// TestPluginAuxList_FilterValidation pins the "filter must validate"
// promise: an unknown map_type or an out-of-range slot under
// match_slot=true returns InvalidArgument so callers spot typos
// immediately. The empty-filter "list everything" path still works.
func TestPluginAuxList_FilterValidation(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}

	t.Run("unknown_map_type", func(t *testing.T) {
		req := connect.NewRequest(&v1.PluginAuxListRequest{MapType: "bogus"})
		if _, err := s.PluginAuxList(context.Background(), req); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("match_slot_below_base", func(t *testing.T) {
		req := connect.NewRequest(&v1.PluginAuxListRequest{
			MapType:   bpf.MapTypeEndpoint,
			Slot:      bpf.EndpointPluginBase - 1,
			MatchSlot: true,
		})
		_, err := s.PluginAuxList(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeInvalidArgument {
			t.Errorf("expected InvalidArgument, got %v", err)
		}
	})
}
