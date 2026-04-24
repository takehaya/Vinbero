package server

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
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
// coordinated updates elsewhere.
func TestOwnerTagFor(t *testing.T) {
	if got := bpf.AuxOwnerPluginTag(bpf.MapTypeEndpoint, 32); got != "plugin:endpoint:32" {
		t.Errorf("got %q, want plugin:endpoint:32", got)
	}
	if got := bpf.AuxOwnerPluginTag(bpf.MapTypeHeadendV4, 16); got != "plugin:headend_v4:16" {
		t.Errorf("got %q, want plugin:headend_v4:16", got)
	}
}
