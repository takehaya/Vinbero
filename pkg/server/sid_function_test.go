package server

import (
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// newProtoToEntryServer builds a SidFunctionServer with nil deps. protoToEntry
// only reads s.pluginAux on the plugin_aux_json branch, and never touches
// s.mapOps; tests that exercise raw / index / range-check paths can therefore
// share this minimal server without spinning up real BPF maps.
func newProtoToEntryServer() *SidFunctionServer {
	return NewSidFunctionServer(nil, nil, nil)
}

// pluginAction returns a v1.Srv6LocalAction value inside the endpoint plugin
// slot range so plugin_aux_index validation succeeds. Action 32 corresponds
// to EndpointPluginBase.
func pluginAction() v1.Srv6LocalAction {
	return v1.Srv6LocalAction(bpf.EndpointPluginBase)
}

// TestProtoToEntry_3WayExclusive verifies that plugin_aux_raw,
// plugin_aux_json and plugin_aux_index cannot be combined on the same
// SidFunction. Single-field combinations that don't require pluginAux
// wiring (raw alone, index alone, none) are also asserted to succeed.
func TestProtoToEntry_3WayExclusive(t *testing.T) {
	s := newProtoToEntryServer()

	cases := []struct {
		name       string
		raw        []byte
		jsonStr    string
		index      uint32
		action     v1.Srv6LocalAction
		wantErr    bool
		wantAuxNil bool // only meaningful when wantErr == false
		wantAuxIdx uint16
	}{
		{
			name:       "raw only",
			raw:        []byte{1, 2, 3},
			action:     pluginAction(),
			wantErr:    false,
			wantAuxNil: false,
		},
		{
			name:       "index only",
			index:      1,
			action:     pluginAction(),
			wantErr:    false,
			wantAuxNil: true, // index path returns aux == nil
			wantAuxIdx: 1,
		},
		{
			name:       "all zero",
			action:     pluginAction(),
			wantErr:    false,
			wantAuxNil: true,
		},
		{
			name:    "raw + json",
			raw:     []byte{1},
			jsonStr: "{}",
			wantErr: true,
		},
		{
			name:    "json + index",
			jsonStr: "{}",
			index:   1,
			action:  pluginAction(),
			wantErr: true,
		},
		{
			name:    "raw + index",
			raw:     []byte{1},
			index:   1,
			action:  pluginAction(),
			wantErr: true,
		},
		{
			name:    "all three",
			raw:     []byte{1},
			jsonStr: "{}",
			index:   1,
			action:  pluginAction(),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf := &v1.SidFunction{
				Action:         tc.action,
				PluginAuxRaw:   tc.raw,
				PluginAuxJson:  tc.jsonStr,
				PluginAuxIndex: tc.index,
			}
			entry, aux, err := s.protoToEntry(sf)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got entry=%+v aux=%+v", entry, aux)
				}
				if !strings.Contains(err.Error(), "mutually exclusive") {
					t.Fatalf("expected 'mutually exclusive' in error, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if entry == nil {
				t.Fatalf("expected non-nil entry")
			}
			if tc.wantAuxNil && aux != nil {
				t.Fatalf("expected aux to be nil, got %+v", aux)
			}
			if !tc.wantAuxNil && aux == nil {
				t.Fatalf("expected non-nil aux")
			}
			if tc.wantAuxIdx != 0 && entry.AuxIndex != tc.wantAuxIdx {
				t.Fatalf("expected entry.AuxIndex=%d, got %d", tc.wantAuxIdx, entry.AuxIndex)
			}
		})
	}
}

// TestProtoToEntry_PluginAuxIndexValidation covers the action-range and
// uint16 boundary checks on the plugin_aux_index branch.
func TestProtoToEntry_PluginAuxIndexValidation(t *testing.T) {
	s := newProtoToEntryServer()

	cases := []struct {
		name      string
		action    v1.Srv6LocalAction
		index     uint32
		wantErr   bool
		errSubstr string
		wantIdx   uint16
	}{
		{
			name:      "action below plugin range",
			action:    v1.Srv6LocalAction(bpf.EndpointPluginBase - 17), // 15
			index:     1,
			wantErr:   true,
			errSubstr: "plugin_aux_index requires action",
		},
		{
			name:      "action at EndpointProgMax (out of range)",
			action:    v1.Srv6LocalAction(bpf.EndpointProgMax), // 64
			index:     1,
			wantErr:   true,
			errSubstr: "plugin_aux_index requires action",
		},
		{
			name:      "index exceeds uint16",
			action:    pluginAction(),
			index:     0x10000,
			wantErr:   true,
			errSubstr: "uint16",
		},
		{
			name:    "valid plugin index",
			action:  pluginAction(),
			index:   1,
			wantErr: false,
			wantIdx: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf := &v1.SidFunction{
				Action:         tc.action,
				PluginAuxIndex: tc.index,
			}
			entry, aux, err := s.protoToEntry(sf)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got entry=%+v aux=%+v", entry, aux)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tc.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if entry == nil {
				t.Fatalf("expected non-nil entry")
			}
			if entry.AuxIndex != tc.wantIdx {
				t.Fatalf("expected entry.AuxIndex=%d, got %d", tc.wantIdx, entry.AuxIndex)
			}
			// index path must not produce a built-in aux entry.
			if aux != nil {
				t.Fatalf("expected aux=nil on index path, got %+v", aux)
			}
		})
	}
}

// TestProtoToEntry_ActionUint8Range guards against silent uint8 truncation.
// Action values outside [0, 255] must be rejected before the entry is built,
// otherwise the stored entry.Action and the action used to derive the plugin
// owner tag would diverge by multiples of 256.
func TestProtoToEntry_ActionUint8Range(t *testing.T) {
	s := newProtoToEntryServer()

	t.Run("action 256 rejected", func(t *testing.T) {
		sf := &v1.SidFunction{
			Action: v1.Srv6LocalAction(256),
		}
		_, _, err := s.protoToEntry(sf)
		if err == nil {
			t.Fatalf("expected error for action 256")
		}
		if !strings.Contains(err.Error(), "uint8") {
			t.Fatalf("expected error mentioning uint8, got %q", err.Error())
		}
	})

	t.Run("negative action rejected", func(t *testing.T) {
		sf := &v1.SidFunction{
			Action: v1.Srv6LocalAction(-1),
		}
		_, _, err := s.protoToEntry(sf)
		if err == nil {
			t.Fatalf("expected error for negative action")
		}
		if !strings.Contains(err.Error(), "uint8") {
			t.Fatalf("expected error mentioning uint8, got %q", err.Error())
		}
	})

	// action=255 is in uint8 range; pair it with the raw aux path so we
	// exercise the range check independently of the plugin index range.
	// 255 is outside [EndpointPluginBase, EndpointProgMax) so the plugin
	// index branch would reject it for an unrelated reason.
	t.Run("action 255 with raw payload accepted", func(t *testing.T) {
		sf := &v1.SidFunction{
			Action:       v1.Srv6LocalAction(255),
			PluginAuxRaw: []byte{0xab},
		}
		entry, _, err := s.protoToEntry(sf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry == nil {
			t.Fatalf("expected non-nil entry")
		}
		if entry.Action != 255 {
			t.Fatalf("expected entry.Action=255, got %d", entry.Action)
		}
	})
}
