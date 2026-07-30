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

// TestProtoToEntry_Gtp4eSrcConfig verifies the END_M_GTP4_E source rules:
// exactly one of gtp_v4_src_addr / gtp_v4_src_position must be set, the
// position is bounded at 96 (32 bits of the outer IPv6 SA must remain), and
// position 0 is accepted (presence lives in proto3 optional, not in a zero
// sentinel).
func TestProtoToEntry_Gtp4eSrcConfig(t *testing.T) {
	s := newProtoToEntryServer()
	pos := func(v uint32) *uint32 { return &v }

	cases := []struct {
		name    string
		addr    string
		pos     *uint32
		wantErr string // substring; empty = expect success
	}{
		{name: "addr only", addr: "172.16.0.254"},
		{name: "position only", pos: pos(64)},
		{name: "position zero", pos: pos(0)},
		{name: "position max", pos: pos(96)},
		{name: "neither", wantErr: "requires gtp_v4_src_addr or gtp_v4_src_position"},
		{name: "both", addr: "172.16.0.254", pos: pos(64), wantErr: "mutually exclusive"},
		{name: "position out of range", pos: pos(97), wantErr: "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf := &v1.SidFunction{
				Action:           v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E,
				TriggerPrefix:    "fc00:1::/56",
				ArgsOffset:       7,
				GtpV4SrcAddr:     tc.addr,
				GtpV4SrcPosition: tc.pos,
			}
			_, aux, err := s.protoToEntry(sf)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotOff, gotSrc, fromOuter, gotPos := bpf.SidAuxGtp4eData(aux)
			if gotOff != 7 {
				t.Errorf("args_offset: got %d, want 7", gotOff)
			}
			if tc.pos != nil {
				if !fromOuter || uint32(gotPos) != *tc.pos {
					t.Errorf("v4src: got fromOuter=%v pos=%d, want true %d", fromOuter, gotPos, *tc.pos)
				}
			} else {
				if fromOuter {
					t.Errorf("v4src: got fromOuter=true, want false for static addr")
				}
				if got := bpf.FormatIPv4Optional(gotSrc); got != tc.addr {
					t.Errorf("gtp_v4_src_addr: got %q, want %q", got, tc.addr)
				}
			}
		})
	}
}

// TestProtoToEntry_ServiceProgrammingNotImplemented verifies the explicit
// rejection of the service-programming actions while their forward/return
// programs are not registered: accepting them would install a SID whose
// tail-call slot is empty, i.e. a silent no-op.
func TestProtoToEntry_ServiceProgrammingNotImplemented(t *testing.T) {
	s := newProtoToEntryServer()
	for _, action := range []v1.Srv6LocalAction{
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN,
	} {
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:        action,
			TriggerPrefix: "fc00:1::1/128",
		})
		if err == nil {
			t.Errorf("%s: expected not-implemented error, got nil", action)
			continue
		}
		if !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("%s: unexpected error: %v", action, err)
		}
	}
}
