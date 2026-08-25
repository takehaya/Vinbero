package server

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// newProtoToEntryServer builds a SidFunctionServer with nil deps. protoToEntry
// only reads s.pluginAux on the plugin_aux_json branch, and never touches
// s.mapOps; tests that exercise raw / index / range-check paths can therefore
// share this minimal server without spinning up real BPF maps.
func newProtoToEntryServer() *SidFunctionServer {
	return NewSidFunctionServer(nil, nil, nil, nil)
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

// TestProtoToEntry_EndASValidation covers the proxy forward-direction
// validation and the aux layout round trip for END_AS.
func TestProtoToEntry_EndASValidation(t *testing.T) {
	s := newProtoToEntryServer()
	ifaceIn := uint32(42)
	base := func() *v1.SidFunction {
		in := ifaceIn
		return &v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
			TriggerPrefix: "fc00:2::100/128",
			Oif:           7,
			IfaceIn:       &in,
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
		}
	}

	t.Run("valid FIB mode", func(t *testing.T) {
		entry, aux, err := s.protoToEntry(base())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry.Action != uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS) {
			t.Fatalf("action = %d", entry.Action)
		}
		svc := bpf.SidAuxServiceData(aux)
		if svc.IfaceOut != 7 || svc.IfaceIn != 42 || svc.InnerType != bpf.SvcInnerIPv4 || svc.Flags != 0 {
			t.Fatalf("aux round trip mismatch: %+v", svc)
		}
	})

	t.Run("missing oif", func(t *testing.T) {
		sf := base()
		sf.Oif = 0
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for missing oif")
		}
	})

	t.Run("missing iface_in", func(t *testing.T) {
		sf := base()
		sf.IfaceIn = nil
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for missing iface_in")
		}
	})

	t.Run("missing inner_type", func(t *testing.T) {
		sf := base()
		sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_UNSPECIFIED
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for missing inner_type")
		}
	})

	t.Run("service_mac on Ethernet inner", func(t *testing.T) {
		sf := base()
		sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_ETHERNET
		mac := "02:00:00:00:00:01"
		sf.ServiceMac = &mac
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for service_mac with Ethernet inner")
		}
	})

	t.Run("invalid service_mac", func(t *testing.T) {
		sf := base()
		mac := "not-a-mac"
		sf.ServiceMac = &mac
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for invalid service_mac")
		}
	})
}

// TestBuildServiceIngress_EndAS covers the static CACHE validation.
func TestBuildServiceIngress_EndAS(t *testing.T) {
	s := newProtoToEntryServer()
	ifaceIn := uint32(42)
	base := func() *v1.SidFunction {
		in := ifaceIn
		return &v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
			TriggerPrefix: "fc00:2::100/128",
			Oif:           7,
			IfaceIn:       &in,
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
			SrcAddr:       "fc00:2::1",
			Segments:      []string{"fc00:3::3", "fc00:4::4"},
		}
	}

	t.Run("valid", func(t *testing.T) {
		ing, err := s.buildServiceIngress(base())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ing.Behavior != bpf.SvcRetAS || ing.InnerTypeMask != bpf.SvcInnerIPv4 {
			t.Fatalf("unexpected entry: %+v", ing)
		}
		if ing.Encap.NumSegments != 2 {
			t.Fatalf("num segments = %d", ing.Encap.NumSegments)
		}
		if ing.Sid[0] != 0xfc {
			t.Fatalf("owning sid not captured: % x", ing.Sid)
		}
	})

	t.Run("missing segments", func(t *testing.T) {
		sf := base()
		sf.Segments = nil
		if _, err := s.buildServiceIngress(sf); err == nil {
			t.Fatal("expected error for missing segments")
		}
	})

	t.Run("missing src_addr", func(t *testing.T) {
		sf := base()
		sf.SrcAddr = ""
		if _, err := s.buildServiceIngress(sf); err == nil {
			t.Fatal("expected error for missing src_addr")
		}
	})

	t.Run("non-/128 trigger prefix", func(t *testing.T) {
		sf := base()
		sf.TriggerPrefix = "fc00:2::/64"
		if _, err := s.buildServiceIngress(sf); err == nil {
			t.Fatal("expected error for non-/128 prefix")
		}
	})
}

// TestBuildServiceIngress_EndAD covers the dynamic-proxy variant: no
// static CACHE is accepted, and the binding carries the AD behavior.
func TestBuildServiceIngress_EndAD(t *testing.T) {
	s := newProtoToEntryServer()
	ifaceIn := uint32(42)
	base := func() *v1.SidFunction {
		in := ifaceIn
		return &v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
			TriggerPrefix: "fc00:2::200/128",
			Oif:           7,
			IfaceIn:       &in,
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
		}
	}

	t.Run("valid", func(t *testing.T) {
		ing, err := s.buildServiceIngress(base())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ing.Behavior != bpf.SvcRetAD {
			t.Fatalf("behavior = %d, want SvcRetAD", ing.Behavior)
		}
		if ing.Encap.NumSegments != 0 {
			t.Fatalf("dynamic proxy must not embed a static CACHE: %+v", ing.Encap)
		}
	})

	t.Run("static CACHE rejected", func(t *testing.T) {
		sf := base()
		sf.Segments = []string{"fc00:3::3"}
		if _, err := s.buildServiceIngress(sf); err == nil {
			t.Fatal("expected error for segments on END_AD")
		}
	})

	t.Run("hop_limit_margin round trip", func(t *testing.T) {
		sf := base()
		margin := uint32(4)
		sf.HopLimitMargin = &margin
		_, aux, err := s.protoToEntry(sf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := bpf.SidAuxServiceData(aux).HopLimitMargin; got != 4 {
			t.Fatalf("hop_limit_margin = %d, want 4", got)
		}
	})

	t.Run("hop_limit_margin out of range", func(t *testing.T) {
		sf := base()
		margin := uint32(300)
		sf.HopLimitMargin = &margin
		if _, _, err := s.protoToEntry(sf); err == nil {
			t.Fatal("expected error for margin > 255")
		}
	})
}

// TestProtoToEntry_EndAMValidation covers the masquerading-proxy rules:
// static MAC delivery is mandatory and the circuit carries the SR packet
// itself (inner_type IPV6).
func TestProtoToEntry_EndAMValidation(t *testing.T) {
	s := newProtoToEntryServer()
	ifaceIn := uint32(42)
	mac := "02:00:00:00:00:01"
	base := func() *v1.SidFunction {
		in := ifaceIn
		m := mac
		return &v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM,
			TriggerPrefix: "fc00:2::150/128",
			Oif:           1, // lo: has no MAC, so swap in a MAC-bearing oif when needed
			IfaceIn:       &in,
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV6,
			ServiceMac:    &m,
		}
	}

	t.Run("service_mac required", func(t *testing.T) {
		sf := base()
		sf.ServiceMac = nil
		_, _, err := s.protoToEntry(sf)
		if err == nil || !strings.Contains(err.Error(), "requires service_mac") {
			t.Fatalf("expected the service_mac validation error, got %v", err)
		}
	})

	t.Run("inner_type must be IPV6", func(t *testing.T) {
		sf := base()
		sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4
		_, _, err := s.protoToEntry(sf)
		if err == nil || !strings.Contains(err.Error(), "requires inner_type IPV6") {
			t.Fatalf("expected the inner_type validation error, got %v", err)
		}
	})

	t.Run("static CACHE rejected", func(t *testing.T) {
		sf := base()
		sf.Segments = []string{"fc00:3::3"}
		if _, err := s.buildServiceIngress(sf); err == nil {
			t.Fatal("expected error for segments on END_AM")
		}
	})

	t.Run("ingress binding carries AM behavior", func(t *testing.T) {
		ing, err := s.buildServiceIngress(base())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ing.Behavior != bpf.SvcRetAM || ing.InnerTypeMask != bpf.SvcInnerIPv6 {
			t.Fatalf("unexpected binding: %+v", ing)
		}
	})
}

// TestProtoToEntry_EndAN covers the SR-aware native behavior: plain End
// processing with optional NF-catalog metadata in the aux.
func TestProtoToEntry_EndAN(t *testing.T) {
	s := newProtoToEntryServer()

	t.Run("name round trip", func(t *testing.T) {
		name := "demo-fw"
		entry, aux, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN,
			TriggerPrefix: "fc00:a1::1/128",
			ServiceName:   &name,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry.Action != uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN) {
			t.Fatalf("action = %d", entry.Action)
		}
		if got := bpf.SidAuxServiceNameData(aux); got != "demo-fw" {
			t.Fatalf("service_name round trip: %q", got)
		}
	})

	t.Run("no metadata means no aux", func(t *testing.T) {
		_, aux, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN,
			TriggerPrefix: "fc00:a1::2/128",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if aux != nil {
			t.Fatalf("expected no aux without metadata, got %+v", aux)
		}
	})

	t.Run("non-ASCII and NUL rejected", func(t *testing.T) {
		for _, bad := range []string{"demo\x00fw", "デモfw", "demo\tfw"} {
			name := bad
			_, _, err := s.protoToEntry(&v1.SidFunction{
				Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN,
				TriggerPrefix: "fc00:a1::4/128",
				ServiceName:   &name,
			})
			if err == nil || !strings.Contains(err.Error(), "printable ASCII") {
				t.Fatalf("%q: expected the printable-ASCII error, got %v", bad, err)
			}
		}
	})

	t.Run("name too long", func(t *testing.T) {
		name := strings.Repeat("x", 64)
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN,
			TriggerPrefix: "fc00:a1::3/128",
			ServiceName:   &name,
		})
		if err == nil || !strings.Contains(err.Error(), "service_name") {
			t.Fatalf("expected the service_name length error, got %v", err)
		}
	})
}

// TestProtoToEntry_ProxyFieldScope covers validateProxyFieldScope: a
// behavior-specific field set on the wrong action must be rejected, not
// silently accepted and dropped (the protoToEntry/entryToProto asymmetry
// the project forbids).
func TestProtoToEntry_ProxyFieldScope(t *testing.T) {
	s := newProtoToEntryServer()

	t.Run("hop_limit_margin on non-AD rejected", func(t *testing.T) {
		margin := uint32(4)
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:         v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4,
			TriggerPrefix:  "fc00:1::1/128",
			HopLimitMargin: &margin,
		})
		if err == nil || !strings.Contains(err.Error(), "hop_limit_margin applies to END_AD only") {
			t.Fatalf("expected the hop_limit_margin scope error, got %v", err)
		}
	})

	t.Run("service_name on non-AN rejected", func(t *testing.T) {
		name := "demo"
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END,
			TriggerPrefix: "fc00:1::1/128",
			ServiceName:   &name,
		})
		if err == nil || !strings.Contains(err.Error(), "service_name applies to END_AN only") {
			t.Fatalf("expected the service_name scope error, got %v", err)
		}
	})

	t.Run("inner_type on non-proxy rejected", func(t *testing.T) {
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4,
			TriggerPrefix: "fc00:1::1/128",
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
		})
		if err == nil || !strings.Contains(err.Error(), "inner_type applies to the proxy actions") {
			t.Fatalf("expected the inner_type scope error, got %v", err)
		}
	})

	t.Run("inner_type on a proxy action is allowed", func(t *testing.T) {
		in := uint32(1)
		_, _, err := s.protoToEntry(&v1.SidFunction{
			Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
			TriggerPrefix: "fc00:2::1/128",
			Oif:           1,
			IfaceIn:       &in,
			InnerType:     v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4,
		})
		if err != nil {
			t.Fatalf("unexpected error for a valid END_AD: %v", err)
		}
	})
}

// TestProtoToEntry_USID verifies the uN/uA API contract: prefix shapes,
// nexthop requirements, block length bounds, and field scoping.
func TestProtoToEntry_USID(t *testing.T) {
	s := newProtoToEntryServer()
	u32 := func(v uint32) *uint32 { return &v }

	tests := []struct {
		name    string
		sf      *v1.SidFunction
		wantErr string // empty = success
	}{
		{"uN /48 default block", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:b002::/48"}, ""},
		{"uN explicit block 32", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:b002::/48", UsidBlockLen: u32(32)}, ""},
		{"uN non-32 block rejected", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:b002::/48", UsidBlockLen: u32(48)}, "not supported"},
		{"uN wrong prefix width", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:b002::/64"}, "must be /48"},
		{"uN rejects nexthop", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:b002::/48", Nexthop: "fe80::1"}, "does not take a nexthop"},
		{"uA /64 with nexthop", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002:c001::/64", Nexthop: "fe80::1"}, ""},
		{"uA wrong prefix width", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002::/48", Nexthop: "fe80::1"}, "must be /64"},
		{"uA missing nexthop", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002:c001::/64"}, "requires an IPv6 nexthop"},
		{"uN rejects zero node CSID", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, TriggerPrefix: "fd00:aaaa:0000::/48"}, "node CSID must be non-zero"},
		{"uA rejects zero node CSID", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:0000:c001::/64", Nexthop: "fe80::1"}, "node CSID must be non-zero"},
		{"uA rejects zero function CSID", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002::/64", Nexthop: "fe80::1"}, "function CSID must be non-zero"},
		{"uA rejects unspecified nexthop", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002:c001::/64", Nexthop: "::"}, "requires an IPv6 nexthop"},
		{"uA rejects IPv4 nexthop", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, TriggerPrefix: "fd00:aaaa:b002:c001::/64", Nexthop: "192.0.2.1"}, "requires an IPv6 nexthop"},
		{"usid_block_len on wrong action", &v1.SidFunction{
			Action: v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END, TriggerPrefix: "fd00:1::1/128", UsidBlockLen: u32(32)}, "only valid for END_UN / END_UA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, aux, err := s.protoToEntry(tt.sf)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if entry.Action != uint8(tt.sf.Action) {
				t.Errorf("action = %d, want %d", entry.Action, tt.sf.Action)
			}
			if aux == nil {
				t.Fatalf("uN/uA must carry a usid aux entry")
			}
			nexthop, blockLenBytes := bpf.SidAuxUsidData(aux)
			if blockLenBytes != 4 {
				t.Errorf("block_len_bytes = %d, want 4", blockLenBytes)
			}
			// The data plane forwards uA over this address; nothing else in
			// the test suite observes it, so assert the round trip here.
			want := netip.IPv6Unspecified()
			if tt.sf.Nexthop != "" {
				want = netip.MustParseAddr(tt.sf.Nexthop)
			}
			if got := netip.AddrFrom16(nexthop); got != want {
				t.Errorf("aux nexthop = %v, want %v", got, want)
			}
		})
	}
}

// usidLocator builds an F3216 uSID locator for the claim tests.
func usidLocator(t *testing.T, name, prefix string) *locator.Manager {
	t.Helper()
	mgr := locator.NewManager()
	loc := &locator.Locator{
		Name:              name,
		Prefix:            netip.MustParsePrefix(prefix),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		Behavior:          locator.BehaviorUSID,
		FunctionAutoStart: 1,
		FunctionAutoEnd:   0xffff,
	}
	if err := mgr.Add(loc); err != nil {
		t.Fatalf("locator Add: %v", err)
	}
	return mgr
}

func uaSidFunction(prefix string) *v1.SidFunction {
	return &v1.SidFunction{
		Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA,
		TriggerPrefix: prefix,
		Nexthop:       "fe80::1",
	}
}

// A uA consumes a function CSID out of its locator. Without the claim the
// allocator would hand the same CSID to a service SID, whose /128 wins the
// LPM match over the uA /64 and silently replaces the uA's terminal
// behavior.
func TestClaimUsidFunction_BlocksServiceSIDCollision(t *testing.T) {
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(nil, nil, mgr, nil)

	release, err := s.claimUsidFunction(uaSidFunction("fd00:aaaa:b002:c001::/64"))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	fn := uint32(0xc001)
	if _, _, err := mgr.AllocateSID("loc1", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
		t.Fatalf("service SID allocation of the claimed CSID: err = %v, want ErrFunctionInUse", err)
	}

	// The rollback path returns it, and a neighbouring CSID was never taken.
	release()
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestClaimUsidFunction_RejectsCSIDTakenByServiceSID(t *testing.T) {
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(nil, nil, mgr, nil)

	fn := uint32(0xc001)
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("service SID allocation: %v", err)
	}
	if _, err := s.claimUsidFunction(uaSidFunction("fd00:aaaa:b002:c001::/64")); err == nil {
		t.Fatal("uA registration on a CSID already held by a service SID must fail")
	}
}

// SidFunctionCreate is an upsert, so re-creating the same uA must not
// collide with its own claim. Needs the real map: the re-create is told
// apart from a foreign SID by the entry already sitting at that prefix.
func TestSidFunctionCreate_UAReclaimIsIdempotent(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(bpf.NewMapOperations(objs), nil, mgr, nil)

	const prefix = "fd00:aaaa:b002:c001::/64"
	if err := s.createOneSidFunction(uaSidFunction(prefix)); err != nil {
		t.Fatalf("first create: %v", err)
	}
	t.Cleanup(func() { _ = s.deleteOneSidFunction(prefix) })
	if err := s.createOneSidFunction(uaSidFunction(prefix)); err != nil {
		t.Fatalf("re-create: %v", err)
	}

	// The claim survives the re-create, and delete gives it back.
	fn := uint32(0xc001)
	if _, _, err := mgr.AllocateSID("loc1", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
		t.Fatalf("CSID after re-create: err = %v, want ErrFunctionInUse", err)
	}
	if err := s.deleteOneSidFunction(prefix); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("CSID was not released on delete: %v", err)
	}
}

// uN carries no function, and a uA outside every uSID locator has no
// allocator to collide with. Both are silent no-ops.
func TestClaimUsidFunction_NoOpCases(t *testing.T) {
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(nil, nil, mgr, nil)

	un := &v1.SidFunction{
		Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN,
		TriggerPrefix: "fd00:aaaa:b002::/48",
	}
	if _, err := s.claimUsidFunction(un); err != nil {
		t.Fatalf("uN claim: %v", err)
	}
	if _, err := s.claimUsidFunction(uaSidFunction("fd00:bbbb:b002:c001::/64")); err != nil {
		t.Fatalf("uA outside any locator: %v", err)
	}
	// Neither took a function out of loc1.
	fn := uint32(0xc001)
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("loc1 pool was touched: %v", err)
	}
}

// Deleting some other entry that happens to sit on the same base address as
// a locator-minted service SID must not hand that SID's function back to the
// allocator: the SID is still live, and the CSID would be reissued.
func TestDeleteSidFunction_KeepsForeignLocatorClaim(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(bpf.NewMapOperations(objs), nil, mgr, nil)

	// A service SID claims CSID 0xc001 through the locator.
	fn := uint32(0xc001)
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("service SID allocation: %v", err)
	}

	// An unrelated non-uA entry whose /64 masks to the same address.
	const prefix = "fd00:aaaa:b002:c001::/64"
	other := &v1.SidFunction{
		Action:        v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END,
		TriggerPrefix: prefix,
	}
	if err := s.createOneSidFunction(other); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.deleteOneSidFunction(prefix); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, _, err := mgr.AllocateSID("loc1", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
		t.Fatalf("the service SID's CSID was released by an unrelated delete: err = %v, want ErrFunctionInUse", err)
	}
}
