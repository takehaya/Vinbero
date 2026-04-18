package server

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// parseJSON decodes s as JSON into a map, using json.Number so integer
// values survive without float64 rounding.
func parseJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("parse JSON %q: %v", s, err)
	}
	return out
}

func u8Type() *btf.Int  { return &btf.Int{Size: 1, Encoding: btf.Unsigned} }
func u32Type() *btf.Int { return &btf.Int{Size: 4, Encoding: btf.Unsigned} }
func u64Type() *btf.Int { return &btf.Int{Size: 8, Encoding: btf.Unsigned} }
func s32Type() *btf.Int { return &btf.Int{Size: 4, Encoding: btf.Signed} }

func TestEncode_Primitives_U32_U64(t *testing.T) {
	s := &btf.Struct{
		Name: "p_aux",
		Size: 12,
		Members: []btf.Member{
			{Name: "a", Type: u32Type(), Offset: 0},
			{Name: "b", Type: u64Type(), Offset: 32},
		},
	}
	cases := []struct {
		name string
		js   string
		a    uint32
		b    uint64
	}{
		{"decimal", `{"a": 42, "b": 1000000}`, 42, 1000000},
		{"hex_string", `{"a": "0xff", "b": "0x1234"}`, 0xff, 0x1234},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf, err := EncodePluginAux(s, parseJSON(t, c.js))
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got := binary.NativeEndian.Uint32(buf[0:4]); got != c.a {
				t.Errorf("a: got %d, want %d", got, c.a)
			}
			if got := binary.NativeEndian.Uint64(buf[4:12]); got != c.b {
				t.Errorf("b: got %d, want %d", got, c.b)
			}
		})
	}
}

func TestEncode_SignedInt(t *testing.T) {
	s := &btf.Struct{
		Name:    "s_aux",
		Size:    4,
		Members: []btf.Member{{Name: "x", Type: s32Type(), Offset: 0}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"x": -5}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := int32(binary.NativeEndian.Uint32(buf[0:4])); got != -5 {
		t.Errorf("signed: got %d, want -5", got)
	}
}

func TestEncode_Array_U8_HexShortcut(t *testing.T) {
	s := &btf.Struct{
		Name: "a_aux",
		Size: 6,
		Members: []btf.Member{{
			Name:   "mac",
			Type:   &btf.Array{Type: u8Type(), Nelems: 6},
			Offset: 0,
		}},
	}
	cases := []string{`{"mac":"aabbccddeeff"}`, `{"mac":"AA:BB:CC:DD:EE:FF"}`}
	for _, js := range cases {
		buf, err := EncodePluginAux(s, parseJSON(t, js))
		if err != nil {
			t.Fatalf("%s: %v", js, err)
		}
		want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		for i, b := range want {
			if buf[i] != b {
				t.Errorf("%s: byte %d got 0x%x want 0x%x", js, i, buf[i], b)
			}
		}
	}
}

func TestEncode_Array_U8_JsonArray(t *testing.T) {
	s := &btf.Struct{
		Name: "a_aux",
		Size: 4,
		Members: []btf.Member{{
			Name:   "v",
			Type:   &btf.Array{Type: u8Type(), Nelems: 4},
			Offset: 0,
		}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"v":[1,2,3,4]}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i, want := range []byte{1, 2, 3, 4} {
		if buf[i] != want {
			t.Errorf("byte %d: got %d want %d", i, buf[i], want)
		}
	}
}

func TestEncode_Array_U32(t *testing.T) {
	s := &btf.Struct{
		Name: "a_aux",
		Size: 16,
		Members: []btf.Member{{
			Name:   "v",
			Type:   &btf.Array{Type: u32Type(), Nelems: 4},
			Offset: 0,
		}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"v":[10, 20, 30, 40]}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i, want := range []uint32{10, 20, 30, 40} {
		if got := binary.NativeEndian.Uint32(buf[i*4 : (i+1)*4]); got != want {
			t.Errorf("elem %d: got %d want %d", i, got, want)
		}
	}
}

func TestEncode_NestedStruct(t *testing.T) {
	inner := &btf.Struct{
		Name:    "inner_t",
		Size:    4,
		Members: []btf.Member{{Name: "x", Type: u32Type(), Offset: 0}},
	}
	outer := &btf.Struct{
		Name: "outer_aux",
		Size: 8,
		Members: []btf.Member{
			{Name: "head", Type: u32Type(), Offset: 0},
			{Name: "in", Type: inner, Offset: 32},
		},
	}
	buf, err := EncodePluginAux(outer, parseJSON(t, `{"head": 1, "in": {"x": 99}}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if binary.NativeEndian.Uint32(buf[0:4]) != 1 {
		t.Errorf("head mismatch")
	}
	if binary.NativeEndian.Uint32(buf[4:8]) != 99 {
		t.Errorf("inner.x mismatch")
	}
}

func TestEncode_Typedef_Unwrap_Plain(t *testing.T) {
	alias := &btf.Typedef{Name: "my_id_t", Type: u32Type()}
	s := &btf.Struct{
		Name:    "t_aux",
		Size:    4,
		Members: []btf.Member{{Name: "id", Type: alias, Offset: 0}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"id": 7}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if binary.NativeEndian.Uint32(buf[0:4]) != 7 {
		t.Errorf("id mismatch")
	}
}

func TestEncode_UnknownField_Rejected(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    4,
		Members: []btf.Member{{Name: "a", Type: u32Type(), Offset: 0}},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"typo": 1}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestEncode_TypeMismatch_Rejected(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    4,
		Members: []btf.Member{{Name: "a", Type: u32Type(), Offset: 0}},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"a": "not-a-number"}`))
	if err == nil {
		t.Fatal("expected type-mismatch error")
	}
}

func TestEncode_SizeOverflow_OverflowsInt8(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    1,
		Members: []btf.Member{{Name: "a", Type: u8Type(), Offset: 0}},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"a": 300}`))
	if err == nil {
		t.Fatal("expected overflow error")
	}
}

// ---- special formats -------------------------------------------------

func macTypedef() *btf.Typedef {
	return &btf.Typedef{
		Name: "vinbero_mac_t",
		Type: &btf.Array{Type: u8Type(), Nelems: 6},
	}
}
func ipv4Typedef() *btf.Typedef {
	return &btf.Typedef{
		Name: "vinbero_ipv4_t",
		Type: &btf.Array{Type: u8Type(), Nelems: 4},
	}
}
func ipv6Typedef() *btf.Typedef {
	return &btf.Typedef{
		Name: "vinbero_ipv6_t",
		Type: &btf.Array{Type: u8Type(), Nelems: 16},
	}
}
func ipv4PrefixStruct() *btf.Struct {
	return &btf.Struct{
		Name: "vinbero_ipv4_prefix_t",
		Size: 8,
		Members: []btf.Member{
			{Name: "prefix_len", Type: u8Type(), Offset: 0},
			{Name: "_pad", Type: &btf.Array{Type: u8Type(), Nelems: 3}, Offset: 8},
			{Name: "addr", Type: ipv4Typedef(), Offset: 32},
		},
	}
}
func ipv6PrefixStruct() *btf.Struct {
	return &btf.Struct{
		Name: "vinbero_ipv6_prefix_t",
		Size: 24,
		Members: []btf.Member{
			{Name: "prefix_len", Type: u8Type(), Offset: 0},
			{Name: "_pad", Type: &btf.Array{Type: u8Type(), Nelems: 7}, Offset: 8},
			{Name: "addr", Type: ipv6Typedef(), Offset: 64},
		},
	}
}

func TestEncode_MacTypedef(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    6,
		Members: []btf.Member{{Name: "mac", Type: macTypedef(), Offset: 0}},
	}
	cases := []string{
		`{"mac":"aa:bb:cc:dd:ee:ff"}`,
		`{"mac":"AA-BB-CC-DD-EE-FF"}`,
		`{"mac":"aabbccddeeff"}`,
	}
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, js := range cases {
		buf, err := EncodePluginAux(s, parseJSON(t, js))
		if err != nil {
			t.Fatalf("%s: %v", js, err)
		}
		for i, b := range want {
			if buf[i] != b {
				t.Errorf("%s: byte %d got 0x%x want 0x%x", js, i, buf[i], b)
			}
		}
	}
}

func TestEncode_IPv4Typedef(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    4,
		Members: []btf.Member{{Name: "src", Type: ipv4Typedef(), Offset: 0}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"src":"10.0.0.1"}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{10, 0, 0, 1}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("byte %d got %d want %d", i, buf[i], b)
		}
	}
}

func TestEncode_IPv6Typedef(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    16,
		Members: []btf.Member{{Name: "addr", Type: ipv6Typedef(), Offset: 0}},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"addr":"fc00::1"}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("byte %d got 0x%x want 0x%x", i, buf[i], b)
		}
	}
}

func TestEncode_IPv4PrefixStruct(t *testing.T) {
	// Wrap the prefix struct in a single-field outer aux.
	s := &btf.Struct{
		Name: "aux",
		Size: 8,
		Members: []btf.Member{
			{Name: "net", Type: ipv4PrefixStruct(), Offset: 0},
		},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"net":"10.0.0.0/24"}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if buf[0] != 24 {
		t.Errorf("prefix_len: got %d want 24", buf[0])
	}
	// addr is at offset 4 within the prefix struct.
	want := []byte{10, 0, 0, 0}
	for i, b := range want {
		if buf[4+i] != b {
			t.Errorf("addr byte %d: got %d want %d", i, buf[4+i], b)
		}
	}
}

func TestEncode_IPv6PrefixStruct(t *testing.T) {
	s := &btf.Struct{
		Name: "aux",
		Size: 24,
		Members: []btf.Member{
			{Name: "net", Type: ipv6PrefixStruct(), Offset: 0},
		},
	}
	buf, err := EncodePluginAux(s, parseJSON(t, `{"net":"fc00::/48"}`))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if buf[0] != 48 {
		t.Errorf("prefix_len: got %d want 48", buf[0])
	}
	if buf[8] != 0xfc || buf[9] != 0x00 {
		t.Errorf("addr high bytes: got %02x%02x, want fc00", buf[8], buf[9])
	}
}

func TestEncode_InvalidMac(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    6,
		Members: []btf.Member{{Name: "mac", Type: macTypedef(), Offset: 0}},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"mac":"not-a-mac"}`))
	if err == nil {
		t.Fatal("expected invalid-MAC error")
	}
}

func TestEncode_InvalidIPv4(t *testing.T) {
	s := &btf.Struct{
		Name:    "aux",
		Size:    4,
		Members: []btf.Member{{Name: "addr", Type: ipv4Typedef(), Offset: 0}},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"addr":"300.0.0.1"}`))
	if err == nil {
		t.Fatal("expected invalid-IPv4 error")
	}
}

func TestEncode_PrefixInvalid(t *testing.T) {
	s := &btf.Struct{
		Name: "aux",
		Size: 8,
		Members: []btf.Member{
			{Name: "net", Type: ipv4PrefixStruct(), Offset: 0},
		},
	}
	_, err := EncodePluginAux(s, parseJSON(t, `{"net":"10.0.0.0/40"}`))
	if err == nil {
		t.Fatal("expected prefix-length error")
	}
}
