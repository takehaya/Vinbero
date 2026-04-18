package server

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// EncodePluginAux serialises a JSON payload against a plugin's aux struct
// layout described by BTF. The buffer it returns is sized to the struct
// size reported in BTF (zero-padded to match the C layout). Callers must
// verify len(result) <= SidAuxPluginRawMax; structs larger than that are
// rejected at plugin load time by the BTF validator.
//
// Supported BTF types:
//   - Struct: JSON object, field names must match exactly
//   - Typedef: dispatched on typedef name first (well-known vinbero
//     typedefs get string parsers), otherwise unwrapped
//   - Int (signed + unsigned, 1/2/4/8 bytes): JSON number or string
//     ("42", "0x2a"); big endian values are out of scope — BPF is host
//     native
//   - Array: JSON array (length must match Nelems), or hex string when
//     the element type is u8
//
// Unsupported (rejected with an explicit error): Union, Pointer, Enum,
// bitfields, anonymous nested types with no JSON mapping.
//
// Well-known typedefs/structs (see sdk/c/include/vinbero/types.h):
//
//	vinbero_mac_t          "aa:bb:cc:dd:ee:ff"
//	vinbero_ipv4_t         "10.0.0.1"
//	vinbero_ipv6_t         "fc00::1"
//	vinbero_ipv4_prefix_t  "10.0.0.0/24"
//	vinbero_ipv6_prefix_t  "fc00::/48"
func EncodePluginAux(t *btf.Struct, payload map[string]any) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("plugin aux type is nil")
	}
	buf := make([]byte, t.Size)
	if err := encodeStruct(buf, 0, t, payload); err != nil {
		return nil, err
	}
	return buf, nil
}

// encodeStruct writes a JSON object into the struct's byte layout.
// structFieldPath is threaded through for error messages ("src.addr"
// instead of just "addr").
func encodeStruct(buf []byte, base uint32, s *btf.Struct, payload map[string]any) error {
	// Well-known composite types with string shorthand.
	switch s.Name {
	case "vinbero_ipv4_prefix_t", "vinbero_ipv6_prefix_t":
		// Accept either a string ("10.0.0.0/24") injected by the caller
		// or an object with explicit prefix_len / addr fields. The
		// string form reaches us only when the parent dispatched to
		// encodePrefixString; here we handle the object form.
		return encodePrefixStructObject(buf, base, s, payload)
	}

	known := make(map[string]bool, len(s.Members))
	for _, m := range s.Members {
		known[m.Name] = true
	}
	for name := range payload {
		if !known[name] {
			return fmt.Errorf("unknown field %q in struct %q (expected one of: %s)",
				name, s.Name, fieldNameList(s))
		}
	}

	for _, m := range s.Members {
		if m.BitfieldSize != 0 {
			return fmt.Errorf("field %q: bitfields are not supported", m.Name)
		}
		if m.Offset%8 != 0 {
			return fmt.Errorf("field %q: non-byte-aligned offset", m.Name)
		}
		fieldOff := base + uint32(m.Offset/8)
		val, present := payload[m.Name]
		if !present {
			// Leave zero — matches C {0} initialisation.
			continue
		}
		if err := encodeType(buf, fieldOff, m.Type, val); err != nil {
			return fmt.Errorf("field %q: %w", m.Name, err)
		}
	}
	return nil
}

// encodeType dispatches on the BTF type kind.
func encodeType(buf []byte, off uint32, t btf.Type, val any) error {
	// Typedef dispatch: inspect the typedef NAME before unwrapping so that
	// well-known vinbero aliases get the special parsers.
	if td, ok := t.(*btf.Typedef); ok {
		switch td.Name {
		case "vinbero_mac_t":
			return encodeMAC(buf, off, td.Type, val)
		case "vinbero_ipv4_t":
			return encodeIPv4(buf, off, td.Type, val)
		case "vinbero_ipv6_t":
			return encodeIPv6(buf, off, td.Type, val)
		}
		return encodeType(buf, off, td.Type, val)
	}

	if vol, ok := t.(*btf.Volatile); ok {
		return encodeType(buf, off, vol.Type, val)
	}
	if c, ok := t.(*btf.Const); ok {
		return encodeType(buf, off, c.Type, val)
	}

	switch tt := t.(type) {
	case *btf.Int:
		return encodeInt(buf, off, tt, val)
	case *btf.Array:
		return encodeArray(buf, off, tt, val)
	case *btf.Struct:
		// Well-known struct shorthand: a JSON string that the whole
		// struct accepts (prefix types).
		if s, isStr := val.(string); isStr {
			switch tt.Name {
			case "vinbero_ipv4_prefix_t":
				return encodeIPv4PrefixString(buf, off, tt, s)
			case "vinbero_ipv6_prefix_t":
				return encodeIPv6PrefixString(buf, off, tt, s)
			}
			return fmt.Errorf("struct %q does not accept a string; expected an object", tt.Name)
		}
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object for struct %q, got %T", tt.Name, val)
		}
		return encodeStruct(buf, off, tt, obj)
	case *btf.Union:
		return fmt.Errorf("unions are not supported")
	case *btf.Enum:
		return fmt.Errorf("enums are not supported in this MVP encoder")
	case *btf.Pointer:
		return fmt.Errorf("pointers are not supported")
	}
	return fmt.Errorf("unsupported BTF type %T", t)
}

func encodeInt(buf []byte, off uint32, t *btf.Int, val any) error {
	if off+t.Size > uint32(len(buf)) {
		return fmt.Errorf("int write past buffer end")
	}
	u, _, err := toInt64(val)
	if err != nil {
		return err
	}
	dst := buf[off : off+t.Size]
	switch t.Size {
	case 1:
		if t.Encoding == btf.Signed {
			if u < -(1<<7) || u > (1<<7)-1 {
				return fmt.Errorf("value %d does not fit in int8", u)
			}
		} else if u < 0 || u > (1<<8)-1 {
			return fmt.Errorf("value %d does not fit in uint8", u)
		}
		dst[0] = byte(u)
	case 2:
		if t.Encoding == btf.Signed {
			if u < -(1<<15) || u > (1<<15)-1 {
				return fmt.Errorf("value %d does not fit in int16", u)
			}
		} else if u < 0 || u > (1<<16)-1 {
			return fmt.Errorf("value %d does not fit in uint16", u)
		}
		binary.NativeEndian.PutUint16(dst, uint16(u))
	case 4:
		if t.Encoding == btf.Signed {
			if u < -(1<<31) || u > (1<<31)-1 {
				return fmt.Errorf("value %d does not fit in int32", u)
			}
		} else if u < 0 || u > (1<<32)-1 {
			return fmt.Errorf("value %d does not fit in uint32", u)
		}
		binary.NativeEndian.PutUint32(dst, uint32(u))
	case 8:
		binary.NativeEndian.PutUint64(dst, uint64(u))
	default:
		return fmt.Errorf("unsupported int size %d", t.Size)
	}
	return nil
}

func encodeArray(buf []byte, off uint32, a *btf.Array, val any) error {
	// u8 arrays accept a hex string as a shortcut.
	if isU8(a.Type) {
		if s, ok := val.(string); ok {
			return encodeU8ArrayFromString(buf, off, a.Nelems, s)
		}
	}
	arr, ok := val.([]any)
	if !ok {
		return fmt.Errorf("expected array, got %T", val)
	}
	if uint32(len(arr)) != a.Nelems {
		return fmt.Errorf("array length mismatch: got %d, want %d", len(arr), a.Nelems)
	}
	elemSize, err := sizeOf(a.Type)
	if err != nil {
		return err
	}
	for i, elem := range arr {
		if err := encodeType(buf, off+uint32(i)*elemSize, a.Type, elem); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

// encodeU8ArrayFromString accepts either contiguous hex ("aabbccddeeff")
// or colon-separated hex pairs. Odd-length hex is rejected.
func encodeU8ArrayFromString(buf []byte, off, nelems uint32, s string) error {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), "-", "")
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}
	if uint32(len(raw)) != nelems {
		return fmt.Errorf("hex string decodes to %d bytes, want %d", len(raw), nelems)
	}
	copy(buf[off:off+nelems], raw)
	return nil
}

// encodeMAC writes 6 bytes from a MAC string like "aa:bb:cc:dd:ee:ff".
// Falls back to hex for compatibility with the plain-array shortcut.
func encodeMAC(buf []byte, off uint32, underlying btf.Type, val any) error {
	if !isByteArrayOfLen(underlying, 6) {
		return fmt.Errorf("vinbero_mac_t must be [6]u8")
	}
	s, ok := val.(string)
	if !ok {
		// Allow JSON array of 6 integers as a fallback.
		return encodeArray(buf, off, mustArray(underlying), val)
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		// Accept contiguous hex as last resort.
		if err2 := encodeU8ArrayFromString(buf, off, 6, s); err2 == nil {
			return nil
		}
		return fmt.Errorf("invalid MAC %q: %w", s, err)
	}
	if len(hw) != 6 {
		return fmt.Errorf("MAC %q has %d bytes, expected 6", s, len(hw))
	}
	copy(buf[off:off+6], hw)
	return nil
}

func encodeIPv4(buf []byte, off uint32, underlying btf.Type, val any) error {
	if !isByteArrayOfLen(underlying, 4) {
		return fmt.Errorf("vinbero_ipv4_t must be [4]u8")
	}
	s, ok := val.(string)
	if !ok {
		return encodeArray(buf, off, mustArray(underlying), val)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid IPv4 %q", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("not an IPv4 address: %q", s)
	}
	copy(buf[off:off+4], v4)
	return nil
}

func encodeIPv6(buf []byte, off uint32, underlying btf.Type, val any) error {
	if !isByteArrayOfLen(underlying, 16) {
		return fmt.Errorf("vinbero_ipv6_t must be [16]u8")
	}
	s, ok := val.(string)
	if !ok {
		return encodeArray(buf, off, mustArray(underlying), val)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid IPv6 %q", s)
	}
	v6 := ip.To16()
	if v6 == nil {
		return fmt.Errorf("not an IPv6 address: %q", s)
	}
	// Distinguish IPv4-mapped from real IPv6 when the user explicitly
	// wrote an IPv4 literal; those fit in To4() but should not land in
	// a vinbero_ipv6_t field.
	if ip.To4() != nil && !strings.Contains(s, ":") {
		return fmt.Errorf("address %q is IPv4, not IPv6", s)
	}
	copy(buf[off:off+16], v6)
	return nil
}

// encodeIPv4PrefixString / encodeIPv6PrefixString parse a CIDR string
// and scatter it into the prefix struct's fields. The struct is defined
// in sdk/c/include/vinbero/types.h with layout:
//
//	prefix_len u8
//	_pad       u8[N]   // 3 for IPv4, 7 for IPv6
//	addr       [4|16]u8
func encodeIPv4PrefixString(buf []byte, off uint32, s *btf.Struct, cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid IPv4 prefix %q: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return fmt.Errorf("prefix %q is not IPv4", cidr)
	}
	if p.Bits() < 0 || p.Bits() > 32 {
		return fmt.Errorf("prefix length %d out of range for IPv4", p.Bits())
	}
	a4 := p.Addr().As4()
	return writePrefixFields(buf, off, s, uint8(p.Bits()), a4[:])
}

func encodeIPv6PrefixString(buf []byte, off uint32, s *btf.Struct, cidr string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid IPv6 prefix %q: %w", cidr, err)
	}
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return fmt.Errorf("prefix %q is not IPv6", cidr)
	}
	if p.Bits() < 0 || p.Bits() > 128 {
		return fmt.Errorf("prefix length %d out of range for IPv6", p.Bits())
	}
	a16 := p.Addr().As16()
	return writePrefixFields(buf, off, s, uint8(p.Bits()), a16[:])
}

// writePrefixFields writes prefix_len + addr into the struct layout,
// leaving _pad zeroed. It locates fields by name so layout changes in
// types.h stay backward compatible.
func writePrefixFields(buf []byte, base uint32, s *btf.Struct, prefixLen uint8, addr []byte) error {
	var plenOff, addrOff uint32
	var haveLen, haveAddr bool
	for _, m := range s.Members {
		switch m.Name {
		case "prefix_len":
			plenOff = base + uint32(m.Offset/8)
			haveLen = true
		case "addr":
			addrOff = base + uint32(m.Offset/8)
			haveAddr = true
		}
	}
	if !haveLen || !haveAddr {
		return fmt.Errorf("struct %q missing prefix_len or addr member", s.Name)
	}
	buf[plenOff] = prefixLen
	copy(buf[addrOff:addrOff+uint32(len(addr))], addr)
	return nil
}

// encodePrefixStructObject handles the object form {"prefix_len": ..,
// "addr": "1.2.3.4"} for users that opt out of the string shorthand.
// It reuses the generic struct walker by re-dispatching each field.
func encodePrefixStructObject(buf []byte, base uint32, s *btf.Struct, payload map[string]any) error {
	// Only prefix_len and addr are accepted.
	for k := range payload {
		if k != "prefix_len" && k != "addr" {
			return fmt.Errorf("unknown field %q in %s", k, s.Name)
		}
	}
	for _, m := range s.Members {
		if m.Name != "prefix_len" && m.Name != "addr" {
			continue
		}
		val, ok := payload[m.Name]
		if !ok {
			continue
		}
		if err := encodeType(buf, base+uint32(m.Offset/8), m.Type, val); err != nil {
			return fmt.Errorf("field %q: %w", m.Name, err)
		}
	}
	return nil
}

// ---- helpers ---------------------------------------------------------

// isU8 reports whether t is an unsigned 1-byte integer.
func isU8(t btf.Type) bool {
	if td, ok := t.(*btf.Typedef); ok {
		t = td.Type
	}
	i, ok := t.(*btf.Int)
	return ok && i.Size == 1 && i.Encoding != btf.Signed
}

func isByteArrayOfLen(t btf.Type, n uint32) bool {
	a, ok := t.(*btf.Array)
	if !ok {
		return false
	}
	return a.Nelems == n && isU8(a.Type)
}

func mustArray(t btf.Type) *btf.Array {
	if a, ok := t.(*btf.Array); ok {
		return a
	}
	return nil
}

func sizeOf(t btf.Type) (uint32, error) {
	switch tt := t.(type) {
	case *btf.Int:
		return tt.Size, nil
	case *btf.Struct:
		return tt.Size, nil
	case *btf.Array:
		es, err := sizeOf(tt.Type)
		if err != nil {
			return 0, err
		}
		return es * tt.Nelems, nil
	case *btf.Typedef:
		return sizeOf(tt.Type)
	case *btf.Volatile:
		return sizeOf(tt.Type)
	case *btf.Const:
		return sizeOf(tt.Type)
	}
	return 0, fmt.Errorf("cannot compute size of %T", t)
}

// toInt64 accepts JSON numbers (float64 after decoding) and numeric
// strings ("42", "0x2a", "-1"). Returns value + whether the source was
// negative so callers can bounds-check signed vs unsigned.
func toInt64(val any) (int64, bool, error) {
	switch v := val.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, i < 0, nil
		}
		// Int64 failed: either the value is fractional or it overflows
		// int64. Accept only values that fit an int64 and are whole.
		f, err := v.Float64()
		if err != nil {
			return 0, false, fmt.Errorf("invalid number %q: %w", v, err)
		}
		if f != float64(int64(f)) {
			return 0, false, fmt.Errorf("expected integer, got fractional %v", v)
		}
		return int64(f), f < 0, nil
	case float64:
		if v != float64(int64(v)) {
			return 0, false, fmt.Errorf("expected integer, got fractional %v", v)
		}
		return int64(v), v < 0, nil
	case int:
		return int64(v), v < 0, nil
	case int64:
		return v, v < 0, nil
	case string:
		s := strings.TrimSpace(v)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			u, err := strconv.ParseUint(s[2:], 16, 64)
			if err != nil {
				return 0, false, fmt.Errorf("invalid hex integer %q: %w", v, err)
			}
			return int64(u), false, nil
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err == nil {
			return i, i < 0, nil
		}
		// Accept unsigned 64-bit values that overflow int64.
		u, err2 := strconv.ParseUint(s, 10, 64)
		if err2 == nil {
			return int64(u), false, nil
		}
		return 0, false, fmt.Errorf("invalid integer %q", v)
	}
	return 0, false, fmt.Errorf("expected number or numeric string, got %T", val)
}

func fieldNameList(s *btf.Struct) string {
	names := make([]string, 0, len(s.Members))
	for _, m := range s.Members {
		names = append(names, m.Name)
	}
	return strings.Join(names, ", ")
}
