package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// TestHeadendKeyLayout pins the physical layout of the headend keys: Go
// and the ELF agree on the size, the offsets match the C struct, and only
// the four headend maps carry them. Loads the embedded spec only, so it
// needs no privileges.
func TestHeadendKeyLayout(t *testing.T) {
	if got := binary.Size(HeadendV4Key{}); got != 12 {
		t.Errorf("HeadendV4Key is %d bytes, want 12", got)
	}
	if got := binary.Size(HeadendV6Key{}); got != 24 {
		t.Errorf("HeadendV6Key is %d bytes, want 24", got)
	}
	var k4 HeadendV4Key
	var k6 HeadendV6Key
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"v4 prefixlen", unsafe.Offsetof(k4.Prefixlen), 0},
		{"v4 instance", unsafe.Offsetof(k4.Instance), 4},
		{"v4 addr", unsafe.Offsetof(k4.Addr), 8},
		{"v6 prefixlen", unsafe.Offsetof(k6.Prefixlen), 0},
		{"v6 instance", unsafe.Offsetof(k6.Instance), 4},
		{"v6 addr", unsafe.Offsetof(k6.Addr), 8},
	} {
		if f.got != f.want {
			t.Errorf("%s at offset %d, want %d", f.name, f.got, f.want)
		}
	}

	spec, err := LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	entrySize := uint32(binary.Size(HeadendEntry{}))
	for _, m := range []struct {
		name      string
		typ       ebpf.MapType
		key       uint32
		keyType   string
		valueSize uint32
	}{
		{"headend_v4_map", ebpf.LPMTrie, 12, "headend_v4_key", entrySize},
		{"headend_v6_map", ebpf.LPMTrie, 24, "headend_v6_key", entrySize},
		{"headend_v4_owner_map", ebpf.Hash, 12, "headend_v4_key", auxOwnerTagBytes},
		{"headend_v6_owner_map", ebpf.Hash, 24, "headend_v6_key", auxOwnerTagBytes},
		// The SID tables keep the prefix-only IPv6 key.
		{"sid_function_map", ebpf.LPMTrie, 20, "lpm_key_v6", uint32(binary.Size(SidFunctionEntry{}))},
		{"sid_function_owner_map", ebpf.Hash, 20, "lpm_key_v6", auxOwnerTagBytes},
		// The MUP F-TEID tables already carry the VRF.
		{"mup_uplink_v4_map", ebpf.LPMTrie, uint32(binary.Size(MupUplinkV4Key{})), "mup_uplink_v4_key", entrySize},
		{"mup_uplink_v6_map", ebpf.LPMTrie, uint32(binary.Size(MupUplinkV6Key{})), "mup_uplink_v6_key", entrySize},
	} {
		ms, ok := spec.Maps[m.name]
		if !ok {
			t.Errorf("%s missing from the spec", m.name)
			continue
		}
		if ms.Type != m.typ || ms.KeySize != m.key || ms.ValueSize != m.valueSize {
			t.Errorf("%s: type %s key %d value %d, want %s key %d value %d",
				m.name, ms.Type, ms.KeySize, ms.ValueSize, m.typ, m.key, m.valueSize)
		}
		if got := mapValueTypeName(ms.Key); got != m.keyType {
			t.Errorf("%s: BTF key type %q, want %q", m.name, got, m.keyType)
		}
	}
	for _, name := range []string{"headend_v4_map", "headend_v6_map"} {
		if spec.Maps[name].Flags != 1 { // BPF_F_NO_PREALLOC
			t.Errorf("%s flags = %d, want BPF_F_NO_PREALLOC", name, spec.Maps[name].Flags)
		}
	}
}

// rawKey is the little-endian host's byte image of a key, as bpftool
// shows it and the kernel compares it.
func rawKey(t *testing.T, key any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, key); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestBuildHeadendV4Key(t *testing.T) {
	for _, tc := range []struct {
		cidr      string
		vrf       uint32
		prefixlen uint32
		raw       []byte
		prefix    string // the prefix the key reads back as
	}{
		{"10.1.2.0/24", 0, 56, []byte{56, 0, 0, 0, 0, 0, 0, 0, 10, 1, 2, 0}, "10.1.2.0/24"},
		{"10.1.2.0/24", 0x01020304, 56, []byte{56, 0, 0, 0, 1, 2, 3, 4, 10, 1, 2, 0}, "10.1.2.0/24"},
		{"0.0.0.0/0", 0, 32, []byte{32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "0.0.0.0/0"},
		{"128.0.0.0/1", 0, 33, []byte{33, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0}, "128.0.0.0/1"},
		{"192.0.2.7/32", 0, 64, []byte{64, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 7}, "192.0.2.7/32"},
		// Host bits are cleared, and a bare address is a /32.
		{"10.1.2.3/24", 0, 56, []byte{56, 0, 0, 0, 0, 0, 0, 0, 10, 1, 2, 0}, "10.1.2.0/24"},
		{"192.0.2.7", 0, 64, []byte{64, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 7}, "192.0.2.7/32"},
	} {
		key, err := BuildHeadendV4Key(tc.vrf, tc.cidr)
		if err != nil {
			t.Fatalf("%s: %v", tc.cidr, err)
		}
		if key.Prefixlen != tc.prefixlen {
			t.Errorf("%s: prefixlen %d, want %d", tc.cidr, key.Prefixlen, tc.prefixlen)
		}
		if got := rawKey(t, key); !bytes.Equal(got, tc.raw) {
			t.Errorf("%s vrf %#x: raw key % x, want % x", tc.cidr, tc.vrf, got, tc.raw)
		}
		vrf, prefix := headendV4KeyPrefix(key)
		if vrf != tc.vrf || prefix != tc.prefix {
			t.Errorf("%s: reads back as vrf %#x %s, want vrf %#x %s", tc.cidr, vrf, prefix, tc.vrf, tc.prefix)
		}
	}
	for _, bad := range []string{"", "nonsense", "10.0.0.0/33", "fd00::/64", "fd00::1"} {
		if _, err := BuildHeadendV4Key(0, bad); err == nil {
			t.Errorf("%q accepted as an IPv4 trigger prefix", bad)
		}
	}
}

func TestBuildHeadendV6Key(t *testing.T) {
	for _, tc := range []struct {
		cidr      string
		prefixlen uint32
		prefix    string
	}{
		{"::/0", 32, "::/0"},
		{"8000::/1", 33, "8000::/1"},
		{"2001:db8::/64", 96, "2001:db8::/64"},
		{"2001:db8::/127", 159, "2001:db8::/127"},
		{"2001:db8::1/128", 160, "2001:db8::1/128"},
		{"2001:db8::1:2/64", 96, "2001:db8::/64"},
		{"2001:db8::1", 160, "2001:db8::1/128"},
	} {
		for _, vrf := range []uint32{0, 0x01020304} {
			key, err := BuildHeadendV6Key(vrf, tc.cidr)
			if err != nil {
				t.Fatalf("%s: %v", tc.cidr, err)
			}
			if key.Prefixlen != tc.prefixlen {
				t.Errorf("%s: prefixlen %d, want %d", tc.cidr, key.Prefixlen, tc.prefixlen)
			}
			raw := rawKey(t, key)
			if want := binary.BigEndian.AppendUint32(nil, vrf); !bytes.Equal(raw[4:8], want) {
				t.Errorf("%s: instance % x, want % x", tc.cidr, raw[4:8], want)
			}
			_, ipnet, _ := net.ParseCIDR(tc.prefix)
			if !bytes.Equal(raw[8:], ipnet.IP.To16()) {
				t.Errorf("%s: addr % x, want % x", tc.cidr, raw[8:], ipnet.IP.To16())
			}
			gotVRF, prefix := headendV6KeyPrefix(key)
			if gotVRF != vrf || prefix != tc.prefix {
				t.Errorf("%s: reads back as vrf %#x %s, want vrf %#x %s", tc.cidr, gotVRF, prefix, vrf, tc.prefix)
			}
		}
	}

	// The IPv6 headend key accepts exactly what the SID key does, with the
	// same address bytes and a prefix length 32 longer.
	for _, in := range []string{"", "nonsense", "fd00::/129", "10.0.0.0/8", "10.0.0.1", "fd00:1::/48"} {
		lpm, lerr := buildLpmKeyV6(in)
		key, herr := BuildHeadendV6Key(0, in)
		if (lerr == nil) != (herr == nil) {
			t.Errorf("%q: SID key err %v, headend key err %v", in, lerr, herr)
			continue
		}
		if herr == nil && (key.Addr != lpm.Addr || key.Prefixlen != lpm.Prefixlen+32) {
			t.Errorf("%q: headend key %+v does not match SID key %+v", in, key, lpm)
		}
	}
}
