package bpf

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// headendKeyFamily drives TestXDPProgHeadendKeyVRF for one address family:
// the MapOperations writers (which use vrf_id 0), a raw writer that can
// put an entry into any VRF, and packets toward a chosen destination.
type headendKeyFamily struct {
	name                        string
	cover, longer, other, deflt string // trigger prefixes
	toCover, toLonger, toOther  string // destinations
	create                      func(string, *HeadendEntry, OwnerTag) error
	remove                      func(string, OwnerTag) error
	list                        func() (map[string]*HeadendEntry, error)
	owners                      func() (map[string]OwnerTag, error)
	getOwner                    func(string) (OwnerTag, bool, error)
	putRaw                      func(t *testing.T, vrf uint32, prefix string, e *HeadendEntry)
	putRawOwner                 func(t *testing.T, vrf uint32, prefix string, owner OwnerTag)
	rawPrefixlen                func(t *testing.T, vrf uint32, prefix string) uint32
	rawCount                    func(t *testing.T) int
	packet                      func(t *testing.T, dst string) []byte
}

func headendKeyFamilies(h *xdpTestHelper) []headendKeyFamily {
	m := h.mapOps
	return []headendKeyFamily{
		{
			name:  "v4",
			cover: "10.1.0.0/16", longer: "10.1.2.0/24", other: "198.51.100.0/24", deflt: "0.0.0.0/0",
			toCover: "10.1.9.9", toLonger: "10.1.2.3", toOther: "198.51.100.1",
			create: m.CreateHeadendV4, remove: m.DeleteHeadendV4, list: m.ListHeadendV4,
			owners: m.ListHeadendV4Owners, getOwner: m.GetHeadendV4Owner,
			putRaw: func(t *testing.T, vrf uint32, prefix string, e *HeadendEntry) {
				t.Helper()
				key, err := BuildHeadendV4Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.objs.HeadendV4Map.Put(key, e); err != nil {
					t.Fatal(err)
				}
			},
			putRawOwner: func(t *testing.T, vrf uint32, prefix string, owner OwnerTag) {
				t.Helper()
				key, err := BuildHeadendV4Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.headendV4Owners.Put(key, owner); err != nil {
					t.Fatal(err)
				}
			},
			rawPrefixlen: func(t *testing.T, vrf uint32, prefix string) uint32 {
				t.Helper()
				want, err := BuildHeadendV4Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				var key HeadendV4Key
				var e HeadendEntry
				for it := h.objs.HeadendV4Map.Iterate(); it.Next(&key, &e); {
					if key.Instance == want.Instance && key.Addr == want.Addr && key.Prefixlen == want.Prefixlen {
						return key.Prefixlen
					}
				}
				t.Fatalf("no raw entry for vrf %d %s", vrf, prefix)
				return 0
			},
			rawCount: func(t *testing.T) int {
				t.Helper()
				var key HeadendV4Key
				var e HeadendEntry
				n := 0
				it := h.objs.HeadendV4Map.Iterate()
				for it.Next(&key, &e) {
					n++
				}
				if err := it.Err(); err != nil {
					t.Fatal(err)
				}
				return n
			},
			packet: func(t *testing.T, dst string) []byte {
				t.Helper()
				pkt, err := buildSimpleIPv4Packet(net.ParseIP("192.0.2.1"), net.ParseIP(dst))
				if err != nil {
					t.Fatal(err)
				}
				return pkt
			},
		},
		{
			name:  "v6",
			cover: "fd00:1::/32", longer: "fd00:1:2::/48", other: "fd00:99::/64", deflt: "::/0",
			toCover: "fd00:1:9::9", toLonger: "fd00:1:2::3", toOther: "fd00:99::1",
			create: m.CreateHeadendV6, remove: m.DeleteHeadendV6, list: m.ListHeadendV6,
			owners: m.ListHeadendV6Owners, getOwner: m.GetHeadendV6Owner,
			putRaw: func(t *testing.T, vrf uint32, prefix string, e *HeadendEntry) {
				t.Helper()
				key, err := BuildHeadendV6Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.objs.HeadendV6Map.Put(key, e); err != nil {
					t.Fatal(err)
				}
			},
			putRawOwner: func(t *testing.T, vrf uint32, prefix string, owner OwnerTag) {
				t.Helper()
				key, err := BuildHeadendV6Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.headendV6Owners.Put(key, owner); err != nil {
					t.Fatal(err)
				}
			},
			rawPrefixlen: func(t *testing.T, vrf uint32, prefix string) uint32 {
				t.Helper()
				want, err := BuildHeadendV6Key(vrf, prefix)
				if err != nil {
					t.Fatal(err)
				}
				var key HeadendV6Key
				var e HeadendEntry
				for it := h.objs.HeadendV6Map.Iterate(); it.Next(&key, &e); {
					if key.Instance == want.Instance && key.Addr == want.Addr && key.Prefixlen == want.Prefixlen {
						return key.Prefixlen
					}
				}
				t.Fatalf("no raw entry for vrf %d %s", vrf, prefix)
				return 0
			},
			rawCount: func(t *testing.T) int {
				t.Helper()
				var key HeadendV6Key
				var e HeadendEntry
				n := 0
				it := h.objs.HeadendV6Map.Iterate()
				for it.Next(&key, &e) {
					n++
				}
				if err := it.Err(); err != nil {
					t.Fatal(err)
				}
				return n
			},
			packet: func(t *testing.T, dst string) []byte {
				t.Helper()
				pkt, err := buildSimpleIPv6Packet(net.ParseIP("fd00:ffff::1"), net.ParseIP(dst))
				if err != nil {
					t.Fatal(err)
				}
				return pkt
			},
		},
	}
}

// TestXDPProgHeadendKeyVRF checks the {vrf_id, prefix} headend key while
// every writer and the data plane use vrf_id 0. Longest-prefix match still
// picks the longer prefix with the VRF in front; an entry written directly
// under a non-zero vrf_id is never matched, not even for a packet from an
// AC classified to that VRF, and it neither shadows nor shows up in the
// vrf 0 entries the prefix-keyed API reads and writes.
func TestXDPProgHeadendKeyVRF(t *testing.T) {
	h := newXDPTestHelper(t)
	const ifidx = 1 // loopback; BPF_PROG_TEST_RUN backs the buffer with it
	src, _ := ParseIPv6("fc00::1")
	entryTo := func(t *testing.T, seg string) *HeadendEntry {
		t.Helper()
		segments, n, err := ParseSegments([]string{seg})
		if err != nil {
			t.Fatal(err)
		}
		return &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: n,
			SrcAddr:     src,
			Segments:    segments,
		}
	}
	const segCover, segLonger, segTenant, segDefault = "fc00:a::1", "fc00:b::1", "fc00:c::1", "fc00:d::1"

	for _, f := range headendKeyFamilies(h) {
		t.Run(f.name, func(t *testing.T) {
			// encappedTo runs pkt and reports whether it was encapsulated
			// toward seg; a miss leaves the frame untouched.
			run := func(t *testing.T, dst string, vrf uint32) (uint32, []byte, []byte) {
				t.Helper()
				if err := h.mapOps.SetIngressPolicy(vrf != 0, false, 0); err != nil {
					t.Fatal(err)
				}
				acs := map[IngressACKey]uint32{}
				if vrf != 0 {
					acs[IngressACKey{Ifindex: ifidx, VlanId: 0}] = vrf
				}
				if err := h.mapOps.SetIngressVrf(acs); err != nil {
					t.Fatal(err)
				}
				pkt := f.packet(t, dst)
				ret, out := h.runOnIfindex(pkt, ifidx)
				return ret, out, pkt
			}
			expectEncap := func(t *testing.T, dst string, vrf uint32, seg string) {
				t.Helper()
				_, out, pkt := run(t, dst, vrf)
				if len(out) < ethHeaderLen+40 || bytes.Equal(out[:len(pkt)], pkt) {
					t.Fatalf("%s from vrf %d: not encapsulated, want toward %s", dst, vrf, seg)
				}
				if got := outerDA(out, ethHeaderLen); !got.Equal(net.ParseIP(seg)) {
					t.Errorf("%s from vrf %d: outer DA %s, want %s", dst, vrf, got, seg)
				}
			}
			expectMiss := func(t *testing.T, dst string, vrf uint32) {
				t.Helper()
				ret, out, pkt := run(t, dst, vrf)
				if ret != XDP_PASS {
					t.Errorf("%s from vrf %d: ret %d, want XDP_PASS", dst, vrf, ret)
				}
				if !bytes.Equal(out[:len(pkt)], pkt) {
					t.Errorf("%s from vrf %d: frame rewritten, want a headend miss", dst, vrf)
				}
			}
			t.Cleanup(func() {
				_ = h.mapOps.SetIngressVrf(map[IngressACKey]uint32{})
				_ = h.mapOps.SetIngressPolicy(false, false, 0)
			})

			for _, p := range []struct{ prefix, seg string }{{f.cover, segCover}, {f.longer, segLonger}} {
				if err := f.create(p.prefix, entryTo(t, p.seg), OwnerRPC); err != nil {
					t.Fatal(err)
				}
			}

			// The VRF sits in front of the address, so the stored length is
			// 32 longer, and the longest match still wins inside vrf 0.
			if got := f.rawPrefixlen(t, 0, f.longer); got != headendKeyVRFBits+uint32(prefixLenOf(t, f.longer)) {
				t.Errorf("raw prefixlen of %s = %d", f.longer, got)
			}
			expectEncap(t, f.toLonger, 0, segLonger)
			expectEncap(t, f.toCover, 0, segCover)

			// A packet from a tenant AC is matched in vrf 0 as well.
			expectEncap(t, f.toLonger, 7, segLonger)

			// Entries under a non-zero vrf_id, written directly: a prefix
			// nothing in vrf 0 covers, and the vrf 0 longer prefix again.
			f.putRaw(t, 7, f.other, entryTo(t, segTenant))
			tenantLonger := entryTo(t, segTenant)
			tenantLonger.PolicyId = 77
			f.putRaw(t, 7, f.longer, tenantLonger)
			f.putRawOwner(t, 7, f.other, OwnerPluginBundle("tenant"))
			if n := f.rawCount(t); n != 4 {
				t.Fatalf("raw map holds %d entries, want 4", n)
			}
			for _, vrf := range []uint32{0, 7} {
				expectMiss(t, f.toOther, vrf)
				expectEncap(t, f.toLonger, vrf, segLonger)
			}

			// The prefix-keyed API sees vrf 0 only, in plain CIDR form.
			entries, err := f.list()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 || entries[f.cover] == nil || entries[f.longer] == nil {
				t.Errorf("list = %v, want exactly %s and %s", keysOf(entries), f.cover, f.longer)
			}
			if seg := net.IP(entries[f.longer].Segments[0][:]); !seg.Equal(net.ParseIP(segLonger)) {
				t.Errorf("list shows %s with segment %s, want the vrf 0 entry (%s)", f.longer, seg, segLonger)
			}
			owners, err := f.owners()
			if err != nil {
				t.Fatal(err)
			}
			if len(owners) != 2 || owners[f.cover] != OwnerRPC || owners[f.longer] != OwnerRPC {
				t.Errorf("owners = %v, want %s and %s owned by %s", owners, f.cover, f.longer, OwnerRPC)
			}
			if owner, ok, err := f.getOwner(f.other); err != nil || ok {
				t.Errorf("vrf 0 owner of %s = %q %v %v, want none", f.other, owner, ok, err)
			}
			// Startup policy-id recovery scans every VRF.
			if id, err := h.mapOps.HighestSRPolicyIDInUse(); err != nil || id < 77 {
				t.Errorf("HighestSRPolicyIDInUse = %d %v, want at least 77", id, err)
			}

			// The tenant owner does not block a vrf 0 write of that prefix,
			// and deleting the vrf 0 entry leaves the tenant one alone.
			if err := f.create(f.other, entryTo(t, segCover), OwnerPluginBundle("global")); err != nil {
				t.Fatalf("vrf 0 create next to a tenant owner: %v", err)
			}
			expectEncap(t, f.toOther, 7, segCover)
			if err := f.remove(f.other, OwnerPluginBundle("global")); err != nil {
				t.Fatal(err)
			}
			expectMiss(t, f.toOther, 0)
			if n := f.rawCount(t); n != 4 {
				t.Errorf("raw map holds %d entries after the vrf 0 delete, want 4", n)
			}

			// A vrf 0 default route catches what nothing longer covers,
			// with the tenant entry for the same destination still present.
			if err := f.create(f.deflt, entryTo(t, segDefault), OwnerRPC); err != nil {
				t.Fatal(err)
			}
			if got := f.rawPrefixlen(t, 0, f.deflt); got != headendKeyVRFBits {
				t.Errorf("raw prefixlen of %s = %d, want %d", f.deflt, got, headendKeyVRFBits)
			}
			expectEncap(t, f.toOther, 0, segDefault)
			expectEncap(t, f.toOther, 7, segDefault)
			expectEncap(t, f.toLonger, 0, segLonger)

			for _, p := range []string{f.cover, f.longer, f.deflt} {
				if err := f.remove(p, OwnerRPC); err != nil {
					t.Fatal(err)
				}
			}
			if n := f.rawCount(t); n != 2 {
				t.Errorf("raw map holds %d entries after cleanup, want the 2 tenant ones", n)
			}
		})
	}
}

func prefixLenOf(t *testing.T, cidr string) int {
	t.Helper()
	_, n, err := ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestPluginHeadendKeyABI loads the example plugin built against the
// current headers into the shared maps, then checks both ways an ELF built
// with a prefix-only headend key is refused: by name when it carries BTF,
// by size at load when it does not.
func TestPluginHeadendKeyABI(t *testing.T) {
	h := newXDPTestHelper(t)
	spec := customCDPlaneSpec(t)
	for name, want := range map[string]struct {
		size uint32
		key  string
	}{
		"headend_v4_map": {12, "headend_v4_key"},
		"headend_v6_map": {24, "headend_v6_key"},
	} {
		ms, ok := spec.Maps[name]
		if !ok {
			t.Fatalf("the example plugin does not declare %s", name)
		}
		if ms.KeySize != want.size || mapValueTypeName(ms.Key) != want.key {
			t.Errorf("%s declared with key %q of %d bytes, want %q of %d",
				name, mapValueTypeName(ms.Key), ms.KeySize, want.key, want.size)
		}
	}
	loadCustomCDPlane(t, h)

	replacements := func(spec *ebpf.CollectionSpec) map[string]*ebpf.Map {
		out := map[string]*ebpf.Map{}
		for _, shared := range []map[string]*ebpf.Map{h.mapOps.GetSharedReadOnlyMaps(), h.mapOps.GetSharedReadWriteMaps()} {
			for name, m := range shared {
				if _, declared := spec.Maps[name]; declared {
					out[name] = m
				}
			}
		}
		return out
	}

	old := spec.Copy()
	old.Maps["headend_v4_map"].KeySize = 8
	old.Maps["headend_v4_map"].Key = &btf.Struct{Name: "lpm_key_v4"}
	if _, err := ValidatePluginCollection(old, customCDPlaneProgram, SharedReadOnlyMapNamesSet()); err == nil {
		t.Error("validation accepted a headend_v4_map declared with lpm_key_v4")
	}

	stripped := spec.Copy()
	stripped.Maps["headend_v4_map"].KeySize = 8
	stripped.Maps["headend_v4_map"].Key = nil
	if _, err := ValidatePluginCollection(stripped, customCDPlaneProgram, SharedReadOnlyMapNamesSet()); err != nil {
		t.Fatalf("validation without key BTF: %v", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(stripped, ebpf.CollectionOptions{MapReplacements: replacements(stripped)})
	if err == nil {
		coll.Close()
		t.Fatal("a headend_v4_map declared with an 8-byte key replaced the shared map")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Errorf("load error %v, want ErrMapIncompatible", err)
	}
}
