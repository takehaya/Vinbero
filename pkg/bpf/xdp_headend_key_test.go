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
	putMalformed                func(t *testing.T) func()
	putMalformedOwner           func(t *testing.T, owner OwnerTag)
	createIn                    func(uint32, string, *HeadendEntry, OwnerTag) error
	removeIn                    func(uint32, string, OwnerTag) error
	getIn                       func(uint32, string) (*HeadendEntry, error)
	getOwnerIn                  func(uint32, string) (OwnerTag, bool, error)
	listIDs                     func() (map[HeadendID]*HeadendEntry, error)
	ownerIDs                    func() (map[HeadendID]OwnerTag, error)
	flushIn                     func(uint32, OwnerTag) (uint32, error)
	flush                       func(OwnerTag) (uint32, error)
	forceFlush                  func() (uint32, error)
	pruneUnlisted               func(OwnerTag) (int, error)
	policyID                    uint32
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
			flush: m.FlushHeadendV4, forceFlush: m.ForceFlushHeadendV4, pruneUnlisted: m.PruneUnlistedHeadendV4,
			createIn: m.CreateHeadendV4In, removeIn: m.DeleteHeadendV4In, getIn: m.GetHeadendV4In,
			getOwnerIn: m.GetHeadendV4OwnerIn, listIDs: m.ListHeadendV4IDs, ownerIDs: m.ListHeadendV4OwnerIDs,
			flushIn: m.FlushHeadendV4In,
			putMalformedOwner: func(t *testing.T, owner OwnerTag) {
				t.Helper()
				if err := m.headendV4Owners.Put(&HeadendV4Key{Prefixlen: 8}, owner); err != nil {
					t.Fatal(err)
				}
			},
			policyID: 77,
			putMalformed: func(t *testing.T) func() {
				t.Helper()
				key := &HeadendV4Key{Prefixlen: 8} // shorter than the vrf_id field
				if err := h.objs.HeadendV4Map.Put(key, &HeadendEntry{}); err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := h.objs.HeadendV4Map.Delete(key); err != nil {
						t.Fatal(err)
					}
				}
			},
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
			flush: m.FlushHeadendV6, forceFlush: m.ForceFlushHeadendV6, pruneUnlisted: m.PruneUnlistedHeadendV6,
			createIn: m.CreateHeadendV6In, removeIn: m.DeleteHeadendV6In, getIn: m.GetHeadendV6In,
			getOwnerIn: m.GetHeadendV6OwnerIn, listIDs: m.ListHeadendV6IDs, ownerIDs: m.ListHeadendV6OwnerIDs,
			flushIn: m.FlushHeadendV6In,
			putMalformedOwner: func(t *testing.T, owner OwnerTag) {
				t.Helper()
				if err := m.headendV6Owners.Put(&HeadendV6Key{Prefixlen: 8}, owner); err != nil {
					t.Fatal(err)
				}
			},
			policyID: 88,
			putMalformed: func(t *testing.T) func() {
				t.Helper()
				key := &HeadendV6Key{Prefixlen: 8} // shorter than the vrf_id field
				if err := h.objs.HeadendV6Map.Put(key, &HeadendEntry{}); err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := h.objs.HeadendV6Map.Delete(key); err != nil {
						t.Fatal(err)
					}
				}
			},
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
			tenantLonger.PolicyId = f.policyID
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
			// Startup policy-id recovery scans every VRF. The other family's
			// subtest leaves nothing behind (its force flush), so the only
			// policy id in use is the tenant entry's.
			if id, err := h.mapOps.HighestSRPolicyIDInUse(); err != nil || id != f.policyID {
				t.Errorf("HighestSRPolicyIDInUse = %d %v, want %d", id, err, f.policyID)
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

			// The per-VRF owner inventory names what an owner holds outside
			// vrf 0, an owner record without its entry included, so the
			// owner cleanup prunes it by name. The unlisted prune is left
			// with the malformed keys no listing can name.
			gone := OwnerPluginBundle("gone")
			f.putRaw(t, 9, f.cover, entryTo(t, segTenant))
			f.putRawOwner(t, 9, f.cover, gone)
			f.putRawOwner(t, 9, f.longer, gone)
			f.putMalformedOwner(t, gone)
			ids, err := f.ownerIDs()
			if err != nil {
				t.Fatal(err)
			}
			if ids[HeadendID{9, f.cover}] != gone || ids[HeadendID{9, f.longer}] != gone || ids[HeadendID{0, f.cover}] != OwnerRPC {
				t.Errorf("owner ids = %v", ids)
			}
			if n, err := f.pruneUnlisted(gone); err != nil || n != 1 {
				t.Errorf("prune unlisted = %d %v, want 1 (the malformed owner record)", n, err)
			}
			for _, p := range []string{f.cover, f.longer} {
				if err := f.removeIn(9, p, gone); err != nil {
					t.Errorf("delete vrf 9 %s: %v", p, err)
				}
			}
			if n := f.rawCount(t); n != 5 {
				t.Errorf("raw map holds %d entries after the prune, want 5", n)
			}
			if owner, ok, err := f.getOwner(f.cover); err != nil || !ok || owner != OwnerRPC {
				t.Errorf("vrf 0 owner of %s after the prune = %q %v %v", f.cover, owner, ok, err)
			}

			// The flushes empty every VRF under the rules they apply to vrf
			// 0: the scoped one takes the scope's entries and unowned ones.
			// A malformed key is skipped and reported; the rest still goes.
			dropMalformed := f.putMalformed(t)
			if entries, err := f.list(); err != nil || len(entries) != 3 {
				t.Errorf("list with a malformed key = %v %v, want the 3 vrf 0 entries", keysOf(entries), err)
			}
			n, err := f.flush(OwnerPluginBundle("tenant"))
			if n != 2 || !errors.Is(err, ErrMalformedHeadendKey) {
				t.Errorf("scoped flush = %d %v, want 2 and ErrMalformedHeadendKey", n, err)
			}
			if n := f.rawCount(t); n != 4 {
				t.Errorf("raw map holds %d entries after the scoped flush, want 4", n)
			}
			n, err = f.forceFlush()
			if n != 3 || !errors.Is(err, ErrMalformedHeadendKey) {
				t.Errorf("force flush = %d %v, want 3 and ErrMalformedHeadendKey", n, err)
			}
			dropMalformed()
			if n, err := f.forceFlush(); n != 0 || err != nil {
				t.Errorf("force flush of an empty map = %d %v", n, err)
			}
			if n := f.rawCount(t); n != 0 {
				t.Errorf("raw map holds %d entries after the force flush, want 0", n)
			}
			if owners, err := f.owners(); err != nil || len(owners) != 0 {
				t.Errorf("owners after the force flush = %v %v", owners, err)
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

// TestXDPProgHeadendSamePrefixAcrossVRFs writes one trigger prefix in the
// global VRF and in two named ones through the per-VRF MapOperations
// methods. The three are separate entries with their own owners: each is
// read, listed and removed alone, the VRF-scoped flush takes one VRF's,
// and the data plane, which looks up vrf_id 0 only, keeps encapsulating
// with the global entry whatever VRF the packet came from.
func TestXDPProgHeadendSamePrefixAcrossVRFs(t *testing.T) {
	h := newXDPTestHelper(t)
	const ifidx = 1
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
	seg := map[uint32]string{0: "fc00:a::1", 7: "fc00:b::1", 8: "fc00:c::1"}
	owner := map[uint32]OwnerTag{0: OwnerRPC, 7: OwnerRPC, 8: OwnerPluginBundle("tenant")}

	for _, f := range headendKeyFamilies(h) {
		t.Run(f.name, func(t *testing.T) {
			t.Cleanup(func() {
				_, _ = f.forceFlush()
				_ = h.mapOps.SetIngressVrf(map[IngressACKey]uint32{})
				_ = h.mapOps.SetIngressPolicy(false, false, 0)
			})
			outerTo := func(t *testing.T, vrf uint32) net.IP {
				t.Helper()
				if err := h.mapOps.SetIngressPolicy(vrf != 0, false, 0); err != nil {
					t.Fatal(err)
				}
				acs := map[IngressACKey]uint32{}
				if vrf != 0 {
					acs[IngressACKey{Ifindex: ifidx}] = vrf
				}
				if err := h.mapOps.SetIngressVrf(acs); err != nil {
					t.Fatal(err)
				}
				pkt := f.packet(t, f.toLonger)
				_, out := h.runOnIfindex(pkt, ifidx)
				if len(out) < ethHeaderLen+40 || bytes.Equal(out[:len(pkt)], pkt) {
					return nil
				}
				return outerDA(out, ethHeaderLen)
			}
			segOf := func(e *HeadendEntry) string { return net.IP(e.Segments[0][:]).String() }

			for _, vrf := range []uint32{0, 7, 8} {
				if err := f.createIn(vrf, f.longer, entryTo(t, seg[vrf]), owner[vrf]); err != nil {
					t.Fatalf("create vrf %d: %v", vrf, err)
				}
			}
			// The prefix-only API is the global VRF: the same key as vrf 0.
			if err := f.create(f.longer, entryTo(t, seg[0]), OwnerRPC); err != nil {
				t.Fatalf("prefix-only create over the vrf 0 entry: %v", err)
			}
			if n := f.rawCount(t); n != 3 {
				t.Fatalf("raw map holds %d entries, want 3", n)
			}
			for _, vrf := range []uint32{0, 7, 8} {
				if got := f.rawPrefixlen(t, vrf, f.longer); got != headendKeyVRFBits+uint32(prefixLenOf(t, f.longer)) {
					t.Errorf("vrf %d raw prefixlen = %d", vrf, got)
				}
				e, err := f.getIn(vrf, f.longer)
				if err != nil || segOf(e) != seg[vrf] {
					t.Errorf("get vrf %d = %v %v, want segment %s", vrf, e, err, seg[vrf])
				}
				if o, ok, err := f.getOwnerIn(vrf, f.longer); err != nil || !ok || o != owner[vrf] {
					t.Errorf("owner vrf %d = %q %v %v, want %q", vrf, o, ok, err, owner[vrf])
				}
				// A covering lookup stays inside the VRF.
				if e, err := f.getIn(vrf, f.toLonger); err != nil || segOf(e) != seg[vrf] {
					t.Errorf("get vrf %d %s = %v %v, want the covering entry of that VRF", vrf, f.toLonger, e, err)
				}
			}
			ids, err := f.listIDs()
			if err != nil || len(ids) != 3 {
				t.Fatalf("list ids = %v %v, want 3", ids, err)
			}
			for _, vrf := range []uint32{0, 7, 8} {
				if e := ids[HeadendID{vrf, f.longer}]; e == nil || segOf(e) != seg[vrf] {
					t.Errorf("list ids vrf %d = %v", vrf, e)
				}
			}
			if entries, err := f.list(); err != nil || len(entries) != 1 || segOf(entries[f.longer]) != seg[0] {
				t.Errorf("prefix-only list = %v %v, want the vrf 0 entry alone", keysOf(entries), err)
			}
			if n, err := h.mapOps.HeadendEntriesInVRF(7); err != nil || n != 1 {
				t.Errorf("entries in vrf 7 = %d %v, want 1", n, err)
			}

			// The lookup is vrf_id 0 for every packet.
			for _, vrf := range []uint32{0, 7, 8} {
				if got := outerTo(t, vrf); !got.Equal(net.ParseIP(seg[0])) {
					t.Errorf("packet from vrf %d: outer DA %v, want the vrf 0 segment %s", vrf, got, seg[0])
				}
			}

			// Each is owned and removed alone.
			if err := f.removeIn(8, f.longer, OwnerRPC); !errors.Is(err, ErrEntryOwnerMismatch) {
				t.Errorf("RPC delete of the tenant's vrf 8 entry = %v, want ErrEntryOwnerMismatch", err)
			}
			if err := f.removeIn(7, f.longer, OwnerRPC); err != nil {
				t.Fatal(err)
			}
			if _, err := f.getIn(7, f.longer); err == nil {
				t.Error("vrf 7 entry still there after its delete")
			}
			for _, vrf := range []uint32{0, 8} {
				if _, err := f.getIn(vrf, f.longer); err != nil {
					t.Errorf("vrf %d entry gone with the vrf 7 delete: %v", vrf, err)
				}
			}
			if n, err := h.mapOps.HeadendEntriesInVRF(7); err != nil || n != 0 {
				t.Errorf("entries in vrf 7 after the delete = %d %v, want 0", n, err)
			}
			if n, err := f.flushIn(8, OwnerRPC); err != nil || n != 0 {
				t.Errorf("RPC-scoped flush of vrf 8 = %d %v, want 0 (the entry is the tenant's)", n, err)
			}
			if n, err := f.flushIn(8, owner[8]); err != nil || n != 1 {
				t.Errorf("flush of vrf 8 = %d %v, want 1", n, err)
			}
			if e, err := f.getIn(0, f.longer); err != nil || segOf(e) != seg[0] {
				t.Errorf("vrf 0 entry after the vrf 8 flush = %v %v", e, err)
			}
			if err := f.remove(f.longer, OwnerRPC); err != nil {
				t.Fatal(err)
			}
			if n := f.rawCount(t); n != 0 {
				t.Errorf("raw map holds %d entries at the end, want 0", n)
			}
		})
	}
}
