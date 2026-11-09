package bpf

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// dummyIfindex creates a dummy link: devmap entries must name a device
// that exists.
func dummyIfindex(t *testing.T, name string) uint32 {
	t.Helper()
	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Skipf("cannot create dummy link: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(d) })
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(l.Attrs().Index)
}

// devmapEntries reads outer[bd] back as {key: value}; nil when absent.
func devmapEntries(t *testing.T, outer *ebpf.Map, bd uint16) map[uint32]devmapVal {
	t.Helper()
	var id ebpf.MapID
	if err := outer.Lookup(uint32(bd), &id); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		t.Fatalf("outer lookup: %v", err)
	}
	inner, err := ebpf.NewMapFromID(id)
	if err != nil {
		t.Fatalf("open inner devmap: %v", err)
	}
	defer func() { _ = inner.Close() }()
	out := map[uint32]devmapVal{}
	var (
		k uint32
		v devmapVal
	)
	it := inner.Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate inner devmap: %v", err)
	}
	return out
}

func sortedKeys(m map[uint32]devmapVal) []uint32 {
	keys := make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestBumDevmapSync(t *testing.T) {
	h := newXDPBumHelper(t)
	mode := BumModeXDP
	var (
		resolved [][IPv6AddrLen]byte
		ifUp     uint32 // the uplink of every peer: no AC of the BD
	)
	uplink := func(q UplinkQuery) (BumUplink, error) {
		resolved = append(resolved, q.Dst)
		return BumUplink{Ifindex: ifUp}, nil
	}
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return mode }, uplink, zap.NewNop())
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	ac := func(ifindex uint32, vlan uint16, bd uint16) {
		t.Helper()
		if err := h.mapOps.CreateHeadendL2(ifindex, vlan, &HeadendEntry{
			Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
			SrcAddr: src, Segments: segs, BdId: bd,
		}, [ESILen]byte{}); err != nil {
			t.Fatal(err)
		}
	}
	peer := func(index uint16, floodExclude bool) {
		t.Helper()
		e := &HeadendEntry{
			Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
			SrcAddr: src, Segments: segs,
		}
		if floodExclude {
			e.FloodExclude = 1
		}
		if err := h.mapOps.CreateBdPeer(bumTestBD, index, e, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
			t.Fatal(err)
		}
	}

	// A peer before any AC: no devmap (nothing to flood from or to).
	peer(0, false)
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Fatalf("BD without an AC got a flood devmap: %v", got)
	}

	ifA, ifB := dummyIfindex(t, "bumdm-a"), dummyIfindex(t, "bumdm-b")
	ifUp = dummyIfindex(t, "bumdm-up")
	ac(1, 100, bumTestBD)
	ac(ifA, 0, 999) // another BD
	peer(1, true)         // RT2 unicast peer: not flooded
	peer(EsPeerIndexBase, false)
	peer(2, false)

	flood := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)
	want := []uint32{1, BumSlotKeyBase, BumSlotKeyBase | 2} // slots 0 and 2
	if got := sortedKeys(flood); !slices.Equal(got, want) {
		t.Fatalf("flood devmap keys = %#x, want %#x", got, want)
	}
	if flood[1].ProgFD != 0 || flood[1].Ifindex != 1 {
		t.Errorf("AC entry = %+v, want ifindex 1 without a program", flood[1])
	}
	// The kernel reports the attached program by ID, not by fd.
	info, err := s.egress.Info()
	if err != nil {
		t.Fatal(err)
	}
	egressID, _ := info.ID()
	for _, slot := range []uint32{0, 2} {
		v := flood[BumSlotKeyBase|slot]
		if v.Ifindex != ifUp {
			t.Errorf("slot %d uplink = %d, want %d", slot, v.Ifindex, ifUp)
		}
		if v.ProgFD != uint32(egressID) {
			t.Errorf("slot %d program id = %d, want the shared bum_remote_egress (id %d)", slot, v.ProgFD, egressID)
		}
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumLocalMap, bumTestBD)); !slices.Equal(got, []uint32{1}) {
		t.Errorf("local devmap keys = %v, want [1]", got)
	}

	// Mutations rebuild the BD.
	if _, err := h.mapOps.DeleteBdPeer(bumTestBD, 0); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)); !slices.Equal(got, []uint32{1, BumSlotKeyBase | 2}) { // slot 2 left
		t.Errorf("after DeleteBdPeer(0): keys = %#x", got)
	}
	ac(ifB, 100, bumTestBD)
	if got := sortedKeys(devmapEntries(t, h.objs.BumLocalMap, bumTestBD)); !slices.Equal(got, []uint32{1, ifB}) {
		t.Errorf("after a new AC: local keys = %v, want [1 %d]", got, ifB)
	}
	if err := h.mapOps.DeleteHeadendL2(ifB, 100); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumLocalMap, bumTestBD)); !slices.Equal(got, []uint32{1}) {
		t.Errorf("after deleting an AC: local keys = %v, want [1]", got)
	}

	// Each BD keeps its own devmap.
	if got := sortedKeys(devmapEntries(t, h.objs.BumFloodMap, 999)); !slices.Equal(got, []uint32{ifA}) {
		t.Errorf("BD 999 flood keys = %v, want [%d]", got, ifA)
	}

	// tc mode removes the devmaps (SyncAll also visits BDs known only
	// from the outer maps): the BD falls back to the tc path.
	mode = BumModeTC
	if err := h.mapOps.DeleteHeadendL2(ifA, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncAll(); err != nil {
		t.Fatal(err)
	}
	if devmapEntries(t, h.objs.BumFloodMap, 999) != nil {
		t.Error("BD 999 lost its last AC but kept a devmap")
	}
	if devmapEntries(t, h.objs.BumFloodMap, bumTestBD) != nil || devmapEntries(t, h.objs.BumLocalMap, bumTestBD) != nil {
		t.Error("tc mode kept a devmap")
	}

	// An unresolvable uplink leaves only that slot out.
	mode = BumModeXDP
	s.uplink = func(UplinkQuery) (BumUplink, error) { return BumUplink{}, errors.New("no route") }
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)); !slices.Equal(got, []uint32{1}) {
		t.Errorf("unresolved uplink: keys = %#x, want only the AC", got)
	}
	if len(resolved) == 0 {
		t.Error("the resolver was never asked")
	}

	// An AC whose device is gone leaves only that AC out.
	s.uplink = uplink
	ac(0x7ffffff0, 100, bumTestBD) // no such device
	if got := sortedKeys(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)); !slices.Equal(got, []uint32{1, BumSlotKeyBase | 2}) {
		t.Errorf("AC without a device: flood keys = %#x, want the other AC and slot 2", got)
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumLocalMap, bumTestBD)); !slices.Equal(got, []uint32{1}) {
		t.Errorf("AC without a device: local keys = %v, want [1]", got)
	}
	if err := h.mapOps.DeleteHeadendL2(0x7ffffff0, 100); err != nil {
		t.Fatal(err)
	}

	// ACs with different VLAN IDs: xdp mode would forward the tag
	// unchanged, so the BD is left to the tc path and the bridge.
	ac(1, 200, bumTestBD)
	if devmapEntries(t, h.objs.BumFloodMap, bumTestBD) != nil || devmapEntries(t, h.objs.BumLocalMap, bumTestBD) != nil {
		t.Error("a BD whose ACs differ in VLAN kept a devmap")
	}
	if _, ok := s.unserved[bumTestBD]; !ok {
		t.Error("the BD is not recorded as falling back")
	}
	if err := h.mapOps.DeleteHeadendL2(1, 200); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)); !slices.Equal(got, []uint32{1, BumSlotKeyBase | 2}) {
		t.Errorf("one VLAN again: flood keys = %#x, want the AC and slot 2", got)
	}
	if _, ok := s.unserved[bumTestBD]; ok {
		t.Error("the BD still counts as falling back")
	}
}

// ACs and slots that do not fit into one BD devmap leave the BD on the tc
// path rather than with a devmap that misses some of them.
func TestBumDevmapSyncCapacity(t *testing.T) {
	h := newXDPBumHelper(t)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(UplinkQuery) (BumUplink, error) { return BumUplink{Ifindex: 1}, nil }, zap.NewNop())
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	entry := func() *HeadendEntry {
		return &HeadendEntry{
			Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
			SrcAddr: src, Segments: segs, BdId: bumTestBD,
		}
	}
	// Devmap entries must name devices that exist; ifindex 1 (lo) is the
	// only one guaranteed, so the ACs are dummies.
	const acs = bumDevmapMaxEntries - 2
	for i := range acs {
		ifindex := dummyIfindex(t, fmt.Sprintf("bumcap-%d", i))
		if err := h.mapOps.CreateHeadendL2(ifindex, 100, entry(), [ESILen]byte{}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range uint16(2) {
		if err := h.mapOps.CreateBdPeer(bumTestBD, i, entry(), [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)); got != bumDevmapMaxEntries {
		t.Fatalf("flood devmap has %d entries, want %d", got, bumDevmapMaxEntries)
	}
	if err := h.mapOps.CreateBdPeer(bumTestBD, 2, entry(), [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if devmapEntries(t, h.objs.BumFloodMap, bumTestBD) != nil {
		t.Error("a BD that does not fit kept a devmap")
	}
	if _, ok := s.unserved[bumTestBD]; !ok {
		t.Error("the BD is not recorded as falling back")
	}
}

// KeepNeighResolved turns a slot's next hop into a managed neighbour that
// the kernel keeps trying to resolve without traffic, GC-exempt, and leaves
// a static one alone.
func TestKeepNeighResolved(t *testing.T) {
	// Explicit MACs, as in adjacencyEnv: udevd rewrites a kernel-assigned
	// veth MAC shortly after creation, and the address change flushes the
	// device's neighbour table, managed entries included.
	macA, _ := net.ParseMAC("02:ad:00:00:01:0a")
	macB, _ := net.ParseMAC("02:ad:00:00:01:0b")
	veth := &netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: "bumnb-a", HardwareAddr: macA},
		PeerName:         "bumnb-b",
		PeerHardwareAddr: macB,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create veth: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	addr := func(name, cidr string) (netlink.Link, uint32) {
		t.Helper()
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := netlink.ParseAddr(cidr)
		a.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(l, a); err != nil {
			t.Fatal(err)
		}
		return l, uint32(l.Attrs().Index)
	}
	linkA, ifA := addr("bumnb-a", "fd00:bb::1/64")
	linkB, _ := addr("bumnb-b", "fd00:bb::2/64")
	if err := netlink.LinkSetUp(linkA); err != nil {
		t.Fatal(err)
	}

	find := func(ip net.IP) *netlink.Neigh {
		neighs, err := netlink.NeighList(int(ifA), netlink.FAMILY_V6)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range neighs {
			if n.IP.Equal(ip) {
				return &n
			}
		}
		return nil
	}
	waitFor := func(what string, limit time.Duration, ok func(*netlink.Neigh) bool, ip net.IP) *netlink.Neigh {
		t.Helper()
		deadline := time.Now().Add(limit)
		for {
			n := find(ip)
			if n != nil && ok(n) {
				return n
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: neighbour = %+v", what, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// The next hop does not answer yet: its solicits run out and the entry
	// fails, staying managed and exempt from GC.
	nh := net.ParseIP("fd00:bb::2")
	if err := KeepNeighResolved(ifA, nh); err != nil {
		t.Fatal(err)
	}
	failed := waitFor("next hop did not fail while unreachable", 15*time.Second,
		func(n *netlink.Neigh) bool { return n.State&netlink.NUD_FAILED != 0 }, nh)
	if failed.FlagsExt&netlink.NTF_EXT_MANAGED == 0 || failed.Flags&netlink.NTF_EXT_LEARNED == 0 {
		t.Errorf("failed entry: flags %#x, ext flags %#x; want extern_learn and managed", failed.Flags, failed.FlagsExt)
	}

	// Once it answers, the kernel's periodic probe resolves it, no traffic
	// involved (after a failure that takes up to the 5 s probe interval
	// plus a round of solicits).
	if err := netlink.LinkSetUp(linkB); err != nil {
		t.Fatal(err)
	}
	const reachable = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE
	waitFor("next hop not resolved after it came up", 20*time.Second,
		func(n *netlink.Neigh) bool { return n.State&reachable != 0 && len(n.HardwareAddr) != 0 }, nh)
	// Idempotent.
	if err := KeepNeighResolved(ifA, nh); err != nil {
		t.Fatal(err)
	}

	static := net.ParseIP("fd00:bb::3")
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex: int(ifA), Family: netlink.FAMILY_V6, IP: static,
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 3}, State: netlink.NUD_PERMANENT,
	}); err != nil {
		t.Fatal(err)
	}
	if err := KeepNeighResolved(ifA, static); err != nil {
		t.Fatal(err)
	}
	if n := find(static); n == nil || n.State != netlink.NUD_PERMANENT || n.FlagsExt&netlink.NTF_EXT_MANAGED != 0 {
		t.Errorf("static neighbour changed: %+v", n)
	}
}
