package bpf

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
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
	uplink := func(seg [IPv6AddrLen]byte) (uint32, error) {
		resolved = append(resolved, seg)
		return ifUp, nil
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
	ac(1, 200, bumTestBD) // a second VLAN on the same port is one member
	ac(ifA, 0, 999)       // another BD
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
	s.uplink = func([IPv6AddrLen]byte) (uint32, error) { return 0, errors.New("no route") }
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
}
