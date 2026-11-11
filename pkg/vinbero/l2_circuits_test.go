package vinbero

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

type circuitKey struct {
	ifindex uint32
	vlan    uint16
}

// fakeL2Maps is headend_l2 and its ESI side table in memory.
type fakeL2Maps struct {
	entries   map[circuitKey]bpf.HeadendEntry
	esi       map[circuitKey][bpf.ESILen]byte
	failPut   int // the put that fails, counting from 1; 0 = none
	puts      int
	failDel   bool
	failWhere bool
}

func newFakeL2Maps() *fakeL2Maps {
	return &fakeL2Maps{entries: map[circuitKey]bpf.HeadendEntry{}, esi: map[circuitKey][bpf.ESILen]byte{}}
}

func (f *fakeL2Maps) CreateHeadendL2(ifindex uint32, vlan uint16, e *bpf.HeadendEntry, esi [bpf.ESILen]byte) error {
	f.puts++
	if f.puts == f.failPut {
		return errors.New("injected put failure")
	}
	k := circuitKey{ifindex, vlan}
	f.entries[k] = *e
	if esi == ([bpf.ESILen]byte{}) {
		delete(f.esi, k)
	} else {
		f.esi[k] = esi
	}
	return nil
}

func (f *fakeL2Maps) DeleteHeadendL2(ifindex uint32, vlan uint16) error {
	if f.failDel {
		return errors.New("injected delete failure")
	}
	k := circuitKey{ifindex, vlan}
	if _, ok := f.entries[k]; !ok {
		return fmt.Errorf("failed to delete headend L2 entry: %w", ebpf.ErrKeyNotExist)
	}
	delete(f.entries, k)
	delete(f.esi, k)
	return nil
}

func (f *fakeL2Maps) GetHeadendL2(ifindex uint32, vlan uint16) (*bpf.HeadendEntry, error) {
	e, ok := f.entries[circuitKey{ifindex, vlan}]
	if !ok {
		return nil, fmt.Errorf("failed to lookup headend L2 entry: %w", ebpf.ErrKeyNotExist)
	}
	return &e, nil
}

func (f *fakeL2Maps) GetHeadendL2Esi(ifindex uint32, vlan uint16) ([bpf.ESILen]byte, error) {
	return f.esi[circuitKey{ifindex, vlan}], nil
}

func (f *fakeL2Maps) DeleteHeadendL2Where(match func(uint32) bool) (int, error) {
	if f.failWhere {
		return 0, errors.New("injected flush failure")
	}
	n := 0
	for k := range f.entries {
		if match(k.ifindex) {
			delete(f.entries, k)
			delete(f.esi, k)
			n++
		}
	}
	return n, nil
}

// fakeL2Store is the state file's circuit record. file is what was last
// written; failSave makes the next writes fail.
type fakeL2Store struct {
	mem, file []netresource.ManagedL2Circuit
	failSave  int // how many of the next writes fail
	writes    int
}

func clone(in []netresource.ManagedL2Circuit) []netresource.ManagedL2Circuit {
	out := []netresource.ManagedL2Circuit{}
	for _, c := range in {
		c.Segments = slices.Clone(c.Segments)
		out = append(out, c)
	}
	return out
}

func (s *fakeL2Store) L2Circuits() []netresource.ManagedL2Circuit { return clone(s.mem) }

func (s *fakeL2Store) write(c []netresource.ManagedL2Circuit) error {
	s.writes++
	if s.failSave > 0 {
		s.failSave--
		return errors.New("injected write failure")
	}
	s.file = clone(c)
	return nil
}

func (s *fakeL2Store) SaveL2Circuits(c []netresource.ManagedL2Circuit) error {
	if err := s.write(c); err != nil {
		return err
	}
	s.mem = clone(c)
	return nil
}

func (s *fakeL2Store) DropL2Circuits(c []netresource.ManagedL2Circuit) error {
	s.mem = clone(c)
	return s.write(c)
}

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
	esi1 = [bpf.ESILen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
)

func newTestCircuits(links map[uint32]LinkID) (*L2Circuits, *fakeL2Maps, *fakeL2Store) {
	m, s := newFakeL2Maps(), &fakeL2Store{}
	c := NewL2Circuits(m, s, zap.NewNop())
	c.linkByIndex = func(ifindex uint32) (LinkID, bool, error) {
		l, ok := links[ifindex]
		return l, ok, nil
	}
	return c, m, s
}

func l2Entry(bd uint16) *bpf.HeadendEntry {
	src, _ := bpf.ParseIPv6("fc00:1::1")
	segs, n, _ := bpf.ParseSegments([]string{"fc00:2::1", "fc00:3::3"})
	return &bpf.HeadendEntry{
		Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs, BdId: bd,
	}
}

func circuitOn(l LinkID, vlan, bd uint16, esi [bpf.ESILen]byte) L2Circuit {
	return L2Circuit{Link: l, VLAN: vlan, Entry: l2Entry(bd), ESI: esi}
}

// The saved form brings back the same entry and ESI.
func TestL2CircuitRecordRoundTrip(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	for _, ckt := range []L2Circuit{
		circuitOn(l, 100, 100, esi1),
		circuitOn(l, 0, 0, [bpf.ESILen]byte{}),
		{Link: l, Entry: &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED), BdId: 5}},
	} {
		r := circuitRecord(ckt)
		e, esi, err := circuitEntry(r)
		if err != nil {
			t.Fatalf("circuitEntry(%+v): %v", r, err)
		}
		if !reflect.DeepEqual(e, ckt.Entry) || esi != ckt.ESI {
			t.Errorf("round trip of %+v: got %+v %v", ckt, e, esi)
		}
	}
	for _, bad := range []netresource.ManagedL2Circuit{
		{Mode: "SRV6_HEADEND_BEHAVIOR_NOPE"},
		{Mode: "SRV6_HEADEND_BEHAVIOR_UNSPECIFIED"},
		{Mode: "SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2", SrcAddr: "nope"},
		{Mode: "SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2", ESI: "01:02"},
	} {
		if _, _, err := circuitEntry(bad); err == nil {
			t.Errorf("circuitEntry(%+v) accepted", bad)
		}
	}
}

// A create is in the map and in the file, or in neither: a failed write of
// the state file puts the entry the circuit replaced back.
func TestL2CircuitsCreateSaveFailure(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	c, m, s := newTestCircuits(map[uint32]LinkID{7: l})
	if err := c.Create(circuitOn(l, 0, 100, esi1)); err != nil {
		t.Fatal(err)
	}
	if len(s.file) != 1 || s.file[0].BdID != 100 || s.file[0].ESI == "" || s.file[0].MAC != macA.String() {
		t.Fatalf("saved %+v", s.file)
	}

	// Moving the circuit to BD 200 fails to save: BD 100 and its ESI stay.
	s.failSave = 1
	if err := c.Create(circuitOn(l, 0, 200, [bpf.ESILen]byte{})); err == nil || !strings.Contains(err.Error(), "not created") {
		t.Fatalf("Create with a failing save = %v", err)
	}
	if e := m.entries[circuitKey{7, 0}]; e.BdId != 100 || m.esi[circuitKey{7, 0}] != esi1 {
		t.Errorf("map after the failed create: %+v esi %v", e, m.esi[circuitKey{7, 0}])
	}
	if !reflect.DeepEqual(s.mem, s.file) || s.file[0].BdID != 100 {
		t.Errorf("record after the failed create: mem %+v file %+v", s.mem, s.file)
	}

	// A new circuit whose save fails leaves no entry.
	s.failSave = 1
	if err := c.Create(circuitOn(l, 7, 100, [bpf.ESILen]byte{})); err == nil {
		t.Fatal("Create with a failing save succeeded")
	}
	if _, ok := m.entries[circuitKey{7, 7}]; ok {
		t.Error("the entry of a failed create stays in the map")
	}
	// Retrying succeeds.
	if err := c.Create(circuitOn(l, 7, 100, [bpf.ESILen]byte{})); err != nil || len(s.file) != 2 {
		t.Errorf("retry: %v, saved %+v", err, s.file)
	}
}

// A rename between the RPC's lookup and the write is recorded: the circuit
// carries the name the interface has once it is written.
func TestL2CircuitsCreateRecordsRenameDuringCreate(t *testing.T) {
	asked := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	links := map[uint32]LinkID{7: {Name: "veth0x", Ifindex: 7, MAC: macA}}
	c, m, s := newTestCircuits(links)
	if err := c.Create(circuitOn(asked, 0, 100, esi1)); err != nil {
		t.Fatal(err)
	}
	if s.file[0].Interface != "veth0x" || s.file[0].MAC != macA.String() {
		t.Errorf("saved %+v, want the name after the rename", s.file[0])
	}
	// Another interface took the ifindex in between: the create fails and
	// leaves the map and the file as they were.
	links[7] = LinkID{Name: "veth9", Ifindex: 7, MAC: macB}
	if err := c.Create(circuitOn(asked, 5, 100, esi1)); !errors.Is(err, ErrL2InterfaceGone) {
		t.Fatalf("Create on a reused ifindex = %v", err)
	}
	if _, ok := m.entries[circuitKey{7, 5}]; ok || len(s.file) != 1 {
		t.Errorf("a create on a reused ifindex left %v, saved %+v", m.entries, s.file)
	}
}

// A circuit written while its interface was deleted is taken back and not
// saved; a map write that fails is not saved either.
func TestL2CircuitsCreateInterfaceGoneAndWriteFailure(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	c, m, s := newTestCircuits(map[uint32]LinkID{})
	if err := c.Create(circuitOn(l, 0, 100, esi1)); !errors.Is(err, ErrL2InterfaceGone) {
		t.Fatalf("Create on a vanished interface = %v", err)
	}
	if len(m.entries) != 0 || len(m.esi) != 0 || len(s.file) != 0 || s.writes != 0 {
		t.Errorf("left %v %v, saved %+v", m.entries, m.esi, s.file)
	}

	c, m, s = newTestCircuits(map[uint32]LinkID{7: l})
	m.failPut = 1
	if err := c.Create(circuitOn(l, 0, 100, esi1)); err == nil {
		t.Fatal("a failed map write succeeded")
	}
	if len(m.entries) != 0 || s.writes != 0 {
		t.Errorf("left %v, %d writes", m.entries, s.writes)
	}
}

// A delete marks the circuit, removes the entry, then the record. A failure
// at each step leaves a state the next start or a repeated delete finishes.
func TestL2CircuitsDeleteStages(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	setup := func() (*L2Circuits, *fakeL2Maps, *fakeL2Store) {
		c, m, s := newTestCircuits(map[uint32]LinkID{7: l})
		if err := c.Create(circuitOn(l, 0, 100, esi1)); err != nil {
			t.Fatal(err)
		}
		return c, m, s
	}

	// The mark is not written: nothing changes.
	c, m, s := setup()
	s.failSave = 1
	if err := c.Delete(7, 0); err == nil || !strings.Contains(err.Error(), "not deleted") {
		t.Fatalf("Delete = %v", err)
	}
	if _, ok := m.entries[circuitKey{7, 0}]; !ok || s.file[0].Deleting || s.mem[0].Deleting {
		t.Errorf("after a failed mark: entry %v, record %+v", ok, s.file)
	}

	// The entry cannot be removed: the record stays marked, in memory and
	// file alike, and a repeat finishes the delete.
	c, m, s = setup()
	m.failDel = true
	if err := c.Delete(7, 0); err == nil || !strings.Contains(err.Error(), "being deleted") {
		t.Fatalf("Delete = %v", err)
	}
	if !s.file[0].Deleting || !s.mem[0].Deleting {
		t.Errorf("record after a failed map delete: %+v", s.file)
	}
	m.failDel = false
	if err := c.Delete(7, 0); err != nil || len(s.file) != 0 || len(m.entries) != 0 {
		t.Errorf("repeat: %v, saved %+v, map %v", err, s.file, m.entries)
	}

	// The record cannot be removed: the entry is gone, the record stays
	// marked; a repeat removes it.
	c, m, s = setup()
	s.failSave = 0
	writes := s.writes
	deleteWithFailingLastSave(t, c, s)
	if s.writes != writes+2 || len(m.entries) != 0 || len(s.file) != 1 || !s.file[0].Deleting || !s.mem[0].Deleting {
		t.Errorf("after a failed record removal: map %v, file %+v, mem %+v", m.entries, s.file, s.mem)
	}
	if err := c.Delete(7, 0); err != nil || len(s.file) != 0 {
		t.Errorf("repeat: %v, saved %+v", err, s.file)
	}

	// Neither a record nor an entry: not found.
	if err := c.Delete(7, 0); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("Delete of nothing = %v", err)
	}
	// An entry without a record (pinned by an older version) is removed.
	m.entries[circuitKey{8, 0}] = *l2Entry(100)
	if err := c.Delete(8, 0); err != nil || len(m.entries) != 0 {
		t.Errorf("Delete of an unsaved entry = %v, map %v", err, m.entries)
	}
}

// deleteWithFailingLastSave deletes 7/0 with the record removal failing.
func deleteWithFailingLastSave(t *testing.T, c *L2Circuits, s *fakeL2Store) {
	t.Helper()
	orig := c.maps
	c.maps = &failNextSave{l2CircuitMaps: orig, s: s}
	defer func() { c.maps = orig }()
	if err := c.Delete(7, 0); err == nil || !strings.Contains(err.Error(), "removed from the data plane") {
		t.Fatalf("Delete = %v", err)
	}
}

// failNextSave makes the save after the map delete fail.
type failNextSave struct {
	l2CircuitMaps
	s *fakeL2Store
}

func (f *failNextSave) DeleteHeadendL2(ifindex uint32, vlan uint16) error {
	f.s.failSave = 1
	return f.l2CircuitMaps.DeleteHeadendL2(ifindex, vlan)
}

// The saved circuit of a vanished name is deleted by that name; one whose
// ifindex an interface still holds is not.
func TestL2CircuitsDeleteVanished(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	links := map[uint32]LinkID{7: l}
	c, m, s := newTestCircuits(links)
	if err := c.Create(circuitOn(l, 0, 100, esi1)); err != nil {
		t.Fatal(err)
	}
	links[7] = LinkID{Name: "renamed0", Ifindex: 7, MAC: macA}
	if ok, err := c.DeleteVanished("veth0", 0); ok || err != nil {
		t.Errorf("ifindex still held: %v %v", ok, err)
	}
	delete(links, 7)
	if ok, err := c.DeleteVanished("veth0", 1); ok || err != nil {
		t.Errorf("other VLAN: %v %v", ok, err)
	}
	if ok, err := c.DeleteVanished("veth0", 0); !ok || err != nil || len(s.file) != 0 || len(m.entries) != 0 {
		t.Errorf("vanished: %v %v, saved %+v, map %v", ok, err, s.file, m.entries)
	}
}

// A flush removes saved and unsaved circuits; a failed map flush leaves the
// records marked.
func TestL2CircuitsFlush(t *testing.T) {
	l := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	c, m, s := newTestCircuits(map[uint32]LinkID{7: l})
	for _, vlan := range []uint16{0, 5} {
		if err := c.Create(circuitOn(l, vlan, 100+vlan, esi1)); err != nil {
			t.Fatal(err)
		}
	}
	m.entries[circuitKey{9, 0}] = *l2Entry(300)
	m.failWhere = true
	if _, err := c.Flush(); err == nil || !strings.Contains(err.Error(), "being deleted") {
		t.Fatalf("Flush = %v", err)
	}
	if len(s.file) != 2 || !s.file[0].Deleting || !s.file[1].Deleting {
		t.Errorf("records after a failed flush: %+v", s.file)
	}
	m.failWhere = false
	if n, err := c.Flush(); err != nil || n != 3 || len(s.file) != 0 || len(m.entries) != 0 {
		t.Errorf("Flush = %d, %v; saved %+v, map %v", n, err, s.file, m.entries)
	}
}

// The link watcher's removal takes the records of the interface with its
// entries, and a rename or new address it sees is recorded.
func TestL2CircuitsWatcher(t *testing.T) {
	a := LinkID{Name: "veth0", Ifindex: 7, MAC: macA}
	b := LinkID{Name: "veth1", Ifindex: 8, MAC: macB}
	c, m, s := newTestCircuits(map[uint32]LinkID{7: a, 8: b})
	for _, l := range []LinkID{a, b} {
		if err := c.Create(circuitOn(l, 0, 100, [bpf.ESILen]byte{})); err != nil {
			t.Fatal(err)
		}
	}
	c.follow(LinkID{Name: "veth1x", Ifindex: 8, MAC: macA})
	if s.file[1].Interface != "veth1x" || s.file[1].MAC != macA.String() || s.file[0].Interface != "veth0" {
		t.Errorf("after the rename: %+v", s.file)
	}
	writes := s.writes
	c.follow(LinkID{Name: "veth1x", Ifindex: 8, MAC: macA})
	if s.writes != writes {
		t.Error("an unchanged interface is written again")
	}
	if n, err := c.deleteWhere(func(i uint32) bool { return i == 7 }); n != 1 || err != nil {
		t.Fatalf("deleteWhere = %d, %v", n, err)
	}
	if len(s.file) != 1 || s.file[0].Ifindex != 8 || len(m.entries) != 1 {
		t.Errorf("after the deletion: saved %+v, map %v", s.file, m.entries)
	}
	// A failed write keeps the removal in memory, so the next write has it.
	s.failSave = 1
	if _, err := c.deleteWhere(func(i uint32) bool { return i == 8 }); err != nil {
		t.Fatal(err)
	}
	if len(s.mem) != 0 || len(s.file) != 1 {
		t.Errorf("mem %+v file %+v", s.mem, s.file)
	}
}

// The restore at boot, one circuit per case.
func TestL2CircuitsRestore(t *testing.T) {
	esiStr := bpf.FormatESI(esi1)
	rec := func(name string, ifindex uint32, mac net.HardwareAddr, vlan, bd uint16) netresource.ManagedL2Circuit {
		return circuitRecord(L2Circuit{Link: LinkID{Name: name, Ifindex: ifindex, MAC: mac}, VLAN: vlan, Entry: l2Entry(bd), ESI: esi1})
	}
	saved := []netresource.ManagedL2Circuit{
		rec("same0", 10, macA, 0, 100),    // restored
		rec("same0", 10, macA, 20, 200),   // restored: a second VLAN in another BD
		rec("gone0", 11, macA, 0, 100),    // the interface is gone
		rec("again0", 12, macA, 0, 100),   // made again: the name is on ifindex 22
		rec("renamed0", 13, macA, 0, 100), // ifindex 13 now has another name
		rec("reused0", 14, macA, 0, 100),  // ifindex 14 has the name, another address
		rec("del0", 15, macA, 0, 100),     // its delete had not finished
	}
	saved[6].Deleting = true
	links := map[uint32]LinkID{
		10: {Name: "same0", Ifindex: 10, MAC: macA},
		22: {Name: "again0", Ifindex: 22, MAC: macA},
		13: {Name: "other0", Ifindex: 13, MAC: macA},
		14: {Name: "reused0", Ifindex: 14, MAC: macB},
		15: {Name: "del0", Ifindex: 15, MAC: macA},
	}
	for _, pinned := range []bool{false, true} {
		c, m, s := newTestCircuits(links)
		s.mem, s.file = clone(saved), clone(saved)
		if pinned {
			// What the maps kept: the circuits without their ESI, and one
			// written by a version that did not save circuits.
			for _, r := range saved {
				e, _, _ := circuitEntry(r)
				m.entries[circuitKey{r.Ifindex, r.VLAN}] = *e
			}
			m.entries[circuitKey{30, 0}] = *l2Entry(100)
		}
		if err := c.restore(); err != nil {
			t.Fatalf("pinned=%v: restore: %v", pinned, err)
		}
		want := map[circuitKey]bool{{10, 0}: true, {10, 20}: true}
		if pinned {
			want[circuitKey{30, 0}] = true
		}
		got := map[circuitKey]bool{}
		for k := range m.entries {
			got[k] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("pinned=%v: entries %v, want %v", pinned, got, want)
		}
		if m.esi[circuitKey{10, 0}] != esi1 || m.esi[circuitKey{10, 20}] != esi1 {
			t.Errorf("pinned=%v: ESI not restored: %v", pinned, m.esi)
		}
		if m.entries[circuitKey{10, 20}].BdId != 200 {
			t.Errorf("pinned=%v: VLAN 20 is in BD %d", pinned, m.entries[circuitKey{10, 20}].BdId)
		}
		if len(s.file) != 2 || s.file[0].Interface != "same0" || s.file[1].Interface != "same0" || s.file[0].ESI != esiStr {
			t.Errorf("pinned=%v: kept %+v", pinned, s.file)
		}
	}
}

// A record set that does not decode, or names one key twice, stops the
// start; so does a lookup that fails.
func TestL2CircuitsRestoreRefuses(t *testing.T) {
	good := circuitRecord(circuitOn(LinkID{Name: "a", Ifindex: 1, MAC: macA}, 0, 100, esi1))
	bad := good
	bad.Mode = "nope"
	for name, recs := range map[string][]netresource.ManagedL2Circuit{
		"bad mode":  {bad},
		"duplicate": {good, good},
	} {
		c, m, s := newTestCircuits(map[uint32]LinkID{1: {Name: "a", Ifindex: 1, MAC: macA}})
		s.mem = recs
		if err := c.restore(); err == nil {
			t.Errorf("%s: restore accepted", name)
		}
		if len(m.entries) != 0 {
			t.Errorf("%s: wrote %v before refusing", name, m.entries)
		}
	}
	c, _, s := newTestCircuits(nil)
	c.linkByIndex = func(uint32) (LinkID, bool, error) { return LinkID{}, false, errors.New("netlink down") }
	s.mem = []netresource.ManagedL2Circuit{good}
	if err := c.restore(); err == nil {
		t.Error("restore guessed past a failed lookup")
	}
}
