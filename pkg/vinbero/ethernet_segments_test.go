package vinbero

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

// fakeEsiMap is esi_map in memory; it is empty at every start, as the map
// is not pinned.
type fakeEsiMap map[[bpf.ESILen]byte]bpf.EsiEntry

func (f fakeEsiMap) CreateEsi(esi [bpf.ESILen]byte, e *bpf.EsiEntry) error {
	f[esi] = *e
	return nil
}

func (f fakeEsiMap) DeleteEsi(esi [bpf.ESILen]byte) error {
	if _, ok := f[esi]; !ok {
		return fmt.Errorf("failed to delete esi entry: %w", ebpf.ErrKeyNotExist)
	}
	delete(f, esi)
	return nil
}

func (f fakeEsiMap) GetEsi(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error) {
	e, ok := f[esi]
	if !ok {
		return nil, fmt.Errorf("failed to lookup esi entry: %w", ebpf.ErrKeyNotExist)
	}
	return &e, nil
}

func (f fakeEsiMap) SetEsiDfPe(esi [bpf.ESILen]byte, df [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error) {
	e, ok := f[esi]
	if !ok {
		return nil, fmt.Errorf("failed to lookup esi entry: %w", ebpf.ErrKeyNotExist)
	}
	e.DfPeSrcAddr = df
	f[esi] = e
	return &e, nil
}

var esi2 = [bpf.ESILen]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 2}

func esEntry(local bool, mode uint8, localPE, df string) *bpf.EsiEntry {
	l, _ := bpf.ParseIPv6(localPE)
	d, _ := bpf.ParseIPv6(df)
	return bpf.NewEsiEntry(bpf.EsiConfig{LocalAttached: local, RedundancyMode: mode, LocalPeSrcAddr: l, DfPeSrcAddr: d})
}

// boot starts the segment book from the state file at path, the way
// InitResourceManager does, with an empty esi_map.
func bootSegments(t *testing.T, path string) (*EthernetSegments, fakeEsiMap, *netresource.ResourceManager) {
	t.Helper()
	res, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m := fakeEsiMap{}
	s := NewEthernetSegments(m, res, zap.NewNop())
	if err := s.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	return s, m, res
}

// breakStateFile makes the next writes of the state file fail, also as root.
func breakStateFile(t *testing.T, path string) func() {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// A segment comes back after a restart as it was created, its operator DF
// and RD included; a deleted one does not.
func TestEthernetSegmentsRestartRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _, _ := bootSegments(t, path)
	if err := s.Create(esi1, esEntry(true, 2, "fc00:1::1", ""), "65000:1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(esi2, esEntry(false, 7, "", ""), ""); err != nil {
		t.Fatal(err)
	}
	df, _ := bpf.ParseIPv6("fc00:2::2")
	if _, err := s.SetDF(esi1, df); err != nil {
		t.Fatal(err)
	}
	_, m, res := bootSegments(t, path)
	if want := *esEntry(true, 2, "fc00:1::1", "fc00:2::2"); m[esi1] != want {
		t.Errorf("esi1 after restart = %+v, want %+v", m[esi1], want)
	}
	if want := *esEntry(false, 7, "", ""); m[esi2] != want {
		t.Errorf("esi2 (a mode the enum does not name) after restart = %+v, want %+v", m[esi2], want)
	}
	recs := res.EthernetSegments()
	if len(recs) != 2 || recs[0].RD != "65000:1" || recs[0].RedundancyMode != "ESI_REDUNDANCY_MODE_ALL_ACTIVE" || recs[1].RedundancyMode != "7" {
		t.Errorf("records = %+v", recs)
	}

	s2 := NewEthernetSegments(m, res, zap.NewNop())
	if _, err := s2.SetDF(esi1, [bpf.IPv6AddrLen]byte{}); err != nil {
		t.Fatal(err)
	}
	if existed, err := s2.Delete(esi2); err != nil || !existed {
		t.Fatalf("delete: existed=%v err=%v", existed, err)
	}
	if existed, err := s2.Delete(esi2); err != nil || existed {
		t.Fatalf("second delete: existed=%v err=%v", existed, err)
	}
	_, m, _ = bootSegments(t, path)
	if _, ok := m[esi2]; ok || len(m) != 1 {
		t.Errorf("after delete and restart: %+v", m)
	}
	if m[esi1].DfPeSrcAddr != ([bpf.IPv6AddrLen]byte{}) {
		t.Errorf("a cleared DF came back: %+v", m[esi1])
	}
}

// A create, delete or DF change whose save fails changes neither the map
// nor the file, and the same call made again succeeds and is written.
func TestEthernetSegmentsSaveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, m, res := bootSegments(t, path)
	first := esEntry(true, 2, "fc00:1::1", "")
	if err := s.Create(esi1, first, "65000:1"); err != nil {
		t.Fatal(err)
	}
	before := res.EthernetSegments()

	repair := breakStateFile(t, path)
	if err := s.Create(esi2, esEntry(true, 2, "fc00:1::1", ""), ""); err == nil {
		t.Fatal("a create whose save failed succeeded")
	}
	if err := s.Create(esi1, esEntry(false, 1, "", ""), "65000:9"); err == nil {
		t.Fatal("an overwrite whose save failed succeeded")
	}
	if existed, err := s.Delete(esi1); err == nil || existed {
		t.Fatalf("a delete whose save failed: existed=%v err=%v", existed, err)
	}
	df, _ := bpf.ParseIPv6("fc00:2::2")
	if _, err := s.SetDF(esi1, df); err == nil {
		t.Fatal("a DF change whose save failed succeeded")
	}
	if _, ok := m[esi2]; ok || len(m) != 1 || m[esi1] != *first {
		t.Errorf("map after failed changes = %+v", m)
	}
	if got := res.EthernetSegments(); !reflect.DeepEqual(got, before) {
		t.Errorf("record after failed changes = %+v, want %+v", got, before)
	}
	repair()

	// The same overwrite again: written although the record in memory did
	// not change since the last write that succeeded.
	if err := s.Create(esi1, first, "65000:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the retried create was not written: %v", err)
	}
	if err := s.Create(esi2, esEntry(true, 2, "fc00:1::1", ""), ""); err != nil {
		t.Fatal(err)
	}
	_, m, _ = bootSegments(t, path)
	if len(m) != 2 {
		t.Errorf("after retries and restart: %+v", m)
	}
}

// esi_map is not pinned, so a daemon killed between the map write and the
// file write starts with what the file has: a create the RPC did not
// confirm is gone, a delete it did not confirm is undone.
func TestEthernetSegmentsKilledBetweenMapAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, m, _ := bootSegments(t, path)
	if err := s.Create(esi1, esEntry(true, 2, "fc00:1::1", ""), ""); err != nil {
		t.Fatal(err)
	}
	// The map writes of a create of esi2 and a delete of esi1, then the kill.
	_ = m.CreateEsi(esi2, esEntry(true, 2, "fc00:1::1", ""))
	_ = m.DeleteEsi(esi1)
	_, m, _ = bootSegments(t, path)
	if _, ok := m[esi1]; !ok || len(m) != 1 {
		t.Errorf("after the kill and restart: %+v", m)
	}
}

// A segment names no interface: it comes back whether or not the circuits
// on it do. A circuit whose interface vanished is dropped by its own rule
// and the segment stays, as it does when the interface goes while running.
func TestEthernetSegmentsRestoreWithVanishedCircuit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _, res := bootSegments(t, path)
	if err := s.Create(esi1, esEntry(true, 2, "fc00:1::1", ""), ""); err != nil {
		t.Fatal(err)
	}
	gone := LinkID{Name: "gone0", Ifindex: 11, MAC: macA}
	kept := LinkID{Name: "kept0", Ifindex: 12, MAC: macA}
	if err := res.SaveL2Circuits([]netresource.ManagedL2Circuit{
		circuitRecord(circuitOn(gone, 0, 100, esi1)),
		circuitRecord(circuitOn(kept, 0, 100, esi1)),
	}); err != nil {
		t.Fatal(err)
	}

	_, m, res := bootSegments(t, path)
	c := NewL2Circuits(newFakeL2Maps(), res, zap.NewNop())
	l2 := c.maps.(*fakeL2Maps)
	c.linkByIndex = func(ifindex uint32) (LinkID, bool, error) {
		if ifindex == kept.Ifindex {
			return kept, true, nil
		}
		return LinkID{}, false, nil
	}
	if err := c.restore(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[esi1]; !ok {
		t.Error("the segment was not restored")
	}
	if _, ok := l2.entries[circuitKey{11, 0}]; ok {
		t.Error("the circuit of the vanished interface was restored")
	}
	if l2.esi[circuitKey{12, 0}] != esi1 {
		t.Errorf("the circuit on the segment lost its ESI: %v", l2.esi)
	}
	if len(res.L2Circuits()) != 1 || len(res.EthernetSegments()) != 1 {
		t.Errorf("records: circuits %+v segments %+v", res.L2Circuits(), res.EthernetSegments())
	}
}

// A record that does not decode, or a second one of an ESI, stops the start.
func TestEthernetSegmentsRestoreRefuses(t *testing.T) {
	for _, recs := range [][]netresource.ManagedEthernetSegment{
		{{ESI: "01:02", RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE"}},
		{{ESI: "00:00:00:00:00:00:00:00:00:00", RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE"}},
		{{ESI: bpf.FormatESI(esi1), RedundancyMode: "ESI_REDUNDANCY_MODE_NOPE"}},
		{{ESI: bpf.FormatESI(esi1), RedundancyMode: "300"}},
		{{ESI: bpf.FormatESI(esi1), RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE", LocalPeSrcAddr: "nope"}},
		{
			{ESI: bpf.FormatESI(esi1), RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE"},
			{ESI: bpf.FormatESI(esi1), RedundancyMode: "ESI_REDUNDANCY_MODE_SINGLE_ACTIVE"},
		},
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		res, err := netresource.NewResourceManager(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		if err := res.SaveEthernetSegments(recs); err != nil {
			t.Fatal(err)
		}
		m := fakeEsiMap{}
		if err := NewEthernetSegments(m, res, zap.NewNop()).restore(); err == nil {
			t.Errorf("%+v: restored", recs)
		}
		if len(m) != 0 {
			t.Errorf("%+v: wrote %+v before refusing", recs, m)
		}
	}
}

// A map that cannot be read leaves the segment as it was.
func TestEthernetSegmentsCreateReadFailure(t *testing.T) {
	s := NewEthernetSegments(failingGet{fakeEsiMap{}}, nil, zap.NewNop())
	if err := s.Create(esi1, esEntry(true, 2, "fc00:1::1", ""), ""); err == nil {
		t.Fatal("create without reading the previous entry succeeded")
	}
}

type failingGet struct{ fakeEsiMap }

func (failingGet) GetEsi([bpf.ESILen]byte) (*bpf.EsiEntry, error) {
	return nil, errors.New("injected read failure")
}
