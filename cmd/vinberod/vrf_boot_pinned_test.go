package main

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/vrf"
	"go.uber.org/zap"
)

// fakePinned stands in for the pinned maps keyed by a vrf_id: the highest
// id they hold, and per id how many headend entries and owner records.
type fakePinned struct {
	highest uint32
	headend map[uint32]int
	order   []string
}

func (f *fakePinned) HighestVRFIDInUse() (uint32, error) {
	f.order = append(f.order, "scan")
	return f.highest, nil
}

func (f *fakePinned) PurgeHeadendVRFs(keep func(uint32) bool) (map[uint32]int, error) {
	f.order = append(f.order, "purge")
	out := map[uint32]int{}
	for id, n := range f.headend {
		if id != 0 && !keep(id) {
			out[id] = n
			delete(f.headend, id)
		}
	}
	return out, nil
}

// A config-origin VRF the config dropped takes its headend entries with
// it, whoever owns them, and so does a vrf_id the state file does not
// record. The VRFs that stay keep theirs, and the global VRF is not
// touched. Both happen before the ingress map is written, which comes
// after every allocation.
func TestRestoreVRFs_RemovesHeadendsOfVRFsThatDoNotExist(t *testing.T) {
	resMgr := resourceManagerWith(t, `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":4,"entries":[
		{"name":"cfg-old","vrf_id":1,"config":true},
		{"name":"api","vrf_id":2}]}}`)
	pinned := &fakePinned{highest: 3, headend: map[uint32]int{0: 4, 1: 2, 2: 1, 3: 5}}
	mgr := vrf.NewManager()
	prog := &recordingProg{}
	prog.onWrite = func() {
		if len(pinned.order) != 2 {
			t.Errorf("ingress map written before the scan and the purge: %v", pinned.order)
		}
	}
	if err := restoreVRFs(config.VRFsConfig{}, nil, false, mgr, prog, pinned, resMgr, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Get("cfg-old"); ok {
		t.Fatal("undeclared config VRF restored")
	}
	if len(pinned.headend) != 2 || pinned.headend[0] != 4 || pinned.headend[2] != 1 {
		t.Errorf("headend entries left = %v, want the global VRF's and api's", pinned.headend)
	}
}

// A state file that was lost does not hand a vrf_id that still keys pinned
// state to a new VRF: the allocator starts above every id in use.
func TestRestoreVRFs_AllocatesAboveIDsInThePinnedMaps(t *testing.T) {
	resMgr := resourceManagerWith(t, `{"vrfs":[],"bridges":[]}`)
	pinned := &fakePinned{highest: 7, headend: map[uint32]int{7: 1}}
	mgr := vrf.NewManager()
	if err := restoreVRFs(config.VRFsConfig{}, []string{"a", "b"}, true, mgr, &recordingProg{}, pinned, resMgr, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	a, _ := mgr.IDForName("a")
	b, _ := mgr.IDForName("b")
	if a != 8 || b != 9 {
		t.Errorf("ids a=%d b=%d, want 8 and 9 (above the pinned id 7)", a, b)
	}
	if len(pinned.headend) != 0 {
		t.Errorf("entries of the forgotten vrf_id 7 left: %v", pinned.headend)
	}
}
