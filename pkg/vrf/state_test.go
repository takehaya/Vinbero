package vrf

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type fakeStore struct {
	saved []State
	err   error
}

func (f *fakeStore) SaveVRFState(s State) error {
	if f.err != nil {
		return f.err
	}
	f.saved = append(f.saved, s)
	return nil
}

func (f *fakeStore) last(t *testing.T) State {
	t.Helper()
	if len(f.saved) == 0 {
		t.Fatal("nothing saved")
	}
	return f.saved[len(f.saved)-1]
}

// restart runs what a daemon restart does to the manager: a fresh one, loaded
// from what the old one saved.
func restart(t *testing.T, s State) *Manager {
	t.Helper()
	m := NewManager()
	if err := m.Restore(s); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	return m
}

func addRuntimeAC(t *testing.T, m *Manager, name string, ac AC) {
	t.Helper()
	if _, err := m.AddAC(name, ac); err != nil {
		t.Fatalf("AddAC: %v", err)
	}
	m.MarkRuntimeAC(name, ac)
}

// Ids survive a restart whatever order the next run touches the VRFs in, and
// an id retired by a delete stays retired across the restart.
func TestState_IDsAreStableAndMonotonicAcrossRestart(t *testing.T) {
	store := &fakeStore{}
	m := NewManager()
	m.SetStore(store)
	a := m.Ensure("a")
	b := m.Ensure("b")
	c := m.Ensure("c")
	m.Delete("c")
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := restart(t, store.last(t))
	// The other order, which would swap the ids if they were allocated anew.
	if got := m2.Ensure("b"); got.ID != b.ID {
		t.Errorf("b after restart = %d, want %d", got.ID, b.ID)
	}
	if got := m2.Ensure("a"); got.ID != a.ID {
		t.Errorf("a after restart = %d, want %d", got.ID, a.ID)
	}
	if d := m2.Ensure("d"); d.ID <= c.ID {
		t.Errorf("new VRF after restart got %d, want above the retired %d", d.ID, c.ID)
	}
}

// A runtime AC comes back and is still treated as one: vanished means skipped.
func TestState_RuntimeACsSurviveRestart(t *testing.T) {
	store := &fakeStore{}
	m := NewManager()
	m.SetStore(store)
	addRuntimeAC(t, m, "tenant", AC{"veth1", 0})
	addRuntimeAC(t, m, "tenant", AC{"veth2", 100})
	if _, err := m.AddAC("tenant", AC{"eth1", 0}); err != nil { // config-declared
		t.Fatalf("AddAC: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st := store.last(t)
	want := []AC{{"veth1", 0}, {"veth2", 100}}
	if len(st.VRFs) != 1 || !reflect.DeepEqual(st.VRFs[0].RuntimeACs, want) {
		t.Fatalf("saved = %+v, want only the runtime ACs %v", st, want)
	}

	m2 := restart(t, st)
	v, ok := m2.Get("tenant")
	if !ok || !reflect.DeepEqual(v.ACs, want) {
		t.Fatalf("restored = %+v, want ACs %v", v, want)
	}
	if !m2.IsRuntimeAC("tenant", AC{"veth1", 0}) {
		t.Error("restored AC is not marked runtime")
	}
	fp := &fakeProg{}
	res := func(n string) (uint32, error) {
		if n == "veth2" {
			return 22, nil
		}
		return 0, fmt.Errorf("%w: %s", ErrInterfaceGone, n)
	}
	if err := m2.Reconcile(res, fp); err != nil {
		t.Fatalf("Reconcile with a vanished restored AC: %v", err)
	}
	if got := fp.mapping[bpf.IngressACKey{Ifindex: 22, VlanId: 100}]; got != v.ID || len(fp.mapping) != 1 {
		t.Errorf("mapping = %v, want only veth2 -> %d", fp.mapping, v.ID)
	}
	if !fp.enabled {
		t.Error("front door not enabled by restored ACs")
	}
	// It stays recorded until its owner removes it.
	if got, _ := m2.Get("tenant"); len(got.ACs) != 2 {
		t.Errorf("vanished AC dropped: %+v", got.ACs)
	}
}

// A config-declared AC whose interface does not resolve stays fatal, also when
// the state file had recorded it as a runtime AC.
func TestState_ConfigTakesOverRuntimeAC(t *testing.T) {
	ac := AC{"veth1", 0}
	m := restart(t, State{NextID: 3, VRFs: []PersistedVRF{
		{Name: "old", ID: 1, RuntimeACs: []AC{ac}},
		{Name: "new", ID: 2},
	}})
	owner, released := m.ReleaseRuntimeAC(ac)
	if !released || owner != "old" {
		t.Fatalf("ReleaseRuntimeAC = %q, %v", owner, released)
	}
	if _, err := m.AddAC("new", ac); err != nil {
		t.Fatalf("AddAC after the release: %v", err)
	}
	if m.IsRuntimeAC("new", ac) {
		t.Error("taken-over AC is still runtime")
	}
	gone := func(n string) (uint32, error) { return 0, fmt.Errorf("%w: %s", ErrInterfaceGone, n) }
	if err := m.Reconcile(gone, &fakeProg{}); err == nil {
		t.Error("unresolved config-declared AC did not fail Reconcile")
	}
	if _, released := m.ReleaseRuntimeAC(AC{"other", 0}); released {
		t.Error("released an AC nobody holds")
	}
}

func TestState_RestoreRefusesContradictions(t *testing.T) {
	for name, tc := range map[string]struct {
		st   State
		want string
	}{
		"no name":        {State{VRFs: []PersistedVRF{{ID: 1}}}, "without a name"},
		"tenant with 0":  {State{VRFs: []PersistedVRF{{Name: "a"}}}, "belongs to"},
		"global with 1":  {State{VRFs: []PersistedVRF{{Name: GlobalVRFName, ID: 1}}}, "belongs to"},
		"duplicate name": {State{VRFs: []PersistedVRF{{Name: "a", ID: 1}, {Name: "a", ID: 2}}}, "twice"},
		"duplicate id":   {State{VRFs: []PersistedVRF{{Name: "a", ID: 1}, {Name: "b", ID: 1}}}, "also held"},
		"shared ac": {State{VRFs: []PersistedVRF{
			{Name: "a", ID: 1, RuntimeACs: []AC{{"v", 0}}},
			{Name: "b", ID: 2, RuntimeACs: []AC{{"v", 0}}},
		}}, "also held"},
		"bad vlan": {State{VRFs: []PersistedVRF{{Name: "a", ID: 1, RuntimeACs: []AC{{"v", 4096}}}}}, "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			m := NewManager()
			err := m.Restore(tc.st)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Restore = %v, want an error about %q", err, tc.want)
			}
			if len(m.List()) != 0 {
				t.Errorf("partial restore left %+v", m.List())
			}
		})
	}
	m := NewManager()
	m.Ensure("a")
	if err := m.Restore(State{}); err == nil {
		t.Error("Restore on a used manager succeeded")
	}
}

// A saved id at or above the watermark would be handed out again, so the
// state is refused; that covers an id with no successor (MaxUint32) too.
func TestState_RestoreRefusesAnIDAtOrAboveTheWatermark(t *testing.T) {
	for name, st := range map[string]State{
		"watermark below an id": {NextID: 2, VRFs: []PersistedVRF{{Name: "a", ID: 7}}},
		"watermark at an id":    {NextID: 7, VRFs: []PersistedVRF{{Name: "a", ID: 7}}},
		"no watermark":          {VRFs: []PersistedVRF{{Name: "a", ID: 1}}},
		"last uint32":           {NextID: 2, VRFs: []PersistedVRF{{Name: "a", ID: 1}, {Name: "b", ID: math.MaxUint32}}},
	} {
		t.Run(name, func(t *testing.T) {
			m := NewManager()
			if err := m.Restore(st); err == nil || !strings.Contains(err.Error(), "next_vrf_id") {
				t.Fatalf("Restore = %v, want a next_vrf_id error", err)
			}
			if len(m.List()) != 0 {
				t.Errorf("partial restore left %+v", m.List())
			}
		})
	}
	m := restart(t, State{NextID: 8, VRFs: []PersistedVRF{{Name: "a", ID: 7}}})
	if id := m.Ensure("b").ID; id != 8 {
		t.Errorf("next id = %d, want 8", id)
	}
	// A file from before ids were recorded starts the allocator at 1.
	if id := restart(t, State{}).Ensure("b").ID; id != 1 {
		t.Errorf("next id on an empty state = %d, want 1", id)
	}
}

// A VRF the boot-time load created comes back only while the config declares
// it or something still holds it. One created over the API stays until it is
// deleted. A dropped VRF's id is not handed out again.
func TestState_FinishRestoreDropsConfigVRFsNothingHolds(t *testing.T) {
	store := &fakeStore{}
	m := NewManager()
	m.SetStore(store)
	m.Ensure("cfg-kept")
	m.Ensure("cfg-gone")
	addRuntimeAC(t, m, "cfg-with-ac", AC{"veth1", 0})
	if _, err := m.SetBridge("legacy-br", Bridge{Name: "legacy-br", BdID: 10}); err != nil {
		t.Fatal(err)
	}
	if dropped := m.FinishRestore([]string{"cfg-kept", "cfg-gone", "cfg-with-ac"}); len(dropped) != 0 {
		t.Fatalf("first boot dropped %v", dropped)
	}
	api := m.Ensure("api") // after the boot-time load
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	st := store.last(t)
	for _, p := range st.VRFs {
		if p.Config != (p.Name != "api") {
			t.Errorf("%s saved with Config=%v", p.Name, p.Config)
		}
	}

	// Next boot: the config dropped every entry, and the bridge record moved
	// to its real VRF.
	m2 := restart(t, st)
	if _, err := m2.SetBridge("tenant", Bridge{Name: "legacy-br", BdID: 10}); err != nil {
		t.Fatal(err)
	}
	dropped := m2.FinishRestore(nil)
	if want := []string{"cfg-gone", "cfg-kept", "legacy-br"}; !reflect.DeepEqual(dropped, want) {
		t.Errorf("dropped = %v, want %v", dropped, want)
	}
	for _, name := range []string{"cfg-with-ac", "api", "tenant"} {
		if _, ok := m2.Get(name); !ok {
			t.Errorf("%s not kept", name)
		}
	}
	if id := m2.Ensure("new").ID; id <= api.ID {
		t.Errorf("new VRF got %d, want above every earlier id (last %d)", id, api.ID)
	}
	if !m2.RestoreDone() {
		t.Error("RestoreDone after FinishRestore = false")
	}
}

// A delete whose save failed is reported as unsaved until a save succeeds.
func TestState_UnsavedDeleteUntilTheNextSave(t *testing.T) {
	store := &fakeStore{err: errors.New("disk full")}
	m := NewManager()
	m.SetStore(store)
	m.Ensure("a")
	m.Delete("a")
	if err := m.Save(); err == nil {
		t.Fatal("Save hid the store's error")
	}
	if !m.UnsavedDelete("a") || m.UnsavedDelete("b") {
		t.Fatalf("UnsavedDelete(a)=%v (b)=%v", m.UnsavedDelete("a"), m.UnsavedDelete("b"))
	}
	store.err = nil
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if m.UnsavedDelete("a") {
		t.Error("still unsaved after a successful save")
	}
	if len(store.last(t).VRFs) != 0 {
		t.Errorf("saved %+v, want the VRF gone", store.last(t))
	}
	// Recreating the name ends the pending delete as well.
	m.Delete("b")
	m.Ensure("b")
	if m.UnsavedDelete("b") {
		t.Error("recreated VRF still counts as deleted")
	}
}

// A restored AC whose interface is gone is warned about once, not on every
// reconcile, and again when it disappears a second time.
func TestState_GoneRuntimeACWarnsOnce(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	m := restart(t, State{NextID: 2, VRFs: []PersistedVRF{{Name: "a", ID: 1, RuntimeACs: []AC{{"veth1", 0}}}}})
	m.SetLogger(zap.New(core))
	present := false
	res := func(n string) (uint32, error) {
		if present {
			return 5, nil
		}
		return 0, fmt.Errorf("%w: %s", ErrInterfaceGone, n)
	}
	for range 3 {
		if err := m.Reconcile(res, &fakeProg{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := logs.Len(); n != 1 {
		t.Fatalf("warnings after three reconciles = %d, want 1", n)
	}
	present = true
	if err := m.Reconcile(res, &fakeProg{}); err != nil {
		t.Fatal(err)
	}
	present = false
	if err := m.Reconcile(res, &fakeProg{}); err != nil {
		t.Fatal(err)
	}
	if n := logs.Len(); n != 2 {
		t.Errorf("warnings after the interface came and went = %d, want 2", n)
	}
}

func TestSave_OnlyWhenChangedAndRetriesAfterFailure(t *testing.T) {
	store := &fakeStore{err: errors.New("disk full")}
	m := NewManager()
	if err := m.Save(); err != nil {
		t.Fatalf("Save without a store: %v", err)
	}
	m.SetStore(store)
	m.Ensure("a")
	if err := m.Save(); err == nil {
		t.Fatal("Save hid the store's error")
	}
	store.err = nil
	if err := m.Save(); err != nil {
		t.Fatalf("Save after the disk recovered: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saves = %d, want 1 retry", len(store.saved))
	}
	m.Ensure("a") // already exists: nothing new to write
	if err := m.Save(); err != nil || len(store.saved) != 1 {
		t.Errorf("unchanged Save wrote again: %v, %d", err, len(store.saved))
	}
	// A restored manager has nothing to write until something changes.
	m2 := restart(t, store.last(t))
	m2.SetStore(store)
	if err := m2.Save(); err != nil || len(store.saved) != 1 {
		t.Errorf("Save right after Restore wrote: %v, %d", err, len(store.saved))
	}
}
