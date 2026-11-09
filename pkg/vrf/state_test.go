package vrf

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
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

// A next id behind the saved ids must not hand one of them out again.
func TestState_RestoreNextIDIsAboveEverySavedID(t *testing.T) {
	m := restart(t, State{NextID: 2, VRFs: []PersistedVRF{{Name: "a", ID: 7}}})
	if id := m.Ensure("b").ID; id != 8 {
		t.Errorf("next id = %d, want 8", id)
	}
	// A file from before ids were recorded starts the allocator at 1.
	if id := restart(t, State{}).Ensure("b").ID; id != 1 {
		t.Errorf("next id on an empty state = %d, want 1", id)
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
