package vrf

import (
	"fmt"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

type fakeProg struct {
	mapping     map[bpf.IngressACKey]uint32
	enabled     bool
	defaultDeny bool
	denyAction  uint8
}

func (f *fakeProg) SetIngressVrf(m map[bpf.IngressACKey]uint32) error {
	f.mapping = m
	return nil
}
func (f *fakeProg) SetIngressPolicy(enabled, defaultDeny bool, denyAction uint8) error {
	f.enabled, f.defaultDeny, f.denyAction = enabled, defaultDeny, denyAction
	return nil
}

func resolver(names map[string]uint32) func(string) (uint32, error) {
	return func(n string) (uint32, error) {
		if idx, ok := names[n]; ok {
			return idx, nil
		}
		return 0, fmt.Errorf("no such interface %q", n)
	}
}

// Ensure allocates a stable id per name; distinct names get distinct ids; the
// global VRF is id 0 (not a stored VRF).
func TestManager_EnsureAndID(t *testing.T) {
	m := NewManager()
	a := m.Ensure("a")
	b := m.Ensure("b")
	if a.ID == GlobalVRFID || b.ID == GlobalVRFID || a.ID == b.ID {
		t.Fatalf("ids a=%d b=%d, want distinct non-zero", a.ID, b.ID)
	}
	if a2 := m.Ensure("a"); a2.ID != a.ID {
		t.Errorf("Ensure(a) id = %d, want stable %d", a2.ID, a.ID)
	}
	if id, ok := m.IDForName("a"); !ok || id != a.ID {
		t.Errorf("IDForName(a) = %d,%t want %d,true", id, ok, a.ID)
	}
	if _, ok := m.IDForName("ghost"); ok {
		t.Errorf("IDForName(ghost) ok = true, want false (global VRF)")
	}
	if v, ok := m.ByID(a.ID); !ok || v.Name != "a" {
		t.Errorf("ByID(%d) = %+v,%t want a", a.ID, v, ok)
	}
}

// Delete recycles the id for the next Ensure.
func TestManager_DeleteRecyclesID(t *testing.T) {
	m := NewManager()
	a := m.Ensure("a")
	m.Delete("a")
	if _, ok := m.IDForName("a"); ok {
		t.Error("IDForName(a) after delete: want absent")
	}
	c := m.Ensure("c")
	if c.ID != a.ID {
		t.Errorf("recycled id = %d, want %d", c.ID, a.ID)
	}
}

func TestManager_AC(t *testing.T) {
	m := NewManager()
	if added, err := m.AddAC("v", AC{"eth1", 100}); err != nil || !added {
		t.Fatalf("AddAC = (added %v, %v), want (true, nil)", added, err)
	}
	if added, err := m.AddAC("v", AC{"eth1", 100}); err != nil || added { // idempotent
		t.Fatalf("AddAC idempotent = (added %v, %v), want (false, nil)", added, err)
	}
	if added, _ := m.AddAC("v", AC{"eth2", 0}); !added {
		t.Fatalf("AddAC new ac: added = false, want true")
	}
	got := m.List()
	if len(got) != 1 || len(got[0].ACs) != 2 {
		t.Fatalf("List = %+v, want 1 vrf with 2 acs", got)
	}
	if got[0].ACs[0] != (AC{"eth1", 100}) || got[0].ACs[1] != (AC{"eth2", 0}) {
		t.Errorf("ACs = %+v, want sorted", got[0].ACs)
	}
	if removed := m.RemoveAC("v", AC{"eth1", 100}); !removed {
		t.Errorf("RemoveAC present ac: removed = false, want true")
	}
	if removed := m.RemoveAC("v", AC{"eth1", 100}); removed { // idempotent
		t.Errorf("RemoveAC absent ac: removed = true, want false")
	}
	if got := m.List(); len(got[0].ACs) != 1 || got[0].ACs[0] != (AC{"eth2", 0}) {
		t.Errorf("after RemoveAC ACs = %+v, want [eth2.0]", got[0].ACs)
	}
}

func TestManager_ACValidation(t *testing.T) {
	m := NewManager()
	if _, err := m.AddAC("", AC{"eth1", 0}); err == nil {
		t.Error("empty name: want error")
	}
	if _, err := m.AddAC("v", AC{"", 0}); err == nil {
		t.Error("empty interface: want error")
	}
	if _, err := m.AddAC("v", AC{"eth1", 4096}); err == nil {
		t.Error("vlan 4096: want error")
	}
}

// An AC belongs to exactly one VRF: re-adding it to the same VRF is idempotent,
// but adding it to a different VRF is rejected (so Reconcile can never build a
// colliding {ifindex, vlan} key).
func TestManager_AC_NoCrossVRFDuplicate(t *testing.T) {
	m := NewManager()
	if _, err := m.AddAC("a", AC{"eth1", 100}); err != nil {
		t.Fatalf("AddAC a: %v", err)
	}
	if added, err := m.AddAC("a", AC{"eth1", 100}); err != nil || added {
		t.Errorf("re-add to same VRF should be idempotent no-op, got (added %v, %v)", added, err)
	}
	if _, err := m.AddAC("b", AC{"eth1", 100}); err == nil {
		t.Error("adding an AC owned by another VRF: want error")
	}
	// b must not have been mutated by the rejected add.
	if _, ok := m.IDForName("b"); ok {
		// Ensure-on-reject would be surprising; b should not exist yet.
		if got := len(m.List()); got != 1 {
			t.Errorf("rejected cross-VRF AC created a VRF; List len = %d, want 1", got)
		}
	}
}

// Ensure and ByID return ACs that do not alias the manager's internal slice,
// so a caller mutating the returned ACs cannot corrupt stored state.
func TestManager_ReturnedACsAreCopies(t *testing.T) {
	m := NewManager()
	_, _ = m.AddAC("v", AC{"eth1", 100})

	got := m.Ensure("v")
	if len(got.ACs) != 1 {
		t.Fatalf("Ensure ACs = %+v, want one", got.ACs)
	}
	got.ACs[0] = AC{"hacked", 4095} // mutate the returned slice

	id, _ := m.IDForName("v")
	byID, _ := m.ByID(id)
	if len(byID.ACs) != 1 || byID.ACs[0] != (AC{"eth1", 100}) {
		t.Errorf("internal ACs were corrupted via the returned slice: %+v", byID.ACs)
	}
	// Mutating ByID's result must likewise not leak back.
	byID.ACs[0] = AC{"hacked2", 4094}
	if again, _ := m.ByID(id); again.ACs[0] != (AC{"eth1", 100}) {
		t.Errorf("ByID result aliases internal state: %+v", again.ACs)
	}
}

// The reserved global VRF name maps ACs to vrf_id 0 (the underlay): under
// default-deny those ACs get an explicit {ifindex, vlan} -> 0 entry so they
// pass, while a tenant VRF keeps a non-zero id. The id 0 is never recycled.
func TestManager_GlobalVRFAC(t *testing.T) {
	m := NewManager()
	if added, err := m.AddAC(GlobalVRFName, AC{"eth3", 0}); err != nil || !added {
		t.Fatalf("AddAC global = (added %v, %v), want (true, nil)", added, err)
	}
	if id, ok := m.IDForName(GlobalVRFName); !ok || id != GlobalVRFID {
		t.Fatalf("IDForName(global) = (%d, %v), want (0, true)", id, ok)
	}
	// A tenant VRF still gets a non-zero id, distinct from the global VRF.
	if _, err := m.AddAC("tenant", AC{"eth1", 100}); err != nil {
		t.Fatalf("AddAC tenant: %v", err)
	}
	if id, _ := m.IDForName("tenant"); id == GlobalVRFID {
		t.Errorf("tenant VRF got the global id 0")
	}
	// Reconcile programs the global AC as an explicit -> 0 entry.
	fp := &fakeProg{}
	if err := m.Reconcile(resolver(map[string]uint32{"eth3": 13, "eth1": 11}), fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if v, ok := fp.mapping[bpf.IngressACKey{Ifindex: 13, VlanId: 0}]; !ok || v != GlobalVRFID {
		t.Errorf("global AC eth3 -> (%d, %v), want explicit 0 entry", v, ok)
	}
	// The global id must not be recycled to a tenant on delete.
	m.Delete(GlobalVRFName)
	if next := m.Ensure("tenant2"); next.ID == GlobalVRFID {
		t.Errorf("global id 0 was recycled to tenant2")
	}
}

// Reconcile is fatal on a duplicate {ifindex, vlan}: AddAC blocks the same
// {interface, vlan} across VRFs, but two distinct interface names resolving to
// one ifindex still must not silently flap classification.
func TestManager_Reconcile_DuplicateIfindexIsFatal(t *testing.T) {
	m := NewManager()
	_, _ = m.AddAC("a", AC{"eth1", 100})
	_, _ = m.AddAC("b", AC{"eth2", 100})
	// eth1 and eth2 both resolve to ifindex 11 -> {11, 100} claimed twice.
	res := resolver(map[string]uint32{"eth1": 11, "eth2": 11})
	if err := m.Reconcile(res, &fakeProg{}); err == nil {
		t.Error("duplicate ifindex/vlan across VRFs: want a fatal Reconcile error")
	}
}

func TestManager_Reconcile(t *testing.T) {
	m := NewManager()
	_, _ = m.AddAC("a", AC{"eth1", 100})
	_, _ = m.AddAC("b", AC{"eth2", 0})
	idA, _ := m.IDForName("a")
	idB, _ := m.IDForName("b")
	res := resolver(map[string]uint32{"eth1": 11, "eth2": 12})

	fp := &fakeProg{}
	if err := m.Reconcile(res, fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if fp.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 100}] != idA {
		t.Errorf("eth1.100 -> %d, want %d", fp.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 100}], idA)
	}
	if fp.mapping[bpf.IngressACKey{Ifindex: 12, VlanId: 0}] != idB {
		t.Errorf("eth2.0 -> %d, want %d", fp.mapping[bpf.IngressACKey{Ifindex: 12, VlanId: 0}], idB)
	}
	if !fp.enabled || fp.defaultDeny {
		t.Errorf("policy enabled=%t deny=%t, want true/false", fp.enabled, fp.defaultDeny)
	}
}

func TestManager_Reconcile_UnresolvableIsFatal(t *testing.T) {
	m := NewManager()
	_, _ = m.AddAC("a", AC{"ghost", 0})
	if err := m.Reconcile(resolver(map[string]uint32{}), &fakeProg{}); err == nil {
		t.Error("unresolvable interface: want error")
	}
}

// A VRF with an id but no AC (e.g. ensured by a binding) does not enable the
// front door on its own; default-deny does.
func TestManager_EnabledRules(t *testing.T) {
	m := NewManager()
	m.Ensure("mup1") // id, no AC
	fp := &fakeProg{}
	if err := m.Reconcile(resolver(nil), fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if fp.enabled {
		t.Error("id-only VRF must not enable the front door")
	}
	m.SetPolicy(Policy{DefaultDeny: true, DenyAction: DenyActionPass})
	if err := m.Reconcile(resolver(nil), fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !fp.enabled || !fp.defaultDeny || fp.denyAction != DenyActionPass {
		t.Errorf("policy enabled=%t deny=%t action=%d, want true/true/pass", fp.enabled, fp.defaultDeny, fp.denyAction)
	}
}
