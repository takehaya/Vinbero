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
	if err := m.AddAC("v", AC{"eth1", 100}); err != nil {
		t.Fatalf("AddAC: %v", err)
	}
	if err := m.AddAC("v", AC{"eth1", 100}); err != nil { // idempotent
		t.Fatalf("AddAC idempotent: %v", err)
	}
	_ = m.AddAC("v", AC{"eth2", 0})
	got := m.List()
	if len(got) != 1 || len(got[0].ACs) != 2 {
		t.Fatalf("List = %+v, want 1 vrf with 2 acs", got)
	}
	if got[0].ACs[0] != (AC{"eth1", 100}) || got[0].ACs[1] != (AC{"eth2", 0}) {
		t.Errorf("ACs = %+v, want sorted", got[0].ACs)
	}
	m.RemoveAC("v", AC{"eth1", 100})
	if got := m.List(); len(got[0].ACs) != 1 || got[0].ACs[0] != (AC{"eth2", 0}) {
		t.Errorf("after RemoveAC ACs = %+v, want [eth2.0]", got[0].ACs)
	}
}

func TestManager_ACValidation(t *testing.T) {
	m := NewManager()
	if err := m.AddAC("", AC{"eth1", 0}); err == nil {
		t.Error("empty name: want error")
	}
	if err := m.AddAC("v", AC{"", 0}); err == nil {
		t.Error("empty interface: want error")
	}
	if err := m.AddAC("v", AC{"eth1", 4096}); err == nil {
		t.Error("vlan 4096: want error")
	}
}

// An AC belongs to exactly one VRF: re-adding it to the same VRF is idempotent,
// but adding it to a different VRF is rejected (so Reconcile can never build a
// colliding {ifindex, vlan} key).
func TestManager_AC_NoCrossVRFDuplicate(t *testing.T) {
	m := NewManager()
	if err := m.AddAC("a", AC{"eth1", 100}); err != nil {
		t.Fatalf("AddAC a: %v", err)
	}
	if err := m.AddAC("a", AC{"eth1", 100}); err != nil {
		t.Errorf("re-add to same VRF should be idempotent, got %v", err)
	}
	if err := m.AddAC("b", AC{"eth1", 100}); err == nil {
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

// Reconcile is fatal on a duplicate {ifindex, vlan}: AddAC blocks the same
// {interface, vlan} across VRFs, but two distinct interface names resolving to
// one ifindex still must not silently flap classification.
func TestManager_Reconcile_DuplicateIfindexIsFatal(t *testing.T) {
	m := NewManager()
	_ = m.AddAC("a", AC{"eth1", 100})
	_ = m.AddAC("b", AC{"eth2", 100})
	// eth1 and eth2 both resolve to ifindex 11 -> {11, 100} claimed twice.
	res := resolver(map[string]uint32{"eth1": 11, "eth2": 11})
	if err := m.Reconcile(res, &fakeProg{}); err == nil {
		t.Error("duplicate ifindex/vlan across VRFs: want a fatal Reconcile error")
	}
}

func TestManager_Reconcile(t *testing.T) {
	m := NewManager()
	_ = m.AddAC("a", AC{"eth1", 100})
	_ = m.AddAC("b", AC{"eth2", 0})
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
	_ = m.AddAC("a", AC{"ghost", 0})
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
