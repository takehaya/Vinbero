package ingressvrf

import (
	"fmt"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// fakeProg records the last Reconcile output.
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

// resolver maps interface names to fixed ifindexes; unknown names error.
func resolver(names map[string]uint32) func(string) (uint32, error) {
	return func(n string) (uint32, error) {
		if idx, ok := names[n]; ok {
			return idx, nil
		}
		return 0, fmt.Errorf("no such interface %q", n)
	}
}

func TestManager_BindUnbindList(t *testing.T) {
	m := NewManager()
	if err := m.Bind("eth1", 100, 1); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := m.Bind("eth1", 200, 2); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := m.Bind("eth0", 0, 0); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// Rebind replaces.
	if err := m.Bind("eth1", 100, 9); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	got := m.List()
	if len(got) != 3 {
		t.Fatalf("List len = %d, want 3: %+v", len(got), got)
	}
	// Sorted by {interface, vlan}: eth0.0, eth1.100, eth1.200.
	if got[0] != (Entry{"eth0", 0, 0}) || got[1] != (Entry{"eth1", 100, 9}) || got[2] != (Entry{"eth1", 200, 2}) {
		t.Errorf("List = %+v, want sorted eth0.0/eth1.100=9/eth1.200=2", got)
	}

	m.Unbind("eth1", 100)
	m.Unbind("eth9", 0) // idempotent: no such binding
	if got := m.List(); len(got) != 2 {
		t.Errorf("after unbind len = %d, want 2: %+v", len(got), got)
	}
}

func TestManager_BindValidation(t *testing.T) {
	m := NewManager()
	if err := m.Bind("", 0, 1); err == nil {
		t.Error("empty interface: want error")
	}
	if err := m.Bind("eth1", 4096, 1); err == nil {
		t.Error("vlan 4096: want error")
	}
}

func TestManager_Reconcile(t *testing.T) {
	m := NewManager()
	_ = m.Bind("eth1", 100, 1)
	_ = m.Bind("eth2", 0, 2)
	res := resolver(map[string]uint32{"eth1": 11, "eth2": 12})

	fp := &fakeProg{}
	if err := m.Reconcile(res, fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fp.mapping) != 2 {
		t.Fatalf("mapping len = %d, want 2: %+v", len(fp.mapping), fp.mapping)
	}
	if fp.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 100}] != 1 {
		t.Errorf("eth1.100 -> %d, want 1", fp.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 100}])
	}
	if fp.mapping[bpf.IngressACKey{Ifindex: 12, VlanId: 0}] != 2 {
		t.Errorf("eth2.0 -> %d, want 2", fp.mapping[bpf.IngressACKey{Ifindex: 12, VlanId: 0}])
	}
	// enabled because entries exist; default-deny off.
	if !fp.enabled || fp.defaultDeny {
		t.Errorf("policy: enabled=%t defaultDeny=%t, want true/false", fp.enabled, fp.defaultDeny)
	}
}

func TestManager_Reconcile_UnresolvableIsFatal(t *testing.T) {
	m := NewManager()
	_ = m.Bind("ghost", 0, 1)
	if err := m.Reconcile(resolver(map[string]uint32{}), &fakeProg{}); err == nil {
		t.Error("unresolvable interface: want error")
	}
}

// default-deny with no entries still enables the data-plane front door (so the
// deny posture is enforced), and an empty mapping is programmed.
func TestManager_DefaultDenyEnablesWithNoEntries(t *testing.T) {
	m := NewManager()
	m.SetPolicy(Policy{DefaultDeny: true, DenyAction: DenyActionPass})
	fp := &fakeProg{}
	if err := m.Reconcile(resolver(map[string]uint32{}), fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !fp.enabled || !fp.defaultDeny || fp.denyAction != DenyActionPass {
		t.Errorf("policy: enabled=%t deny=%t action=%d, want true/true/pass", fp.enabled, fp.defaultDeny, fp.denyAction)
	}
	if len(fp.mapping) != 0 {
		t.Errorf("mapping len = %d, want 0", len(fp.mapping))
	}
}

// No entries and default-deny off: front door stays disabled (back-compat).
func TestManager_DisabledWhenEmpty(t *testing.T) {
	m := NewManager()
	fp := &fakeProg{}
	if err := m.Reconcile(resolver(map[string]uint32{}), fp); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if fp.enabled {
		t.Error("empty + no default-deny: front door must stay disabled")
	}
}
