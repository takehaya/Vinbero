package server

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// fakeProgrammer captures the last ingress_vrf_map / policy write so a
// VrfServer handler can be asserted without a live BPF map.
type fakeProgrammer struct {
	mapping     map[bpf.IngressACKey]uint32
	enabled     bool
	defaultDeny bool
	denyAction  uint8
	calls       int
}

func (f *fakeProgrammer) SetIngressVrf(mapping map[bpf.IngressACKey]uint32) error {
	f.mapping = mapping
	return nil
}

func (f *fakeProgrammer) SetIngressPolicy(enabled, defaultDeny bool, denyAction uint8) error {
	f.enabled, f.defaultDeny, f.denyAction = enabled, defaultDeny, denyAction
	f.calls++
	return nil
}

// fakeResolver maps interface names to fixed ifindexes so Reconcile does not
// depend on the test host having those interfaces.
func fakeResolver(name string) (uint32, error) {
	switch name {
	case "eth0":
		return 10, nil
	case "eth1":
		return 11, nil
	}
	return 0, fmt.Errorf("no such interface %q", name)
}

func newTestVrfServer() (*VrfServer, *fakeProgrammer) {
	prog := &fakeProgrammer{}
	s := NewVrfServer(vrf.NewManager(), prog)
	s.resolve = fakeResolver
	return s, prog
}

// VrfAcAdd creates the VRF (allocating a non-zero id), and the reconcile
// programs ingress_vrf_map with {ifindex, vlan} -> vrf_id and enables the
// front door.
func TestVrfServer_AcAddProgramsMap(t *testing.T) {
	s, prog := newTestVrfServer()

	resp, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a",
		Ac:   &v1.VrfAc{InterfaceName: "eth0", Vlan: 100},
	}))
	if err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	id := resp.Msg.GetVrf().GetVrfId()
	if id == vrf.GlobalVRFID {
		t.Fatalf("VRF tenant-a got the global id %d, want a tenant id", id)
	}
	if !prog.enabled {
		t.Errorf("front door not enabled after an AC add")
	}
	want := map[bpf.IngressACKey]uint32{{Ifindex: 10, VlanId: 100}: id}
	if len(prog.mapping) != 1 || prog.mapping[bpf.IngressACKey{Ifindex: 10, VlanId: 100}] != id {
		t.Errorf("ingress_vrf_map = %v, want %v", prog.mapping, want)
	}
}

// A second AC on the same VRF shares its id; an AC on a new VRF gets a
// distinct id, and both appear in the programmed map.
func TestVrfServer_MultipleVRFs(t *testing.T) {
	s, prog := newTestVrfServer()
	add := func(name, iface string, vlan uint32) uint32 {
		t.Helper()
		resp, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
			Name: name, Ac: &v1.VrfAc{InterfaceName: iface, Vlan: vlan},
		}))
		if err != nil {
			t.Fatalf("VrfAcAdd(%s): %v", name, err)
		}
		return resp.Msg.GetVrf().GetVrfId()
	}
	idA := add("tenant-a", "eth0", 100)
	idA2 := add("tenant-a", "eth1", 100)
	idB := add("tenant-b", "eth1", 200)

	if idA != idA2 {
		t.Errorf("same VRF got two ids: %d and %d", idA, idA2)
	}
	if idA == idB {
		t.Errorf("distinct VRFs share id %d", idA)
	}
	if got := prog.mapping[bpf.IngressACKey{Ifindex: 10, VlanId: 100}]; got != idA {
		t.Errorf("eth0.100 -> %d, want %d", got, idA)
	}
	if got := prog.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 100}]; got != idA {
		t.Errorf("eth1.100 -> %d, want %d", got, idA)
	}
	if got := prog.mapping[bpf.IngressACKey{Ifindex: 11, VlanId: 200}]; got != idB {
		t.Errorf("eth1.200 -> %d, want %d", got, idB)
	}
}

// Removing the last AC empties the map; the front door stays enabled only
// while default-deny is on or some AC remains.
func TestVrfServer_AcRemoveDisablesWhenEmpty(t *testing.T) {
	s, prog := newTestVrfServer()
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 100},
	})); err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	if _, err := s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 100},
	})); err != nil {
		t.Fatalf("VrfAcRemove: %v", err)
	}
	if len(prog.mapping) != 0 {
		t.Errorf("ingress_vrf_map = %v, want empty after removing the last AC", prog.mapping)
	}
	if prog.enabled {
		t.Errorf("front door still enabled with no ACs and default-deny off")
	}
}

// default-deny enables the front door even with no AC and programs the policy.
func TestVrfServer_SetPolicy(t *testing.T) {
	s, prog := newTestVrfServer()
	resp, err := s.VrfSetPolicy(context.Background(), connect.NewRequest(&v1.VrfSetPolicyRequest{
		Policy: &v1.VrfPolicy{DefaultDeny: true, DenyAction: "pass"},
	}))
	if err != nil {
		t.Fatalf("VrfSetPolicy: %v", err)
	}
	if !prog.enabled || !prog.defaultDeny || prog.denyAction != vrf.DenyActionPass {
		t.Errorf("policy programmed enabled=%t defaultDeny=%t denyAction=%d, want true/true/%d",
			prog.enabled, prog.defaultDeny, prog.denyAction, vrf.DenyActionPass)
	}
	if got := resp.Msg.GetPolicy().GetDenyAction(); got != "pass" {
		t.Errorf("response deny_action = %q, want \"pass\"", got)
	}
}

// A VLAN past the 12-bit range and an unknown deny_action are both rejected at
// the RPC boundary (InvalidArgument) before any map write.
func TestVrfServer_InvalidInput(t *testing.T) {
	s, prog := newTestVrfServer()

	_, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 4096},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("AcAdd vlan 4096: code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// VrfAcRemove must range-check too: a vlan past 4095 would wrap on the
	// uint16 cast and remove a different AC.
	_, err = s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 4096},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("AcRemove vlan 4096: code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Empty name / interface on remove is a typo, not a legitimate idempotent
	// remove: reject rather than silently no-op.
	_, err = s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "", Ac: &v1.VrfAc{InterfaceName: "eth0"},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("AcRemove empty name: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
	_, err = s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: ""},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("AcRemove empty interface: code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	_, err = s.VrfSetPolicy(context.Background(), connect.NewRequest(&v1.VrfSetPolicyRequest{
		Policy: &v1.VrfPolicy{DefaultDeny: true, DenyAction: "bogus"},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("deny_action bogus: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
	if prog.calls != 0 {
		t.Errorf("invalid input still programmed the policy %d times, want 0", prog.calls)
	}
}

// An unresolvable AC interface fails the reconcile (Internal); the failed add
// is rolled back so the bad AC does not linger and poison every later
// reconcile, and a subsequent valid add still succeeds.
func TestVrfServer_UnresolvableInterfaceRollsBack(t *testing.T) {
	s, prog := newTestVrfServer()
	_, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "does-not-exist", Vlan: 0},
	}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("unresolvable interface: code = %v, want Internal", connect.CodeOf(err))
	}
	// The bad AC must have been rolled out of the manager.
	for _, v := range s.mgr.List() {
		if len(v.ACs) != 0 {
			t.Errorf("failed add left AC behind on vrf %q: %+v", v.Name, v.ACs)
		}
	}
	// A subsequent valid add must succeed (the manager is not poisoned).
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 0},
	})); err != nil {
		t.Fatalf("valid add after a rolled-back failure: %v", err)
	}
	if prog.mapping[bpf.IngressACKey{Ifindex: 10, VlanId: 0}] == 0 {
		t.Errorf("valid AC not programmed after recovery; mapping=%v", prog.mapping)
	}
}

// An AC added to the reserved "global" VRF maps to vrf_id 0 (the underlay), so
// it can be expressed through the same RPC under default-deny.
func TestVrfServer_GlobalVRFAc(t *testing.T) {
	s, prog := newTestVrfServer()
	resp, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: vrf.GlobalVRFName,
		Ac:   &v1.VrfAc{InterfaceName: "eth0", Vlan: 0},
	}))
	if err != nil {
		t.Fatalf("VrfAcAdd global: %v", err)
	}
	if got := resp.Msg.GetVrf().GetVrfId(); got != vrf.GlobalVRFID {
		t.Errorf("global VRF id = %d, want 0", got)
	}
	if v, ok := prog.mapping[bpf.IngressACKey{Ifindex: 10, VlanId: 0}]; !ok || v != vrf.GlobalVRFID {
		t.Errorf("global AC programmed as (%d, %v), want explicit 0 entry", v, ok)
	}
}

// VrfShow lists every VRF (with its id and ACs) plus the global policy.
func TestVrfServer_Show(t *testing.T) {
	s, _ := newTestVrfServer()
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "tenant-a", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 100},
	})); err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	resp, err := s.VrfShow(context.Background(), connect.NewRequest(&v1.VrfShowRequest{}))
	if err != nil {
		t.Fatalf("VrfShow: %v", err)
	}
	if len(resp.Msg.GetVrfs()) != 1 {
		t.Fatalf("VrfShow returned %d VRFs, want 1", len(resp.Msg.GetVrfs()))
	}
	v := resp.Msg.GetVrfs()[0]
	if v.GetName() != "tenant-a" || len(v.GetAcs()) != 1 || v.GetAcs()[0].GetVlan() != 100 {
		t.Errorf("VrfShow vrf = %+v, want tenant-a with one AC on vlan 100", v)
	}
	if resp.Msg.GetPolicy() == nil {
		t.Errorf("VrfShow returned no policy")
	}
}
