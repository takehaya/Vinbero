package server

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
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

// fakeVrfDeviceOps records device create/delete calls; create hands out
// sequential ifindexes starting at 100.
type fakeVrfDeviceOps struct {
	createErr error
	deleteErr error
	created   []string
	deleted   []string
	next      uint32
}

func (f *fakeVrfDeviceOps) CreateVrf(name string, tableID uint32, members []string, l3mdev bool) (uint32, error) {
	if f.createErr != nil {
		return 0, f.createErr
	}
	f.created = append(f.created, name)
	f.next++
	return 99 + f.next, nil
}

func (f *fakeVrfDeviceOps) DeleteVrf(name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, name)
	return nil
}

// fakeSidTable serves findVrfReference: SID prefix -> the vrf_ifindex its
// l3vrf aux references.
type fakeSidTable struct {
	refs map[string]uint32 // prefix -> ifindex
}

func (f *fakeSidTable) ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error) {
	out := make(map[string]*bpf.SidFunctionEntry, len(f.refs))
	i := uint16(1)
	for prefix := range f.refs {
		out[prefix] = &bpf.SidFunctionEntry{
			Action:   uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4),
			AuxIndex: i,
		}
		i++
	}
	return out, nil
}

func (f *fakeSidTable) GetSidAux(index uint32) (*bpf.SidAuxEntry, error) {
	// Re-derive the same iteration pairing ListSidFunctions used. Map order is
	// unstable across calls in theory but stable enough within one process for
	// a single-entry table; tests use at most one referencing SID.
	i := uint32(1)
	for _, ifindex := range f.refs {
		if i == index {
			return bpf.NewSidAuxL3Vrf(ifindex), nil
		}
		i++
	}
	return nil, fmt.Errorf("no aux %d", index)
}

// fakeBindings reports a binding for the names it holds.
type fakeBindings struct{ names map[string]bool }

func (f *fakeBindings) Get(name string) (vrfbgp.Binding, bool) {
	if f.names[name] {
		return vrfbgp.Binding{VRFName: name}, true
	}
	return vrfbgp.Binding{}, false
}

func newTestVrfServer() (*VrfServer, *fakeProgrammer) {
	s, prog, _ := newTestVrfServerFull()
	return s, prog
}

func newTestVrfServerFull() (*VrfServer, *fakeProgrammer, *fakeVrfDeviceOps) {
	prog := &fakeProgrammer{}
	dev := &fakeVrfDeviceOps{}
	s := NewVrfServer(vrf.NewManager(), prog, dev, &fakeSidTable{}, &fakeBindings{})
	s.resolve = fakeResolver
	return s, prog, dev
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

// VrfCreate drives DeviceOps, allocates a vrf_id, and returns both
// server-assigned ids; server-owned fields in the request are rejected.
func TestVrfServer_Create(t *testing.T) {
	s, _, dev := newTestVrfServerFull()
	resp, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{
		Vrfs: []*v1.Vrf{{Name: "vrf-cust", TableId: 100, EnableL3MdevRule: true}},
	}))
	if err != nil {
		t.Fatalf("VrfCreate: %v", err)
	}
	if len(resp.Msg.Errors) != 0 || len(resp.Msg.Created) != 1 {
		t.Fatalf("VrfCreate = created %d, errors %v", len(resp.Msg.Created), resp.Msg.Errors)
	}
	got := resp.Msg.Created[0]
	if got.GetVrfId() == 0 || got.GetIfindex() == 0 || got.GetTableId() != 100 {
		t.Errorf("created = %+v, want non-zero vrf_id/ifindex and table 100", got)
	}
	if len(dev.created) != 1 || dev.created[0] != "vrf-cust" {
		t.Errorf("DeviceOps created = %v, want [vrf-cust]", dev.created)
	}

	// Server-owned fields and invalid kernel-facet input are per-item errors.
	for _, bad := range []*v1.Vrf{
		{Name: "x", TableId: 7, Acs: []*v1.VrfAc{{InterfaceName: "eth0"}}},
		{Name: "x", TableId: 7, VrfId: 3},
		{Name: "x", TableId: 7, Ifindex: 9},
		{Name: "x"},                           // table_id 0
		{Name: vrf.GlobalVRFName, TableId: 7}, // reserved
	} {
		resp, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{Vrfs: []*v1.Vrf{bad}}))
		if err != nil {
			t.Fatalf("VrfCreate(%+v): %v", bad, err)
		}
		if len(resp.Msg.Errors) != 1 {
			t.Errorf("VrfCreate(%+v): want one per-item error, got %+v", bad, resp.Msg.Errors)
		}
	}
	if len(dev.created) != 1 {
		t.Errorf("rejected creates still hit DeviceOps: %v", dev.created)
	}
}

// VrfDelete refuses while any reference exists, and tears the device down
// before dropping the identity once clear.
func TestVrfServer_DeleteRefusals(t *testing.T) {
	s, _, dev := newTestVrfServerFull()
	bindings := s.bindings.(*fakeBindings)
	bindings.names = map[string]bool{}
	if _, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{
		Vrfs: []*v1.Vrf{{Name: "vrf-cust", TableId: 100}},
	})); err != nil {
		t.Fatalf("VrfCreate: %v", err)
	}
	created, _ := s.mgr.Get("vrf-cust")

	del := func() *v1.VrfDeleteResponse {
		t.Helper()
		resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"vrf-cust"}}))
		if err != nil {
			t.Fatalf("VrfDelete: %v", err)
		}
		return resp.Msg
	}

	// 1. Remaining AC refuses.
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "vrf-cust", Ac: &v1.VrfAc{InterfaceName: "eth0"},
	})); err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	if m := del(); len(m.Errors) != 1 {
		t.Fatalf("delete with AC: want refusal, got %+v", m)
	}
	if _, err := s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "vrf-cust", Ac: &v1.VrfAc{InterfaceName: "eth0"},
	})); err != nil {
		t.Fatalf("VrfAcRemove: %v", err)
	}

	// 2. Binding refuses.
	bindings.names["vrf-cust"] = true
	if m := del(); len(m.Errors) != 1 {
		t.Fatalf("delete with binding: want refusal, got %+v", m)
	}
	delete(bindings.names, "vrf-cust")

	// 3. SID referencing the device ifindex refuses.
	s.sids = &fakeSidTable{refs: map[string]uint32{"fd00::/64": created.Device.Ifindex}}
	if m := del(); len(m.Errors) != 1 {
		t.Fatalf("delete with SID ref: want refusal, got %+v", m)
	}
	s.sids = &fakeSidTable{}

	// All clear: device torn down, identity gone, DeviceOps hit.
	if m := del(); len(m.DeletedNames) != 1 {
		t.Fatalf("clear delete failed: %+v", m)
	}
	if len(dev.deleted) != 1 || dev.deleted[0] != "vrf-cust" {
		t.Errorf("DeviceOps deleted = %v, want [vrf-cust]", dev.deleted)
	}
	if _, ok := s.mgr.Get("vrf-cust"); ok {
		t.Error("identity still present after delete")
	}

	// Guard rails: unknown name and the reserved global refuse.
	for _, name := range []string{"ghost", vrf.GlobalVRFName, ""} {
		resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{name}}))
		if err != nil {
			t.Fatalf("VrfDelete(%q): %v", name, err)
		}
		if len(resp.Msg.Errors) != 1 {
			t.Errorf("VrfDelete(%q): want per-item error, got %+v", name, resp.Msg)
		}
	}
}

// A deviceless (ingress-only) VRF deletes without touching DeviceOps; a
// failed device delete leaves the manager untouched so the delete can retry.
func TestVrfServer_DeleteDevicelessAndFailure(t *testing.T) {
	s, _, dev := newTestVrfServerFull()

	// Deviceless: create via an AC, remove the AC, then delete.
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "mup-vrf", Ac: &v1.VrfAc{InterfaceName: "eth0"},
	})); err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	if _, err := s.VrfAcRemove(context.Background(), connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: "mup-vrf", Ac: &v1.VrfAc{InterfaceName: "eth0"},
	})); err != nil {
		t.Fatalf("VrfAcRemove: %v", err)
	}
	resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"mup-vrf"}}))
	if err != nil || len(resp.Msg.Errors) != 0 {
		t.Fatalf("deviceless delete: err=%v resp=%+v", err, resp.Msg)
	}
	if len(dev.deleted) != 0 {
		t.Errorf("deviceless delete hit DeviceOps: %v", dev.deleted)
	}

	// Device delete failure: identity and facet must survive.
	if _, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{
		Vrfs: []*v1.Vrf{{Name: "vrf-x", TableId: 7}},
	})); err != nil {
		t.Fatalf("VrfCreate: %v", err)
	}
	dev.deleteErr = fmt.Errorf("netlink boom")
	resp, err = s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"vrf-x"}}))
	if err != nil || len(resp.Msg.Errors) != 1 {
		t.Fatalf("failing delete: err=%v resp=%+v", err, resp.Msg)
	}
	if v, ok := s.mgr.Get("vrf-x"); !ok || v.Device == nil {
		t.Errorf("failed device delete lost manager state: ok=%v v=%+v", ok, v)
	}
	dev.deleteErr = nil
}

// VrfShow renders the kernel-device facet alongside the ingress facet.
func TestVrfServer_ShowBothFacets(t *testing.T) {
	s, _, _ := newTestVrfServerFull()
	if _, err := s.VrfCreate(context.Background(), connect.NewRequest(&v1.VrfCreateRequest{
		Vrfs: []*v1.Vrf{{Name: "vrf-cust", TableId: 100, Members: []string{"eth1"}}},
	})); err != nil {
		t.Fatalf("VrfCreate: %v", err)
	}
	if _, err := s.VrfAcAdd(context.Background(), connect.NewRequest(&v1.VrfAcAddRequest{
		Name: "vrf-cust", Ac: &v1.VrfAc{InterfaceName: "eth0", Vlan: 200},
	})); err != nil {
		t.Fatalf("VrfAcAdd: %v", err)
	}
	resp, err := s.VrfShow(context.Background(), connect.NewRequest(&v1.VrfShowRequest{}))
	if err != nil {
		t.Fatalf("VrfShow: %v", err)
	}
	if len(resp.Msg.Vrfs) != 1 {
		t.Fatalf("VrfShow returned %d VRFs, want 1", len(resp.Msg.Vrfs))
	}
	v := resp.Msg.Vrfs[0]
	if v.GetTableId() != 100 || v.GetIfindex() == 0 || len(v.GetMembers()) != 1 {
		t.Errorf("kernel facet = table %d ifindex %d members %v", v.GetTableId(), v.GetIfindex(), v.GetMembers())
	}
	if v.GetVrfId() == 0 || len(v.GetAcs()) != 1 || v.GetAcs()[0].GetVlan() != 200 {
		t.Errorf("ingress facet = vrf_id %d acs %+v", v.GetVrfId(), v.GetAcs())
	}
}
