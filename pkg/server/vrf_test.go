package server

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
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

// fakeSidTable serves findVrfReference / findBridgeReference: SID prefix ->
// the ifindex its aux references. l2 switches the entries to End.DT2 with an
// L2 aux (bridge references); default is End.DT4 with an l3vrf aux. auxErr
// makes every GetSidAux fail (the fail-closed path).
type fakeSidTable struct {
	refs   map[string]uint32 // prefix -> ifindex
	l2     bool
	auxErr error
}

func (f *fakeSidTable) ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error) {
	action := uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4)
	if f.l2 {
		action = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2)
	}
	out := make(map[string]*bpf.SidFunctionEntry, len(f.refs))
	i := uint16(1)
	for prefix := range f.refs {
		out[prefix] = &bpf.SidFunctionEntry{
			Action:   action,
			AuxIndex: i,
		}
		i++
	}
	return out, nil
}

func (f *fakeSidTable) GetSidAux(index uint32) (*bpf.SidAuxEntry, error) {
	if f.auxErr != nil {
		return nil, f.auxErr
	}
	// Re-derive the same iteration pairing ListSidFunctions used. Map order is
	// unstable across calls in theory but stable enough within one process for
	// a single-entry table; tests use at most one referencing SID.
	i := uint32(1)
	for _, ifindex := range f.refs {
		if i == index {
			if f.l2 {
				return bpf.NewSidAuxL2(1, ifindex), nil
			}
			return bpf.NewSidAuxL3Vrf(ifindex), nil
		}
		i++
	}
	return nil, fmt.Errorf("no aux %d", index)
}

// fakeBindings reports a binding for the names it holds. Full bindings (with
// families) take precedence; the names set yields a bare binding.
type fakeBindings struct {
	names    map[string]bool
	bindings map[string]vrfbgp.Binding
}

func (f *fakeBindings) Get(name string) (vrfbgp.Binding, bool) {
	if b, ok := f.bindings[name]; ok {
		return b, true
	}
	if f.names[name] {
		return vrfbgp.Binding{VRFName: name}, true
	}
	return vrfbgp.Binding{}, false
}

// fakeServerBridgeOps records bridge create/delete calls into the shared
// event log so ordering against the FDB registrar is assertable.
type fakeServerBridgeOps struct {
	ifindexes map[string]uint32
	deleteErr error
	events    *[]string
}

func (f *fakeServerBridgeOps) CreateBridge(name string, bdID uint16, members []string, ownerVRF string) (uint32, error) {
	*f.events = append(*f.events, "create:"+name)
	return f.ifindexes[name], nil
}

func (f *fakeServerBridgeOps) DeleteBridge(name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	*f.events = append(*f.events, "delete:"+name)
	return nil
}

// fakeFdbRegistrar records register/unregister into the shared event log.
type fakeFdbRegistrar struct {
	events *[]string
	byBd   map[uint16]int // bd -> last registered ifindex
}

func (f *fakeFdbRegistrar) RegisterBridge(ifindex int, bdID uint16) {
	*f.events = append(*f.events, fmt.Sprintf("register:%d:%d", ifindex, bdID))
	if f.byBd == nil {
		f.byBd = map[uint16]int{}
	}
	f.byBd[bdID] = ifindex
}

func (f *fakeFdbRegistrar) UnregisterBridge(ifindex int) {
	*f.events = append(*f.events, fmt.Sprintf("unregister:%d", ifindex))
}

func newTestVrfServer() (*VrfServer, *fakeProgrammer) {
	s, prog, _ := newTestVrfServerFull()
	return s, prog
}

func newTestVrfServerFull() (*VrfServer, *fakeProgrammer, *fakeVrfDeviceOps) {
	prog := &fakeProgrammer{}
	dev := &fakeVrfDeviceOps{}
	events := []string{}
	s := NewVrfServer(vrf.NewManager(), prog, dev, &fakeSidTable{}, &fakeBindings{},
		&fakeServerBridgeOps{ifindexes: map[string]uint32{}, events: &events},
		&fakeFdbRegistrar{events: &events}, nil, nil)
	s.resolve = fakeResolver
	return s, prog, dev
}

// newTestVrfServerBridge wires the bridge-facet fakes with a shared ordered
// event log and returns the handles the attach/detach tests assert on. The
// coordinator's facet resolver reads the server's own vrf.Manager, so a facet
// committed by VrfBridgeAttach is visible to Enable, like the real wiring.
func newTestVrfServerBridge(hook EvpnBridgeHook) (*VrfServer, *fakeServerBridgeOps, *fakeFdbRegistrar, *fakeBindings, *[]string) {
	events := []string{}
	bridges := &fakeServerBridgeOps{ifindexes: map[string]uint32{"br100": 42}, events: &events}
	fdb := &fakeFdbRegistrar{events: &events}
	bindings := &fakeBindings{bindings: map[string]vrfbgp.Binding{}}
	mgr := vrf.NewManager()
	var evpn *EvpnCoordinator
	if hook != nil {
		evpn = NewEvpnCoordinator(hook, testFacetResolver(mgr), func(int) error { return nil }, zap.NewNop())
	}
	s := NewVrfServer(mgr, &fakeProgrammer{}, &fakeVrfDeviceOps{}, &fakeSidTable{}, bindings, bridges, fdb, evpn, nil)
	s.resolve = fakeResolver
	return s, bridges, fdb, bindings, &events
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

	// 3b. An unreadable aux fails closed: the reference check cannot prove
	// the VRF is unreferenced, so the delete is refused (not treated as
	// "no reference").
	s.sids = &fakeSidTable{refs: map[string]uint32{"fd00::/64": 12345}, auxErr: fmt.Errorf("aux boom")}
	if m := del(); len(m.Errors) != 1 {
		t.Fatalf("delete with unreadable aux: want refusal, got %+v", m)
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

// VrfBridgeAttach validates before any netlink, registers the FDB watcher
// with the assigned ifindex, and fires the EVPN enable only when the binding
// actually advertises EVPN.
func TestVrfServer_BridgeAttach(t *testing.T) {
	hook := &fakeEvpnBridge{}
	s, _, fdb, bindings, _ := newTestVrfServerBridge(hook)

	// A bound VRF without EVPN export RTs: attach succeeds, FDB registers,
	// EVPN does NOT enable (the export-RT gate).
	bindings.bindings["evi-100"] = vrfbgp.Binding{VRFName: "evi-100"}
	resp, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
		VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: 100, Members: []string{"eth2"}},
	}))
	if err != nil {
		t.Fatalf("VrfBridgeAttach: %v", err)
	}
	got := resp.Msg.GetVrf()
	if got.GetBridge().GetIfindex() != 42 || got.GetBridge().GetBdId() != 100 {
		t.Errorf("attached bridge = %+v, want ifindex 42 / bd 100", got.GetBridge())
	}
	if fdb.byBd[100] != 42 {
		t.Errorf("FDB registered ifindex = %d, want 42", fdb.byBd[100])
	}
	if len(hook.enabled) != 0 {
		t.Errorf("EVPN enabled without export RTs: %v", hook.enabled)
	}

	// Validation guards (fresh server so no facet exists yet).
	s2, _, _, _, _ := newTestVrfServerBridge(nil)
	for _, bad := range []*v1.VrfBridgeAttachRequest{
		{VrfName: "", Bridge: &v1.Bridge{Name: "br1", BdId: 1}},
		{VrfName: "x", Bridge: &v1.Bridge{BdId: 1}},                            // no device name
		{VrfName: "x", Bridge: &v1.Bridge{Name: "br1"}},                        // bd_id 0
		{VrfName: "x", Bridge: &v1.Bridge{Name: "br1", BdId: 65536}},           // wraps to 0
		{VrfName: "x", Bridge: &v1.Bridge{Name: "br1", BdId: 1, Ifindex: 9}},   // server-owned
		{VrfName: vrf.GlobalVRFName, Bridge: &v1.Bridge{Name: "br1", BdId: 1}}, // reserved
	} {
		if _, err := s2.VrfBridgeAttach(context.Background(), connect.NewRequest(bad)); err == nil {
			t.Errorf("VrfBridgeAttach(%+v): want error", bad)
		}
	}
}

// With a binding that exports EVPN RTs, the attach enables the bridge domain
// (the coordinator resolves the just-committed facet by VRF name).
func TestVrfServer_BridgeAttachEnablesEvpn(t *testing.T) {
	hook := &fakeEvpnBridge{}
	s, _, _, bindings, _ := newTestVrfServerBridge(hook)
	bindings.bindings["evi-100"] = vrfbgp.Binding{
		VRFName: "evi-100",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyEVPN: {RouteTargets: []vrfbgp.RouteTarget{{RT: "65000:100", Direction: vrfbgp.DirectionBoth}}},
		},
	}
	if _, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
		VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: 100},
	})); err != nil {
		t.Fatalf("VrfBridgeAttach: %v", err)
	}
	if !hook.enabled[100] {
		t.Errorf("EVPN not enabled on attach with export RTs: %v", hook.enabled)
	}
}

// VrfBridgeDetach refuses while a SID references the bridge (excluding the
// exporter's own lifecycle SIDs), keeps everything intact on a failed device
// delete, and on success unregisters the watcher only AFTER the delete and
// disables EVPN.
func TestVrfServer_BridgeDetach(t *testing.T) {
	hook := &fakeEvpnBridge{}
	s, bridges, _, _, events := newTestVrfServerBridge(hook)
	if _, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
		VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: 100},
	})); err != nil {
		t.Fatalf("VrfBridgeAttach: %v", err)
	}

	detach := func() error {
		_, err := s.VrfBridgeDetach(context.Background(), connect.NewRequest(&v1.VrfBridgeDetachRequest{VrfName: "evi-100"}))
		return err
	}

	// 1. A SID referencing the bridge ifindex refuses.
	s.sids = &fakeSidTable{refs: map[string]uint32{"fd00::/64": 42}, l2: true}
	if err := detach(); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("detach with SID ref: code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	// 1b. Unreadable aux fails closed.
	s.sids = &fakeSidTable{refs: map[string]uint32{"fd00::/64": 12345}, l2: true, auxErr: fmt.Errorf("aux boom")}
	if err := detach(); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("detach with unreadable aux: code = %v, want Internal", connect.CodeOf(err))
	}
	s.sids = &fakeSidTable{}

	// 2. Device delete failure keeps facet, watcher and EVPN state intact.
	bridges.deleteErr = fmt.Errorf("netlink boom")
	if err := detach(); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("failing delete: code = %v, want Internal", connect.CodeOf(err))
	}
	if v, _ := s.mgr.Get("evi-100"); v.Bridge == nil {
		t.Fatal("failed delete cleared the facet")
	}
	for _, e := range *events {
		if e == "unregister:42" {
			t.Fatal("failed delete unregistered the FDB watcher")
		}
	}
	bridges.deleteErr = nil

	// 3. Success: delete precedes unregister; EVPN disabled; facet gone.
	if err := detach(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	delIdx, unregIdx := -1, -1
	for i, e := range *events {
		switch e {
		case "delete:br100":
			delIdx = i
		case "unregister:42":
			unregIdx = i
		}
	}
	if delIdx == -1 || unregIdx == -1 || delIdx > unregIdx {
		t.Errorf("ordering events = %v, want delete before unregister", *events)
	}
	if len(hook.disabled) != 1 || hook.disabled[0] != 100 {
		t.Errorf("EVPN disabled = %v, want [100]", hook.disabled)
	}
	if v, _ := s.mgr.Get("evi-100"); v.Bridge != nil {
		t.Error("facet still present after detach")
	}

	// 4. No facet: FailedPrecondition; unknown VRF: NotFound.
	if err := detach(); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("re-detach: code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if _, err := s.VrfBridgeDetach(context.Background(), connect.NewRequest(&v1.VrfBridgeDetachRequest{VrfName: "ghost"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("unknown vrf: code = %v, want NotFound", connect.CodeOf(err))
	}
}

// Moving a bridge domain to a different bd is detach -> attach: the detach
// disables the old bd's EVPN state and the re-attach enables the new bd,
// leaving no residue under the old bd (a direct re-attach with a changed bd
// is refused by the facet uniqueness check).
func TestVrfServer_BridgeDetachAttachMovesBd(t *testing.T) {
	hook := &fakeEvpnBridge{}
	s, _, _, bindings, _ := newTestVrfServerBridge(hook)
	bindings.bindings["evi-100"] = vrfbgp.Binding{
		VRFName: "evi-100",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyEVPN: {RouteTargets: []vrfbgp.RouteTarget{{RT: "65000:100", Direction: vrfbgp.DirectionBoth}}},
		},
	}
	attach := func(bd uint32) error {
		_, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
			VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: bd},
		}))
		return err
	}
	if err := attach(100); err != nil {
		t.Fatalf("attach bd 100: %v", err)
	}
	if !hook.enabled[100] {
		t.Fatalf("precondition: bd 100 enabled after attach; enabled=%v", hook.enabled)
	}
	// A direct re-attach with a different bd must refuse.
	if err := attach(200); err == nil {
		t.Fatal("re-attach with a changed bd must refuse (detach first)")
	}
	if _, err := s.VrfBridgeDetach(context.Background(), connect.NewRequest(&v1.VrfBridgeDetachRequest{VrfName: "evi-100"})); err != nil {
		t.Fatalf("VrfBridgeDetach: %v", err)
	}
	if err := attach(200); err != nil {
		t.Fatalf("attach bd 200 after detach: %v", err)
	}
	if !slices.Contains(hook.disabled, uint16(100)) {
		t.Errorf("detach must Disable the old bd 100; disabled=%v", hook.disabled)
	}
	if hook.enabled[100] || !hook.enabled[200] {
		t.Errorf("after the move only bd 200 must be enabled; enabled=%v", hook.enabled)
	}
}

// VrfDelete refuses while the bridge facet is attached (the 4th gate).
func TestVrfServer_DeleteRefusesWithBridge(t *testing.T) {
	s, _, _, _, _ := newTestVrfServerBridge(nil)
	if _, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
		VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: 100},
	})); err != nil {
		t.Fatalf("VrfBridgeAttach: %v", err)
	}
	resp, err := s.VrfDelete(context.Background(), connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{"evi-100"}}))
	if err != nil {
		t.Fatalf("VrfDelete: %v", err)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("delete with bridge facet: want refusal, got %+v", resp.Msg)
	}
}
