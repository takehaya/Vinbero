package vrf

import (
	"errors"
	"fmt"
	"slices"
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
	a := mustEnsure(t, m, "a")
	b := mustEnsure(t, m, "b")
	if a.ID == GlobalVRFID || b.ID == GlobalVRFID || a.ID == b.ID {
		t.Fatalf("ids a=%d b=%d, want distinct non-zero", a.ID, b.ID)
	}
	if a2 := mustEnsure(t, m, "a"); a2.ID != a.ID {
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

// A deleted VRF's id is not handed out again.
func TestManager_DeleteDoesNotReuseID(t *testing.T) {
	m := NewManager()
	a := mustEnsure(t, m, "a")
	m.Delete("a")
	if _, ok := m.IDForName("a"); ok {
		t.Error("IDForName(a) after delete: want absent")
	}
	if c := mustEnsure(t, m, "c"); c.ID <= a.ID {
		t.Errorf("id after delete = %d, want above %d", c.ID, a.ID)
	}
	// Recreating the same name is a new VRF too.
	if again := mustEnsure(t, m, "a"); again.ID == a.ID {
		t.Errorf("recreated VRF reused id %d", a.ID)
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

	got := mustEnsure(t, m, "v")
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

// fakeDeviceOps records device create/delete calls; create returns a fixed
// ifindex per name (or an injected error).
type fakeDeviceOps struct {
	ifindexes map[string]uint32
	createErr error
	// unsaved makes a create succeed in the kernel and fail to persist.
	unsaved   bool
	deleteErr error
	created   []string
	deleted   []string
	// noUnreachable is the noUnreachableDefault each create passed, by name.
	noUnreachable map[string]bool
}

func (f *fakeDeviceOps) CreateVrf(name string, tableID uint32, members []string, l3mdev, noUnreachable bool) (uint32, error) {
	if f.createErr != nil {
		return 0, f.createErr
	}
	f.created = append(f.created, name)
	if f.noUnreachable == nil {
		f.noUnreachable = map[string]bool{}
	}
	f.noUnreachable[name] = noUnreachable
	if f.unsaved {
		return f.ifindexes[name], errors.New("persist state: no space left on device")
	}
	return f.ifindexes[name], nil
}

func (f *fakeDeviceOps) DeleteVrf(name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, name)
	return nil
}

// CreateDevice drives ops, allocates the identity, and attaches the facet
// with the returned ifindex; the reserved global name and a zero table are
// rejected before any netlink call.
func TestManager_CreateDevice(t *testing.T) {
	m := NewManager()
	ops := &fakeDeviceOps{ifindexes: map[string]uint32{"vrf-a": 42}}
	v, err := m.CreateDevice("vrf-a", Device{TableID: 100, Members: []string{"eth1"}, EnableL3mdevRule: true}, ops)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if v.ID == GlobalVRFID {
		t.Errorf("device VRF got the global id 0")
	}
	if v.Device == nil || v.Device.Ifindex != 42 || v.Device.TableID != 100 {
		t.Errorf("Device = %+v, want ifindex 42 / table 100", v.Device)
	}
	if len(ops.created) != 1 || ops.created[0] != "vrf-a" {
		t.Errorf("ops.created = %v, want [vrf-a]", ops.created)
	}

	if _, err := m.CreateDevice(GlobalVRFName, Device{TableID: 100}, ops); err == nil {
		t.Error("global device: want error")
	}
	if _, err := m.CreateDevice("vrf-b", Device{}, ops); err == nil {
		t.Error("table_id 0: want error")
	}
	if len(ops.created) != 1 {
		t.Errorf("rejected creates still hit ops: %v", ops.created)
	}
}

// The unreachable-default opt-out reaches the mechanics layer and stays on
// the facet; leaving it unset asks for the routes.
func TestManager_CreateDevice_NoUnreachableDefault(t *testing.T) {
	m := NewManager()
	ops := &fakeDeviceOps{ifindexes: map[string]uint32{"vrf-a": 42, "vrf-b": 43}}
	v, err := m.CreateDevice("vrf-a", Device{TableID: 100, NoUnreachableDefault: true}, ops)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if !ops.noUnreachable["vrf-a"] || v.Device == nil || !v.Device.NoUnreachableDefault {
		t.Errorf("opt-out: ops saw %v, facet %+v; want true on both", ops.noUnreachable["vrf-a"], v.Device)
	}
	if _, err := m.CreateDevice("vrf-b", Device{TableID: 200}, ops); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if got, ok := ops.noUnreachable["vrf-b"]; !ok || got {
		t.Errorf("default: ops saw noUnreachableDefault=%v (called %v), want false", got, ok)
	}
}

// An ops failure leaves the manager untouched: no identity, no facet.
func TestManager_CreateDevice_OpsErrorLeavesNoIdentity(t *testing.T) {
	m := NewManager()
	ops := &fakeDeviceOps{createErr: fmt.Errorf("netlink boom")}
	if _, err := m.CreateDevice("vrf-a", Device{TableID: 100}, ops); err == nil {
		t.Fatal("want error from ops")
	}
	if _, ok := m.IDForName("vrf-a"); ok {
		t.Error("failed CreateDevice allocated an identity")
	}
}

// SetDevice attaches the facet without netlink (boot seeding); an existing
// ingress-only VRF keeps its id, and the facet appears in Get/List clones
// without aliasing the stored Members.
func TestManager_SetDevice(t *testing.T) {
	m := NewManager()
	_, _ = m.AddAC("vrf-a", AC{"eth1", 100})
	idBefore, _ := m.IDForName("vrf-a")

	members := []string{"eth2"}
	v, err := m.SetDevice("vrf-a", Device{TableID: 200, Members: members, Ifindex: 7})
	if err != nil {
		t.Fatalf("SetDevice: %v", err)
	}
	if v.ID != idBefore {
		t.Errorf("SetDevice changed the id: %d -> %d", idBefore, v.ID)
	}
	if _, err := m.SetDevice(GlobalVRFName, Device{TableID: 1}); err == nil {
		t.Error("global SetDevice: want error")
	}

	// Mutating the caller's slice or the returned clone must not leak in.
	members[0] = "hacked"
	v.Device.Members = append(v.Device.Members, "hacked2")
	got, _ := m.Get("vrf-a")
	if got.Device == nil || len(got.Device.Members) != 1 || got.Device.Members[0] != "eth2" {
		t.Errorf("stored Device.Members corrupted: %+v", got.Device)
	}
	// Deviceless VRFs stay nil in List; the device VRF carries the facet.
	_, _ = m.AddAC("vrf-b", AC{"eth3", 0})
	for _, lv := range m.List() {
		switch lv.Name {
		case "vrf-a":
			if lv.Device == nil || lv.Device.TableID != 200 {
				t.Errorf("List vrf-a Device = %+v, want table 200", lv.Device)
			}
		case "vrf-b":
			if lv.Device != nil {
				t.Errorf("List vrf-b Device = %+v, want nil (deviceless)", lv.Device)
			}
		}
	}
}

// Delete drops the whole object including the facet, and the id stays retired.
func TestManager_Delete_DropsDeviceFacet(t *testing.T) {
	m := NewManager()
	ops := &fakeDeviceOps{ifindexes: map[string]uint32{"vrf-a": 9}}
	v, err := m.CreateDevice("vrf-a", Device{TableID: 100}, ops)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	m.Delete("vrf-a")
	if _, ok := m.Get("vrf-a"); ok {
		t.Error("Get after Delete: want absent")
	}
	if next := mustEnsure(t, m, "vrf-b"); next.ID == v.ID {
		t.Errorf("id %d reused after Delete", v.ID)
	}
}

// The reserved global VRF name maps ACs to vrf_id 0 (the underlay): under
// default-deny those ACs get an explicit {ifindex, vlan} -> 0 entry so they
// pass, while a tenant VRF keeps a non-zero id. The id 0 is never handed out.
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
	// The global id must not go to a tenant after a delete.
	m.Delete(GlobalVRFName)
	if next := mustEnsure(t, m, "tenant2"); next.ID == GlobalVRFID {
		t.Errorf("global id 0 was handed to tenant2")
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

// A runtime AC whose interface is gone is skipped so it cannot block other
// ACs; an AC that was never marked runtime (config-declared) stays fatal, as
// does a resolve failure that says nothing about the interface.
func TestManager_Reconcile_SkipsVanishedRuntimeAC(t *testing.T) {
	gone := func(names map[string]uint32) func(string) (uint32, error) {
		return func(n string) (uint32, error) {
			if idx, ok := names[n]; ok {
				return idx, nil
			}
			return 0, fmt.Errorf("%w: %s", ErrInterfaceGone, n)
		}
	}
	m := NewManager()
	_, _ = m.AddAC("a", AC{"vb0", 0})
	m.MarkRuntimeAC("a", AC{"vb0", 0})
	_, _ = m.AddAC("a", AC{"vb1", 0})
	m.MarkRuntimeAC("a", AC{"vb1", 0})
	fp := &fakeProg{}
	if err := m.Reconcile(gone(map[string]uint32{"vb1": 21}), fp); err != nil {
		t.Fatalf("Reconcile with a vanished runtime AC: %v", err)
	}
	if len(fp.mapping) != 1 || fp.mapping[bpf.IngressACKey{Ifindex: 21}] == 0 {
		t.Errorf("mapping = %v, want only vb1", fp.mapping)
	}
	if err := m.Reconcile(func(string) (uint32, error) { return 0, errors.New("ENOBUFS") }, &fakeProg{}); err == nil {
		t.Error("a resolve failure other than a missing interface must stay fatal")
	}

	_, _ = m.AddAC("a", AC{"cfg0", 0})
	if err := m.Reconcile(gone(map[string]uint32{"vb0": 20, "vb1": 21}), &fakeProg{}); err == nil {
		t.Error("an unmarked (config-declared) AC with a missing interface must stay fatal")
	}

	m.RemoveAC("a", AC{"vb0", 0})
	if m.IsRuntimeAC("a", AC{"vb0", 0}) {
		t.Error("RemoveAC kept the runtime mark")
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
	mustEnsure(t, m, "mup1") // id, no AC
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

// fakeBridgeOps records bridge create/delete calls; create returns a fixed
// ifindex per name and captures the ownerVRF handed to the mechanics layer.
type fakeBridgeOps struct {
	ifindexes map[string]uint32
	createErr error
	created   []string
	owners    map[string]string
	deleted   []string
	memberErr error
	memberOps []string
}

func (f *fakeBridgeOps) CreateBridge(name string, bdID uint16, members []string, ownerVRF string) (uint32, error) {
	if f.createErr != nil {
		return 0, f.createErr
	}
	f.created = append(f.created, name)
	if f.owners == nil {
		f.owners = map[string]string{}
	}
	f.owners[name] = ownerVRF
	return f.ifindexes[name], nil
}

func (f *fakeBridgeOps) DeleteBridge(name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeBridgeOps) AddBridgeMember(bridge, member string) error {
	if f.memberErr != nil {
		return f.memberErr
	}
	f.memberOps = append(f.memberOps, "add:"+bridge+":"+member)
	return nil
}

func (f *fakeBridgeOps) RemoveBridgeMember(bridge, member string) error {
	if f.memberErr != nil {
		return f.memberErr
	}
	f.memberOps = append(f.memberOps, "remove:"+bridge+":"+member)
	return nil
}

// Member add / remove go through ops on the attached bridge and keep the
// facet's member list in step; a failing op leaves the facet unchanged.
func TestManager_BridgeMembers(t *testing.T) {
	m := NewManager()
	ops := &fakeBridgeOps{ifindexes: map[string]uint32{"br100": 7}}
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100, Members: []string{"eth2"}}, ops); err != nil {
		t.Fatalf("AttachBridge: %v", err)
	}
	v, err := m.AddBridgeMember("evi-100", "veth1", ops)
	if err != nil {
		t.Fatalf("AddBridgeMember: %v", err)
	}
	if got := v.Bridge.Members; !slices.Equal(got, []string{"eth2", "veth1"}) {
		t.Errorf("members after add = %v", got)
	}
	// Adding again is idempotent: no duplicate in the facet.
	if v, _ = m.AddBridgeMember("evi-100", "veth1", ops); len(v.Bridge.Members) != 2 {
		t.Errorf("re-add duplicated the member: %v", v.Bridge.Members)
	}
	if v, err = m.RemoveBridgeMember("evi-100", "eth2", ops); err != nil || !slices.Equal(v.Bridge.Members, []string{"veth1"}) {
		t.Errorf("remove = %v / %v", v.Bridge, err)
	}
	want := []string{"add:br100:veth1", "add:br100:veth1", "remove:br100:eth2"}
	if !slices.Equal(ops.memberOps, want) {
		t.Errorf("ops = %v, want %v", ops.memberOps, want)
	}

	// An idempotent re-attach keeps the members added since.
	if v, err = m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100, Members: []string{"eth9"}}, ops); err != nil ||
		!slices.Equal(v.Bridge.Members, []string{"veth1", "eth9"}) {
		t.Errorf("re-attach = %v / %v, want members [veth1 eth9]", v.Bridge, err)
	}
	if v, err = m.RemoveBridgeMember("evi-100", "eth9", ops); err != nil || !slices.Equal(v.Bridge.Members, []string{"veth1"}) {
		t.Errorf("remove = %v / %v", v.Bridge, err)
	}

	ops.memberErr = errors.New("boom")
	if _, err := m.AddBridgeMember("evi-100", "veth2", ops); err == nil {
		t.Error("failing op: want error")
	}
	if got, _ := m.Get("evi-100"); !slices.Equal(got.Bridge.Members, []string{"veth1"}) {
		t.Errorf("failing op changed the facet: %v", got.Bridge.Members)
	}

	ops.memberErr = nil
	for _, bad := range []struct{ vrf, member string }{
		{"missing", "veth3"}, // unknown VRF
		{"evi-100", ""},      // empty member
		{"evi-100", "br100"}, // the bridge itself
	} {
		if _, err := m.AddBridgeMember(bad.vrf, bad.member, ops); err == nil {
			t.Errorf("AddBridgeMember(%q, %q): want error", bad.vrf, bad.member)
		}
	}
	mustEnsure(t, m, "no-bridge")
	if _, err := m.AddBridgeMember("no-bridge", "veth3", ops); err == nil {
		t.Error("VRF without a bridge facet: want error")
	}
}

// AttachBridge drives ops with the owning VRF name, attaches the facet with
// the returned ifindex, and rejects the invalid shapes before any netlink.
func TestManager_AttachBridge(t *testing.T) {
	m := NewManager()
	ops := &fakeBridgeOps{ifindexes: map[string]uint32{"br100": 7}}
	v, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100, Members: []string{"eth2"}}, ops)
	if err != nil {
		t.Fatalf("AttachBridge: %v", err)
	}
	if v.Bridge == nil || v.Bridge.Ifindex != 7 || v.Bridge.BdID != 100 {
		t.Errorf("Bridge = %+v, want ifindex 7 / bd 100", v.Bridge)
	}
	if ops.owners["br100"] != "evi-100" {
		t.Errorf("ops owner = %q, want evi-100", ops.owners["br100"])
	}

	for _, bad := range []struct {
		vrf string
		b   Bridge
	}{
		{GlobalVRFName, Bridge{Name: "br1", BdID: 1}}, // reserved global
		{"", Bridge{Name: "br1", BdID: 1}},            // empty vrf
		{"x", Bridge{BdID: 1}},                        // empty device name
		{"x", Bridge{Name: "br1"}},                    // bd_id 0
	} {
		if _, err := m.AttachBridge(bad.vrf, bad.b, ops); err == nil {
			t.Errorf("AttachBridge(%q, %+v): want error", bad.vrf, bad.b)
		}
	}
	if len(ops.created) != 1 {
		t.Errorf("rejected attaches still hit ops: %v", ops.created)
	}
}

// The facet is unique on three axes: one bridge per VRF, one VRF per bridge
// name, one VRF per bd_id.
func TestManager_AttachBridge_Uniqueness(t *testing.T) {
	m := NewManager()
	ops := &fakeBridgeOps{ifindexes: map[string]uint32{"br100": 7, "br200": 8}}
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100}, ops); err != nil {
		t.Fatalf("AttachBridge: %v", err)
	}
	// Same VRF, different bridge name: refuse (detach first).
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br200", BdID: 200}, ops); err == nil {
		t.Error("second bridge on one VRF: want error")
	}
	// Different VRF, same bridge name: refuse.
	if _, err := m.AttachBridge("evi-200", Bridge{Name: "br100", BdID: 200}, ops); err == nil {
		t.Error("bridge name owned by another VRF: want error")
	}
	// Different VRF, same bd_id: refuse.
	if _, err := m.AttachBridge("evi-200", Bridge{Name: "br200", BdID: 100}, ops); err == nil {
		t.Error("bd_id owned by another VRF: want error")
	}
	// Same VRF, same bridge, different bd_id: refuse (the EVPN exporter keys
	// per-BD state by the bd; changing it under an attached facet would
	// strand the old bd's advertisements).
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 300}, ops); err == nil {
		t.Error("bd change under an attached facet: want error")
	}
	// Same VRF, same bridge re-attach: converges (adopt-idempotent).
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100}, ops); err != nil {
		t.Errorf("idempotent re-attach: %v", err)
	}
}

// An ops failure leaves no identity and no facet.
func TestManager_AttachBridge_OpsErrorLeavesNoIdentity(t *testing.T) {
	m := NewManager()
	ops := &fakeBridgeOps{createErr: fmt.Errorf("netlink boom")}
	if _, err := m.AttachBridge("evi-100", Bridge{Name: "br100", BdID: 100}, ops); err == nil {
		t.Fatal("want error from ops")
	}
	if _, ok := m.IDForName("evi-100"); ok {
		t.Error("failed AttachBridge allocated an identity")
	}
}

// SetBridge / RemoveBridge state semantics; clones do not alias the stored
// Members.
func TestManager_BridgeFacetState(t *testing.T) {
	m := NewManager()
	members := []string{"eth2"}
	v, err := m.SetBridge("evi-100", Bridge{Name: "br100", BdID: 100, Members: members, Ifindex: 9})
	if err != nil {
		t.Fatalf("SetBridge: %v", err)
	}
	// Mutations of the input slice and the returned clone must not leak in.
	members[0] = "hacked"
	v.Bridge.Members = append(v.Bridge.Members, "hacked2")
	got, _ := m.Get("evi-100")
	if got.Bridge == nil || len(got.Bridge.Members) != 1 || got.Bridge.Members[0] != "eth2" {
		t.Errorf("stored Bridge.Members corrupted: %+v", got.Bridge)
	}
	if got.Bridge.BdID != 100 || got.Bridge.Ifindex != 9 {
		t.Errorf("stored Bridge identity wrong: %+v", got.Bridge)
	}

	if removed := m.RemoveBridge("evi-100"); !removed {
		t.Error("RemoveBridge: removed = false, want true")
	}
	if removed := m.RemoveBridge("evi-100"); removed {
		t.Error("RemoveBridge idempotent: removed = true, want false")
	}
	if got, _ := m.Get("evi-100"); got.Bridge != nil {
		t.Error("facet still present after RemoveBridge")
	}
	// The identity survives a facet removal (deleting a VRF is explicit).
	if _, ok := m.IDForName("evi-100"); !ok {
		t.Error("identity gone after RemoveBridge")
	}
}

func mustEnsure(t *testing.T, m *Manager, name string) VRF {
	t.Helper()
	v, err := m.Ensure(name)
	if err != nil {
		t.Fatalf("Ensure(%q): %v", name, err)
	}
	return v
}
