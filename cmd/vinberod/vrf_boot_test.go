package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrf"
	"go.uber.org/zap"
)

type recordingProg struct {
	mapping map[bpf.IngressACKey]uint32
	enabled bool
	deny    bool
	// onWrite runs when ingress_vrf_map is written.
	onWrite func()
}

func (p *recordingProg) SetIngressVrf(m map[bpf.IngressACKey]uint32) error {
	p.mapping = m
	if p.onWrite != nil {
		p.onWrite()
	}
	return nil
}

func (p *recordingProg) SetIngressPolicy(enabled, defaultDeny bool, _ uint8) error {
	p.enabled, p.deny = enabled, defaultDeny
	return nil
}

func resourceManagerWith(t *testing.T, state string) *netresource.ResourceManager {
	m, _ := resourceManagerAt(t, state)
	return m
}

func resourceManagerAt(t *testing.T, state string) (*netresource.ResourceManager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(state), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return m, path
}

// savedIDs reads the vrf_ids the state file at path holds.
func savedIDs(t *testing.T, path string) map[string]uint32 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		VrfObjects *struct {
			Entries []struct {
				Name  string `json:"name"`
				VrfID uint32 `json:"vrf_id"`
			} `json:"entries"`
		} `json:"vrf_objects"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	ids := map[string]uint32{}
	if st.VrfObjects != nil {
		for _, e := range st.VrfObjects.Entries {
			ids[e.Name] = e.VrfID
		}
	}
	return ids
}

const loIfindex = 1

// The classification a saved runtime AC gives is in the map before any device
// is attached, with the id it had before the restart.
func TestBringUpDataPlane_ClassifiesBeforeAttach(t *testing.T) {
	resMgr := resourceManagerWith(t, `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":8,"entries":[
		{"name":"tenant-a","vrf_id":7,"runtime_acs":[{"interface":"lo","vlan":0},{"interface":"vanished0","vlan":0}]}]}}`)
	mgr := vrf.NewManager()
	prog := &recordingProg{}
	attached := false
	err := bringUpDataPlane(func() error {
		return restoreVRFs(config.VRFsConfig{DefaultDeny: true}, nil, false, mgr, prog, nil, resMgr, zap.NewNop())
	}, func() error {
		attached = true
		if got := prog.mapping[bpf.IngressACKey{Ifindex: loIfindex}]; got != 7 {
			t.Errorf("at attach time lo -> %d (mapping %v), want 7", got, prog.mapping)
		}
		if !prog.enabled || !prog.deny {
			t.Errorf("at attach time enabled=%v deny=%v, want the policy written", prog.enabled, prog.deny)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("bringUpDataPlane: %v", err)
	}
	if !attached {
		t.Fatal("attach did not run")
	}
	if id := mustEnsure(t, mgr, "tenant-b").ID; id != 8 {
		t.Errorf("next allocated id = %d, want 8", id)
	}
}

// Nothing is attached when the classification cannot be programmed.
func TestBringUpDataPlane_NoAttachOnClassifyFailure(t *testing.T) {
	want := errors.New("boom")
	err := bringUpDataPlane(func() error { return want }, func() error {
		t.Error("attach ran after a failed classification")
		return nil
	})
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

// A state file that gives one id to two VRFs refuses the boot.
func TestRestoreVRFs_ContradictoryStateIsFatal(t *testing.T) {
	resMgr := resourceManagerWith(t, `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":2,"entries":[
		{"name":"a","vrf_id":1},{"name":"b","vrf_id":1}]}}`)
	if err := restoreVRFs(config.VRFsConfig{}, nil, false, vrf.NewManager(), &recordingProg{}, nil, resMgr, zap.NewNop()); err == nil {
		t.Fatal("restoreVRFs accepted a duplicated id")
	}
}

// A file from before identities were recorded boots: ids are assigned and the
// config's unresolved AC is still fatal.
func TestRestoreVRFs_OlderStateAndConfigACRules(t *testing.T) {
	older := `{"vrfs":[],"bridges":[]}`
	cfg := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "a", ACs: []config.VRFACConfig{{Interface: "lo"}}}}}
	mgr := vrf.NewManager()
	prog := &recordingProg{}
	if err := restoreVRFs(cfg, nil, false, mgr, prog, nil, resourceManagerWith(t, older), zap.NewNop()); err != nil {
		t.Fatalf("older state: %v", err)
	}
	if id, ok := mgr.IDForName("a"); !ok || id == 0 || prog.mapping[bpf.IngressACKey{Ifindex: loIfindex}] != id {
		t.Errorf("a = %d,%v mapping %v", id, ok, prog.mapping)
	}

	bad := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "a", ACs: []config.VRFACConfig{{Interface: "vanished0"}}}}}
	if err := restoreVRFs(bad, nil, false, vrf.NewManager(), &recordingProg{}, nil, resourceManagerWith(t, older), zap.NewNop()); err == nil {
		t.Error("an unresolved config-declared AC did not fail the boot")
	}

	// The same interface recorded as a runtime AC does not soften the config's rule.
	taken := `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":2,"entries":[
		{"name":"a","vrf_id":1,"runtime_acs":[{"interface":"vanished0","vlan":0}]}]}}`
	if err := restoreVRFs(bad, nil, false, vrf.NewManager(), &recordingProg{}, nil, resourceManagerWith(t, taken), zap.NewNop()); err == nil {
		t.Error("a config AC the state calls runtime was skipped instead of failing")
	}
}

// On a state file without saved ids, the ids come out in the order the daemon
// used before they were saved: the config's vrf_bindings first, then the
// state's device records, then vrfs.entries.
func TestRestoreVRFs_FirstBootKeepsTheAllocationOrder(t *testing.T) {
	older := `{"vrfs":[{"name":"dev-x","table_id":100,"members":null,"enable_l3mdev_rule":false,"ifindex":5}],"bridges":[]}`
	cfg := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "entry-c", ACs: []config.VRFACConfig{{Interface: "lo"}}}}}

	mgr := vrf.NewManager()
	if err := restoreVRFs(cfg, []string{"bind-a", "bind-b"}, true, mgr, &recordingProg{}, nil, resourceManagerWith(t, older), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint32{"bind-a": 1, "bind-b": 2, "dev-x": 3, "entry-c": 4} {
		if id, _ := mgr.IDForName(name); id != want {
			t.Errorf("%s = %d, want %d", name, id, want)
		}
	}

	// Without BGP the bindings are not loaded, as before.
	mgr = vrf.NewManager()
	if err := restoreVRFs(cfg, []string{"bind-a", "bind-b"}, false, mgr, &recordingProg{}, nil, resourceManagerWith(t, older), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint32{"dev-x": 1, "entry-c": 2} {
		if id, _ := mgr.IDForName(name); id != want {
			t.Errorf("without BGP %s = %d, want %d", name, id, want)
		}
	}
	if _, ok := mgr.IDForName("bind-a"); ok {
		t.Error("binding VRF allocated without BGP")
	}
}

// The ids are in the state file before ingress_vrf_map is written.
func TestRestoreVRFs_SavesBeforeTheDataPlane(t *testing.T) {
	resMgr, path := resourceManagerAt(t, `{"vrfs":[],"bridges":[]}`)
	cfg := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "a", ACs: []config.VRFACConfig{{Interface: "lo"}}}}}
	mgr := vrf.NewManager()
	var atWrite map[string]uint32
	prog := &recordingProg{onWrite: func() { atWrite = savedIDs(t, path) }}
	if err := restoreVRFs(cfg, []string{"b"}, true, mgr, prog, nil, resMgr, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	a, _ := mgr.IDForName("a")
	b, _ := mgr.IDForName("b")
	if atWrite["a"] != a || atWrite["b"] != b || a == 0 || b == 0 {
		t.Errorf("state file at the map write = %v, want a=%d b=%d", atWrite, a, b)
	}
}

// A VRF the config created and no longer declares, holding nothing, is not
// restored and its id is not handed out again. One created over the API is.
func TestRestoreVRFs_DropsUndeclaredConfigVRFs(t *testing.T) {
	resMgr, path := resourceManagerAt(t, `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":4,"entries":[
		{"name":"cfg-old","vrf_id":1,"config":true},
		{"name":"api","vrf_id":2},
		{"name":"cfg-kept","vrf_id":3,"config":true}]}}`)
	cfg := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "cfg-kept"}}}
	mgr := vrf.NewManager()
	if err := restoreVRFs(cfg, nil, false, mgr, &recordingProg{}, nil, resMgr, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Get("cfg-old"); ok {
		t.Error("undeclared config VRF restored")
	}
	if got := savedIDs(t, path); len(got) != 2 || got["api"] != 2 || got["cfg-kept"] != 3 {
		t.Errorf("saved %v, want api and cfg-kept only", got)
	}
	if id := mustEnsure(t, mgr, "new").ID; id != 4 {
		t.Errorf("new VRF id = %d, want 4", id)
	}
}

type registrar map[int]uint16

func (r registrar) RegisterBridge(ifindex int, bdID uint16) { r[ifindex] = bdID }

// Every bridge facet reaches the FDB watcher, and registering before the VRF
// objects are restored fails instead of watching nothing.
func TestWatchBridgeFacets(t *testing.T) {
	mgr := vrf.NewManager()
	if _, err := mgr.SetBridge("evi", vrf.Bridge{Name: "br100", BdID: 100, Ifindex: 42}); err != nil {
		t.Fatal(err)
	}
	if err := watchBridgeFacets(mgr, registrar{}); err == nil {
		t.Fatal("registration before the restore succeeded")
	}
	mgr.FinishRestore([]string{"evi"})
	r := registrar{}
	if err := watchBridgeFacets(mgr, r); err != nil {
		t.Fatal(err)
	}
	if r[42] != 100 || len(r) != 1 {
		t.Errorf("registered %v, want 42 -> 100", r)
	}
}

func mustEnsure(t *testing.T, m *vrf.Manager, name string) vrf.VRF {
	t.Helper()
	v, err := m.Ensure(name)
	if err != nil {
		t.Fatalf("Ensure(%q): %v", name, err)
	}
	return v
}
