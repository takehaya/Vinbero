package main

import (
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
}

func (p *recordingProg) SetIngressVrf(m map[bpf.IngressACKey]uint32) error {
	p.mapping = m
	return nil
}

func (p *recordingProg) SetIngressPolicy(enabled, defaultDeny bool, _ uint8) error {
	p.enabled, p.deny = enabled, defaultDeny
	return nil
}

func resourceManagerWith(t *testing.T, state string) *netresource.ResourceManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(state), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return m
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
		return restoreVRFs(config.VRFsConfig{DefaultDeny: true}, mgr, prog, resMgr, zap.NewNop())
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
	if id := mgr.Ensure("tenant-b").ID; id != 8 {
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
	if err := restoreVRFs(config.VRFsConfig{}, vrf.NewManager(), &recordingProg{}, resMgr, zap.NewNop()); err == nil {
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
	if err := restoreVRFs(cfg, mgr, prog, resourceManagerWith(t, older), zap.NewNop()); err != nil {
		t.Fatalf("older state: %v", err)
	}
	if id, ok := mgr.IDForName("a"); !ok || id == 0 || prog.mapping[bpf.IngressACKey{Ifindex: loIfindex}] != id {
		t.Errorf("a = %d,%v mapping %v", id, ok, prog.mapping)
	}

	bad := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "a", ACs: []config.VRFACConfig{{Interface: "vanished0"}}}}}
	if err := restoreVRFs(bad, vrf.NewManager(), &recordingProg{}, resourceManagerWith(t, older), zap.NewNop()); err == nil {
		t.Error("an unresolved config-declared AC did not fail the boot")
	}

	// The same interface recorded as a runtime AC does not soften the config's rule.
	taken := `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":2,"entries":[
		{"name":"a","vrf_id":1,"runtime_acs":[{"interface":"vanished0","vlan":0}]}]}}`
	if err := restoreVRFs(bad, vrf.NewManager(), &recordingProg{}, resourceManagerWith(t, taken), zap.NewNop()); err == nil {
		t.Error("a config AC the state calls runtime was skipped instead of failing")
	}
}
