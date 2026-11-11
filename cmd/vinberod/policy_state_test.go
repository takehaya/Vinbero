package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vrf"
)

type policyNode struct {
	res  *netresource.ResourceManager
	mgr  *vrf.Manager
	prog *recordingProg
	srv  *server.VrfServer
}

func bootPolicy(path string, cfg config.VRFsConfig) (*policyNode, error) {
	res, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		return nil, err
	}
	mgr, prog := vrf.NewManager(), &recordingProg{}
	if err := restoreVRFs(cfg, nil, false, mgr, prog, nil, res, zap.NewNop()); err != nil {
		return nil, err
	}
	srv := server.NewVrfServer(mgr, prog, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	srv.SetPolicyStore(vrfPolicyStore(res, cfg))
	return &policyNode{res: res, mgr: mgr, prog: prog, srv: srv}, nil
}

func mustBootPolicy(t *testing.T, path string, cfg config.VRFsConfig) *policyNode {
	t.Helper()
	n, err := bootPolicy(path, cfg)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	return n
}

func (n *policyNode) set(deny bool, action string) error {
	_, err := n.srv.VrfSetPolicy(context.Background(), connect.NewRequest(&v1.VrfSetPolicyRequest{
		Policy: &v1.VrfPolicy{DefaultDeny: deny, DenyAction: action}}))
	return err
}

func vrfsConfig(t *testing.T, yaml string) config.VRFsConfig {
	t.Helper()
	cfg, err := config.Load(yaml)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.VRFs
}

// The policy set over the API is in force from the first packet after a
// restart: restored before the data plane is programmed.
func TestVRFPolicyRestart_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootPolicy(t, path, config.VRFsConfig{})
	if err := n.set(true, "pass"); err != nil {
		t.Fatal(err)
	}
	n2 := mustBootPolicy(t, path, config.VRFsConfig{})
	if got := n2.mgr.Policy(); !got.DefaultDeny || got.DenyAction != vrf.DenyActionPass {
		t.Errorf("policy after restart = %+v", got)
	}
	if !n2.prog.enabled || !n2.prog.deny {
		t.Errorf("data plane after restart: enabled=%v deny=%v", n2.prog.enabled, n2.prog.deny)
	}
	if err := n2.set(false, "drop"); err != nil {
		t.Fatal(err)
	}
	n3 := mustBootPolicy(t, path, config.VRFsConfig{})
	if got := n3.mgr.Policy(); got.DefaultDeny || n3.prog.deny {
		t.Errorf("policy after setting it back and restarting = %+v (deny written %v)", got, n3.prog.deny)
	}
}

// A config file that states the policy owns it, even with the default value:
// the saved one is dropped from the file, and a change over the API is not
// saved.
func TestVRFPolicyRestart_ConfigWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootPolicy(t, path, config.VRFsConfig{})
	if err := n.set(true, "drop"); err != nil {
		t.Fatal(err)
	}
	declared := vrfsConfig(t, "vrfs:\n  default_deny: false\n")
	if !declared.PolicyDeclared() {
		t.Fatal("default_deny: false is not read as declared")
	}
	n2 := mustBootPolicy(t, path, declared)
	if n2.mgr.Policy().DefaultDeny || n2.prog.deny {
		t.Errorf("the saved policy beat the config: %+v", n2.mgr.Policy())
	}
	if n2.res.RuntimeVrfPolicy() != nil {
		t.Errorf("the dropped policy is still recorded: %+v", n2.res.RuntimeVrfPolicy())
	}
	if err := n2.set(true, "pass"); err != nil {
		t.Fatal(err)
	}
	if n2.res.RuntimeVrfPolicy() != nil {
		t.Error("a change of the config's policy was saved")
	}
	// Without the key the config does not own it, and nothing saved comes
	// back after the drop.
	if vrfsConfig(t, "vrfs:\n  entries: []\n").PolicyDeclared() {
		t.Error("a vrfs section without the keys is read as declared")
	}
	n3 := mustBootPolicy(t, path, config.VRFsConfig{})
	if n3.mgr.Policy().DefaultDeny {
		t.Error("the dropped policy came back")
	}
}

// A change whose save fails leaves memory and the data plane as they were,
// and the same call made again succeeds and is written.
func TestVRFPolicyRestart_SaveFailureThenRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootPolicy(t, path, config.VRFsConfig{})
	if err := n.set(false, "drop"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	err := n.set(true, "pass")
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("set with a failed save: %v", err)
	}
	if got := n.mgr.Policy(); got.DefaultDeny || got.DenyAction != vrf.DenyActionDrop {
		t.Errorf("policy after a failed save = %+v", got)
	}
	if n.prog.deny {
		t.Error("the data plane kept the refused policy")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := n.set(true, "pass"); err != nil {
		t.Fatal(err)
	}
	n2 := mustBootPolicy(t, path, config.VRFsConfig{})
	if got := n2.mgr.Policy(); !got.DefaultDeny || got.DenyAction != vrf.DenyActionPass {
		t.Errorf("policy after the retry and a restart = %+v", got)
	}
}

// A saved deny action this version does not know stops the start.
func TestVRFPolicyRestart_RefusesBadRecord(t *testing.T) {
	_, path := resourceManagerAt(t, `{"runtime_vrf_policy":{"default_deny":true,"deny_action":"reject"}}`)
	if _, err := bootPolicy(path, config.VRFsConfig{}); err == nil {
		t.Error("booted with an unknown deny action")
	}
}
