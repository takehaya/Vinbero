package cplane

import (
	"context"
	"errors"
	"testing"
)

func TestUnrestoredPolicyCannotBecomeLegacy(t *testing.T) {
	m := &Manager{plugins: map[string]*plugin{}, unrestored: map[string]UnrestoredPlugin{}}
	m.recordUnrestored(Registration{Name: "compose", Input: compositionPolicy()}, errors.New("module unavailable after restart"))
	if err := m.checkInputRegistration(Registration{Name: "compose"}, nil); err == nil {
		t.Fatal("accepted nil input for unrestored delegated owner before cleanup")
	}
}

func TestUnrestoredPolicyRemovalKeepsOwnership(t *testing.T) {
	old, f := compositionOps(t)
	if err := putComposition(old, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{Source: &compositionSource{newFakeSource()}, Headend: f, ForwardingMaps: f})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	m.recordUnrestored(Registration{Name: "compose", Input: compositionPolicy()}, errors.New("module unavailable after restart"))
	err = m.Register(context.Background(), Registration{Name: "compose", Module: fixtureModule(t, "echo")})
	if err == nil {
		t.Fatal("accepted policy removal before cleanup")
	}
	if len(m.Unrestored()) != 1 {
		t.Fatal("lost unrestored owner")
	}
	if len(f.uplinks) != 1 || len(f.peers) != 1 || len(f.fdb) != 1 {
		t.Fatal("changed retained ownership")
	}
	if err := m.Unregister(context.Background(), "compose"); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(context.Background(), Registration{Name: "compose", Module: fixtureModule(t, "echo")}); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) > 0 || len(f.peers) > 0 || len(f.fdb) > 0 {
		t.Fatalf("successful legacy registration cleared unrestored owner but retained old service state: uplinks=%d peers=%d fdb=%d unrestored=%d", len(f.uplinks), len(f.peers), len(f.fdb), len(m.unrestored))
	}
}
