package cplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
)

func TestUnregisterUnrestoredDoesNotReplayPrivateBehavior(t *testing.T) {
	ctx := context.Background()
	feed := &rollbackRouteFeed{}
	claims := demux.NewClaimRegistry(nil)
	source := demux.New(feed, nil, nil)
	source.SetClaimRegistry(claims)
	t.Cleanup(source.Stop)
	installed := map[string]bool{}
	privateInstalls := 0
	if _, err := source.RegisterBuiltin("builtin", []bgp.Family{bgp.FamilyVPNv4}, func(event bgp.RouteEvent) {
		if event.IsWithdraw {
			delete(installed, event.VPN.Prefix)
			return
		}
		installed[event.VPN.Prefix] = true
		if event.EndpointBehavior == 0xFE01 {
			privateInstalls++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Start(); err != nil {
		t.Fatal(err)
	}
	store := newTestStore(t)
	if err := store.Save(Registration{Name: "broken", Module: []byte("missing module"), Behaviors: []uint16{0xFE01}}); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{Source: source, Claims: claims, Store: store, Headend: newFakeHeadendOps()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(ctx) })
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if len(m.Unrestored()) != 1 || !claims.IsClaimed(0xFE01) {
		t.Fatal("failed restore did not retain its behavior claim")
	}
	ordinary := bgp.RouteEvent{Family: bgp.FamilyVPNv4, Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")},
		VPN: &bgp.VPNRoute{RD: "65000:1", Prefix: "10.20.0.0/24"}, EndpointBehavior: 0x0013}
	private := ordinary
	private.VPN = &bgp.VPNRoute{RD: "65000:1", Prefix: "10.21.0.0/24"}
	private.EndpointBehavior = 0xFE01
	feed.emit(ordinary)
	feed.emit(private)
	if !installed[ordinary.VPN.Prefix] || installed[private.VPN.Prefix] {
		t.Fatal("unexpected forwarding before unregister")
	}
	if err := m.Unregister(ctx, "broken"); err != nil {
		t.Fatal(err)
	}
	if privateInstalls != 0 || installed[private.VPN.Prefix] || !installed[ordinary.VPN.Prefix] {
		t.Fatalf("unregister replayed a private behavior: installed=%v private_installs=%d", installed, privateInstalls)
	}
	if claims.IsClaimed(0xFE01) || len(m.Unrestored()) != 0 {
		t.Fatal("unregister retained the removed registration")
	}
	regs, err := store.List()
	if err != nil || len(regs) != 0 {
		t.Fatalf("unregister retained persistent registration: %v %v", regs, err)
	}
	feed.emit(private)
	if privateInstalls != 1 {
		t.Fatal("a fresh advertisement remained blocked after claim release")
	}
}
