package cplane

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func compositionStats(p *PluginOps) PluginStats {
	m := &Manager{leases: p.leases, advertise: &AdvertiseSet{}, localSIDs: &LocalSIDSet{}, quotas: p.quotas}
	return m.statsFor(&plugin{name: "compose", ops: p, worker: &worker{}, counters: newCounters()})
}

func TestCompositionEquivalentServiceQuota(t *testing.T) {
	p, f := compositionOps(t)
	p.quotas.MaxHeadendEntries = 1
	u := desiredComposition(1).MupUplinks[0]
	if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 1, MupUplinks: []*v1.PluginMupUplink{u, u}}); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 1 || len(f.v4) != 1 || compositionStats(p).HeadendEntries != 1 {
		t.Fatal("shared gate or duplicate declaration charged to plugin")
	}
	f.failFTDelete = true
	if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 2}); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if compositionStats(p).HeadendEntries != 1 {
		t.Fatal("retained ownership disappeared from stats")
	}
	f.failFTDelete = false
	p.RetryPending()
	if compositionStats(p).HeadendEntries != 0 {
		t.Fatal("cleaned ownership still counted")
	}
}

func TestCompositionEVPNQuotaMatchesInventory(t *testing.T) {
	p, f := compositionOps(t)
	p.quotas.MaxHeadendEntries = 2 // One peer plus one MAC.
	a := desiredComposition(1).EvpnForwards[0]
	if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 1, EvpnForwards: []*v1.PluginEvpnForward{a, a}}); err != nil {
		t.Fatal(err)
	}
	if len(f.peers) != 1 || len(f.fdb) != 1 || compositionStats(p).HeadendEntries != 2 {
		t.Fatal("equivalent EVPN declarations do not match owned quota units")
	}
	b := *a
	b.Mac = "02:00:00:00:00:02"
	next := &v1.PluginApplyChunk{DesiredRevision: 2, EvpnForwards: []*v1.PluginEvpnForward{a, &b}}
	if err := putComposition(p, next); err == nil {
		t.Fatal("two MACs and a peer fit quota two")
	}
	p.quotas.MaxHeadendEntries = 3
	if err := putComposition(p, next); err != nil {
		t.Fatal(err)
	}
	if len(f.peers) != 1 || len(f.fdb) != 2 || compositionStats(p).HeadendEntries != 3 {
		t.Fatal("MACs sharing one peer miscounted")
	}
	f.failFDBDelete = true
	if err := p.Flush(); err == nil || compositionStats(p).HeadendEntries != 3 {
		t.Fatal("failed cleanup lost ownership accounting")
	}
	f.failFDBDelete = false
	if err := p.Flush(); err != nil || compositionStats(p).HeadendEntries != 0 {
		t.Fatalf("cleanup did not converge: %v", err)
	}
}

func TestCompositionStatsReportIncompleteInventory(t *testing.T) {
	p, f := compositionOps(t)
	f.failV6Inventory = true
	if !strings.Contains(compositionStats(p).OutputFailure, "inventory incomplete") {
		t.Fatal("inventory read failure hidden")
	}
}

func TestCompositionSIDPartialWithdrawalInvalidatesCache(t *testing.T) {
	f := newSIDDependencyFixture(t)
	routes := []AdvertisedRoute{vpnRoute("10.7.0.0/24", f.oldSID.String()), vpnRoute("10.8.0.0/24", f.oldSID.String())}
	if _, err := f.advertisements.Apply(context.Background(), ownerA, routes, unlimited); err != nil {
		t.Fatal(err)
	}
	f.advertiser.failWithdraw = "10.8.0.0/24"
	f.ops.compositionValid = true
	f.ops.applyMu.Lock()
	_, err := f.ops.withdrawSIDReferencesLocked(t.Context(), []LocalSID{{Name: "self", Locator: "main", Slot: 34}})
	f.ops.applyMu.Unlock()
	if err == nil || f.advertisements.LiveCount(ownerA) != 1 || f.ops.compositionValid {
		t.Fatal("partial withdrawal preserved a valid composition cache")
	}
}

func TestRetiredBindingCallbackCannotWithdrawReplacement(t *testing.T) {
	f := newSIDDependencyFixture(t)
	f.ops.strictInputs = true
	f.ops.retire()
	if err := f.ops.Flush(); err != nil {
		t.Fatal(err)
	}
	// A replacement has the same owner but a different desired advertisement.
	if _, err := f.advertisements.Apply(context.Background(), ownerA, []AdvertisedRoute{vpnRoute("10.8.0.0/24", "fd00:1::2")}, unlimited); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ops.ReconcileAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.advertisements.LiveCount(ownerA) != 1 {
		t.Fatal("retired callback withdrew replacement advertisement")
	}
}
