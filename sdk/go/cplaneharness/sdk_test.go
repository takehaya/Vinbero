package cplaneharness_test

import (
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/sdk/go/cplaneharness"
)

func replayMarker(kind v1.PluginEventKind, source string) *v1.PluginEvent {
	return &v1.PluginEvent{Kind: kind, ReplaySource: source}
}

func TestSDKPluginDefersHeadendAcrossReplayBatchesAndTicks(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:1::1")); err != nil {
		t.Fatal(err)
	}
	before := len(h.Declarations())
	if _, err := h.Deliver(replayMarker(v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, "bgp")); err != nil {
		t.Fatal(err)
	}
	for i, prefix := range []string{"10.1.0.0/24", "10.2.0.0/24"} {
		if _, err := h.Route(advertise(prefix, "fd00:2::1")); err != nil {
			t.Fatal(err)
		}
		if err := h.Tick(time.Duration(i+1) * time.Second); err != nil {
			t.Fatal(err)
		}
		if got := len(h.Declarations()); got != before {
			t.Fatalf("partial replay was applied: %d declarations, want %d", got, before)
		}
	}
	// An unrelated source cannot finish the BGP replay.
	if _, err := h.Deliver(replayMarker(v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, "mac")); err != nil {
		t.Fatal(err)
	}
	if len(h.Declarations()) != before {
		t.Fatal("MAC replay released incomplete BGP state")
	}
	if _, err := h.Deliver(replayMarker(v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, "bgp")); err != nil {
		t.Fatal(err)
	}
	decl, ok := h.LastDeclaration()
	if !ok || len(decl.Entries) != 2 || decl.Entries[0].TriggerPrefix != "10.1.0.0/24" || decl.Entries[1].TriggerPrefix != "10.2.0.0/24" {
		t.Fatalf("completed replay: %+v", decl)
	}
	// Empty replay removes every stale entry, even if no route event arrives.
	before = len(h.Declarations())
	if _, err := h.Deliver(replayMarker(v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, "bgp")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Deliver(replayMarker(v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, "bgp")); err != nil {
		t.Fatal(err)
	}
	decl, _ = h.LastDeclaration()
	if len(h.Declarations()) != before+1 || len(decl.Entries) != 0 {
		t.Fatal("empty replay did not prune stale headend")
	}
}

func TestSDKPluginKeepsPathsWithDifferentRDs(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	first := advertise("10.0.0.7/24", "fd00:1::1")
	second := advertise("10.0.0.0/24", "fd00:2::1")
	second.Rd = "65000:2"
	if _, err := h.Route(first); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Route(second); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Route(withdraw("10.0.0.0/24")); err != nil {
		t.Fatal(err)
	}
	decl, _ := h.LastDeclaration()
	if len(decl.Entries) != 1 || decl.Entries[0].Segments[0] != "fd00:2::1" {
		t.Fatalf("withdrawing one RD lost its alternative: %+v", decl)
	}
}

func TestSDKPluginRemovesPathWhoseBehaviorChanges(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	route := advertise("10.0.0.0/24", "fd00:1::1")
	if _, err := h.Route(route); err != nil {
		t.Fatal(err)
	}
	route.EndpointBehavior = 0x13
	if _, err := h.Route(route); err != nil {
		t.Fatal(err)
	}
	decl, _ := h.LastDeclaration()
	if len(decl.Entries) != 0 {
		t.Fatal("path retained its old behavior after update")
	}
}

func TestSDKPluginRetriesLatestHeadendWithoutNewRouteEvent(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{DenyCommits: true})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:1::1")); err != nil {
		t.Fatal(err)
	}
	// The route changes while commits are refused. Retry must use its latest SID.
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::1")); err != nil {
		t.Fatal(err)
	}
	if len(h.Declarations()) != 0 {
		t.Fatal("refused declaration counted as applied")
	}
	h.SetDenyCommits(false)
	if err := h.Tick(time.Second); err != nil {
		t.Fatal(err)
	}
	decl, _ := h.LastDeclaration()
	if len(decl.Entries) != 1 || decl.Entries[0].Segments[0] != "fd00:2::1" {
		t.Fatalf("retry did not apply latest state: %+v", decl)
	}
	before := len(h.Declarations())
	if err := h.Tick(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if len(h.Declarations()) != before {
		t.Fatal("successful apply stayed pending")
	}
}

func TestSDKPluginRetriesLocalSIDBeforeAdvertising(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config:      exampleConfig(0xFE01, "main", "10.7.0.0/24", "vpn-a", 33, "2001:db8::1"),
		DenyCommits: true,
	})
	if len(h.Declarations()) != 0 {
		t.Fatal("refused allocation was applied")
	}
	h.SetDenyCommits(false)
	if err := h.Tick(time.Second); err != nil {
		t.Fatal(err)
	}
	decls := h.Declarations()
	if len(decls) != 2 || decls[0].Kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID || decls[1].Kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE {
		t.Fatalf("retry must allocate before advertising: %+v", decls)
	}
	if decls[1].Routes[0].Srv6Sid == "" {
		t.Fatal("advertisement has no allocated SID")
	}
}

func TestSDKPluginRetriesCleanupAfterSendingIsDisabled(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: exampleConfig(0xFE01, "main", "10.7.0.0/24", "vpn-a", 33, "2001:db8::1"),
	})
	before := len(h.Declarations())
	h.SetDenyCommits(true)
	h.Reconfigure(nil)
	if len(h.Declarations()) != before {
		t.Fatal("refused cleanup was counted as applied")
	}
	h.SetDenyCommits(false)
	if err := h.Tick(time.Second); err != nil {
		t.Fatal(err)
	}
	cleared := h.Declarations()[before:]
	if len(cleared) != 2 || cleared[0].Kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE || len(cleared[0].Routes) != 0 || cleared[1].Kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID || len(cleared[1].LocalSIDs) != 0 {
		t.Fatalf("retry did not withdraw advertisements and release SIDs: %+v", cleared)
	}
	if err := h.Tick(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if len(h.Declarations()) != before+2 {
		t.Fatal("successful cleanup stayed pending")
	}
}
