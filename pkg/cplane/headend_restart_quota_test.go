package cplane

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func TestHeadendQuotaAfterRestart(t *testing.T) {
	maps := newFakeHeadendOps()
	// Persisted v6 dispatch + owner survive daemon restart; leases do not.
	entry := &bpf.HeadendEntry{Mode: 1, NumSegments: 1}
	if err := maps.CreateHeadendV6("fd00:1::/64", entry, ownerA); err != nil {
		t.Fatal(err)
	}
	leases := NewLeases()
	p, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: maps, Leases: leases,
		Capabilities: wasm.Capabilities{wasm.CapHeadend: {}},
		Guard:        NewGuard(testScope(), nil, nil),
		Quotas:       Quotas{MaxHeadendEntries: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	// This is the registration/restore authorization cleanup.
	if _, err := p.PruneOutOfScope(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	err = p.applyTransaction(&applyTxn{
		kind: v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4, seq: 1,
		entries: []HeadendDesired{{TriggerPrefix: "10.0.1.0/24", Entry: entry}},
	})
	v4, _ := maps.ListHeadendV4()
	v6, _ := maps.ListHeadendV6()
	t.Logf("quota=1; retained v6=%d; new v4=%d; apply error=%v", len(v6), len(v4), err)
	var quotaErr *QuotaError
	if !errors.As(err, &quotaErr) || quotaErr.Declared != 2 || quotaErr.Quota != 1 {
		t.Fatalf("expected combined-family quota refusal, got %v", err)
	}
	if len(v4) != 0 || len(v6) != 1 {
		t.Fatal("quota refusal changed retained entries")
	}
}

func TestHeadendQuotaLoweringAllowsAuthorizationPrune(t *testing.T) {
	maps := newFakeHeadendOps()
	entry := &bpf.HeadendEntry{Mode: 1}
	for _, prefix := range []string{"10.0.1.0/24", "10.0.2.0/24"} {
		if err := maps.CreateHeadendV4(prefix, entry, ownerA); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{"fd00:1::/64", "fd00:2::/64"} {
		if err := maps.CreateHeadendV6(prefix, entry, ownerA); err != nil {
			t.Fatal(err)
		}
	}
	// Restart with smaller quota, then revoke all capabilities/scope.
	p, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: maps, Quotas: Quotas{MaxHeadendEntries: 1}})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := p.PruneOutOfScope(context.Background())
	v4, _ := maps.ListHeadendV4()
	v6, _ := maps.ListHeadendV6()
	t.Logf("removed=%d v4=%d v6=%d err=%v", removed, len(v4), len(v6), err)
	if err != nil || len(v4)+len(v6) != 0 {
		t.Fatal("quota must not prevent revoking previously authorized state")
	}
}
