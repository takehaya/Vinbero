package cplane

import (
	"errors"
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/headend"
)

func familyComposition(t *testing.T) (*PluginOps, *serviceFake) {
	t.Helper()
	p, f := compositionOps(t)
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "fd00::/8"}})
	if err != nil {
		t.Fatal(err)
	}
	p.guard = NewGuard(scope, nil, nil)
	return p, f
}

func headendComposition(revision uint64, prefixes ...string) *v1.PluginApplyChunk {
	m := &v1.PluginApplyChunk{DesiredRevision: revision}
	for _, prefix := range prefixes {
		h := desiredComposition(revision).ForwardingHeadends[0]
		h.Entry.TriggerPrefix = prefix
		m.ForwardingHeadends = append(m.ForwardingHeadends, h)
	}
	return m
}

func TestCompositionHeadendFamilyReplacementAtQuota(t *testing.T) {
	for _, prefixes := range [][2]string{{"fd00:10::1/128", "10.0.0.1/32"}, {"10.0.0.1/32", "fd00:10::1/128"}} {
		t.Run(prefixes[0], func(t *testing.T) {
			p, f := familyComposition(t)
			p.quotas.MaxHeadendEntries = 1
			if err := putComposition(p, headendComposition(1, prefixes[0])); err != nil {
				t.Fatal(err)
			}
			if err := putComposition(p, headendComposition(2, prefixes[1])); err != nil {
				t.Fatal(err)
			}
			if len(f.v4)+len(f.v6) != 1 || p.appliedRevision != 2 || compositionStats(p).HeadendEntries != 1 {
				t.Fatal("valid one-key family replacement did not converge")
			}
		})
	}
}

func TestCompositionFamilyPruneFailureBlocksAllocation(t *testing.T) {
	p, f := familyComposition(t)
	p.quotas.MaxHeadendEntries = 1
	if err := putComposition(p, headendComposition(1, "fd00:10::1/128")); err != nil {
		t.Fatal(err)
	}
	f.failDelete("fd00:10::1/128")
	if err := putComposition(p, headendComposition(2, "10.0.0.1/32")); err == nil || len(f.v4) != 0 || len(f.v6) != 1 {
		t.Fatal("allocated replacement before obsolete key deletion succeeded")
	}
	f.failDelete("")
	p.RetryPending()
	if len(f.v4) != 1 || len(f.v6) != 0 || p.appliedRevision != 2 {
		t.Fatal("cross-family retry did not recover")
	}
}

func TestCompositionFamilyPrunePreservesRetainedKey(t *testing.T) {
	p, f := familyComposition(t)
	p.quotas.MaxHeadendEntries = 2
	if err := putComposition(p, headendComposition(1, "10.0.0.1/32", "fd00:10::1/128")); err != nil {
		t.Fatal(err)
	}
	if err := putComposition(p, headendComposition(2, "10.0.0.1/32", "10.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	for _, write := range f.writes {
		if write == "delete v4 10.0.0.1/32" {
			t.Fatal("temporarily withdrew retained key")
		}
	}
	if len(f.v4) != 2 || len(f.v6) != 0 {
		t.Fatal("wrong final family inventory")
	}
}

func TestColdHeadendStatsIncludeRetainedOwnership(t *testing.T) {
	p, f := familyComposition(t)
	if err := putComposition(p, headendComposition(1, "10.0.0.1/32", "fd00:10::1/128")); err != nil {
		t.Fatal(err)
	}
	r, err := headend.NewReconciler(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewPluginOps(PluginOpsConfig{Owner: p.owner, HeadendReconciler: r, Capabilities: p.caps, Guard: p.guard})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.PruneOutOfScope(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compositionStats(restored).HeadendEntries != 2 {
		t.Fatal("cold permitted ownership requires guest redeclaration to be counted")
	}
	f.failDelete("10.0.0.1/32")
	if err := restored.Flush(); err == nil || compositionStats(restored).HeadendEntries != 1 {
		t.Fatal("failed ordinary deletion lost usage")
	}
	f.failDelete("")
	if err := restored.Flush(); err != nil || compositionStats(restored).HeadendEntries != 0 {
		t.Fatal("completed cold cleanup still counted")
	}
}

func TestOrdinaryInventoryFailurePreservesOtherUsageAndFailure(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	f.listErr = errors.New("headend inventory failed")
	p.outputFailure = "prior apply failure"
	stats := compositionStats(p)
	if stats.HeadendEntries != 3 || !strings.Contains(stats.OutputFailure, "prior apply failure") || !strings.Contains(stats.OutputFailure, "inventory incomplete") {
		t.Fatalf("partial ordinary inventory hid service ownership or prior failure: %+v", stats)
	}
}
