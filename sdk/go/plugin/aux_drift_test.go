package plugin

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// The SDK duplicates two server-side values so callers can import this
// package without pulling in the BPF stack. Nothing but a test keeps the
// copies honest: a stale SidAuxPluginRawMax makes NewPluginAux panic on a
// payload the daemon would have accepted, and a stale owner format makes
// every Get fail with a spurious owner mismatch. Both had drifted before
// this test existed, so it imports the real constants (a test-only
// dependency, which leaves the package's own import surface untouched).

func TestSidAuxPluginRawMaxMatchesServer(t *testing.T) {
	if SidAuxPluginRawMax != bpf.SidAuxPluginRawMax {
		t.Fatalf("SDK SidAuxPluginRawMax = %d, server = %d; a type between the two "+
			"would panic in NewPluginAux despite the daemon accepting it",
			SidAuxPluginRawMax, bpf.SidAuxPluginRawMax)
	}
}

func TestExpectedOwnerMatchesServerTag(t *testing.T) {
	const (
		mapType = "endpoint"
		slot    = 32
	)
	p := &PluginAux[struct{}]{mapType: mapType, slot: slot}
	want := bpf.AuxOwnerPluginTag(mapType, slot)
	if got := p.expectedOwner(); got != want {
		t.Fatalf("expectedOwner() = %q, server mints %q", got, want)
	}
	if !p.ownerMatches(want) {
		t.Fatalf("ownerMatches rejected the tag the server mints: %q", want)
	}
}

// An aux index allocated by an older daemon keeps its unversioned tag in the
// pinned map; rejecting it would make a valid entry unreadable after upgrade.
func TestOwnerMatchesAcceptsLegacyUnversionedTag(t *testing.T) {
	p := &PluginAux[struct{}]{mapType: "endpoint", slot: 32}
	if !p.ownerMatches("plugin:endpoint:32") {
		t.Fatal("legacy unversioned owner tag rejected")
	}
}

func TestOwnerMatchesRejectsAnotherSlot(t *testing.T) {
	p := &PluginAux[struct{}]{mapType: "endpoint", slot: 32}
	for _, tag := range []string{
		bpf.AuxOwnerPluginTag("endpoint", 33),
		bpf.AuxOwnerPluginTag("headend_v4", 32),
		bpf.AuxOwnerBuiltin,
	} {
		if p.ownerMatches(tag) {
			t.Errorf("ownerMatches accepted a foreign owner tag %q", tag)
		}
	}
}
