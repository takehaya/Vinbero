package plugin

import (
	"os"
	"path/filepath"
	"regexp"
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

// The limit is quoted to users in several places, and a number quoted in
// prose drifts silently: the code was corrected once already while the
// proto comment, the CLI help and the design doc went on saying 196. Users
// read those, so a stale one turns a payload the daemon accepts into one
// they never try.
func TestNoDocumentationStillQuotesTheOldAuxLimit(t *testing.T) {
	root := repoRoot(t)
	// Everything a user could read the limit from.
	files := []string{
		"proto/vinbero/v1/vinbero.proto",
		"proto/vinbero/v1/plugin.proto",
		"pkg/cli/cmd_sid.go",
		"pkg/cli/cmd_plugin.go",
		"sdk/README.md",
		"sdk/go/plugin/doc.go",
		"docs/design/ja/plugin-sdk.md",
		"docs/design/ja/api_sequence.md",
	}
	// The old value, as it appears when it is talking about this limit.
	stale := regexp.MustCompile(`196\s*(bytes|B\b|バイト)`)
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if loc := stale.FindIndex(body); loc != nil {
			t.Errorf("%s still quotes the old aux limit at byte %d; it is %d",
				rel, loc[0], bpf.SidAuxPluginRawMax)
		}
	}
}

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}
