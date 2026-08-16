package plugin

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
// proto comment, the CLI help and the design doc went on saying the old
// value. Users read those, so a stale one turns a payload the daemon
// accepts into one they never try.
//
// Each figure is extracted and compared against the real constant rather
// than checked against the value it used to be. Banning the old number
// would pass the next time the limit moves, and would fail on an unrelated
// number that happened to match.
func TestEveryDocumentedAuxLimitMatchesTheConstant(t *testing.T) {
	// Each place a user can read the limit, with the shape it is written
	// in. The pattern captures the figure; a file that stops mentioning it
	// fails too, because a limit nobody documents is its own problem.
	quoted := []struct {
		file    string
		pattern string
	}{
		{"proto/vinbero/v1/vinbero.proto", `<= (\d+) bytes, cast by plugin`},
		{"proto/vinbero/v1/plugin.proto", `SidAuxPluginRawMax \((\d+)\)`},
		{"pkg/cli/cmd_sid.go", `<= (\d+) bytes after decode`},
		{"pkg/cli/cmd_plugin.go", `Raw payload as hex \(<= (\d+) bytes\)`},
		{"sdk/README.md", `\((\d+) bytes\)`},
		{"sdk/go/plugin/doc.go", `<= (\d+) \(SidAuxPluginRawMax\)`},
		// Anchored on the aux payload: this document also states the BPF
		// stack limit in the same words, and that one is not this one.
		{"docs/design/ja/plugin-sdk.md", "plugin_raw` \\((\\d+) バイト\\)"},
		{"docs/design/ja/plugin-sdk.md", `(\d+) バイト以下の byte 列`},
		{"docs/design/ja/api_sequence.md", `bytes \((\d+)B 以内\)`},
	}
	root := repoRoot(t)
	for _, q := range quoted {
		body, err := os.ReadFile(filepath.Join(root, q.file))
		if err != nil {
			t.Errorf("read %s: %v", q.file, err)
			continue
		}
		re := regexp.MustCompile(q.pattern)
		found := re.FindAllStringSubmatch(string(body), -1)
		if len(found) == 0 {
			t.Errorf("%s no longer states the aux limit; it should say %d",
				q.file, bpf.SidAuxPluginRawMax)
			continue
		}
		for _, m := range found {
			got, err := strconv.Atoi(m[1])
			if err != nil {
				t.Errorf("%s: %q is not a number", q.file, m[1])
				continue
			}
			if got != bpf.SidAuxPluginRawMax {
				t.Errorf("%s says the aux limit is %d; it is %d",
					q.file, got, bpf.SidAuxPluginRawMax)
			}
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
