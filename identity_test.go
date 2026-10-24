package buildidentity

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A newly added source directory must not silently escape the embed patterns.
func TestFingerprintCoversCurrentSources(t *testing.T) {
	for _, root := range []string{"sdk/go/cplane", "pkg/cplane/native"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			got, err := sources.ReadFile(filepath.ToSlash(path))
			if err != nil {
				t.Errorf("fingerprint omits %s: %v", path, err)
				return nil
			}
			want, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if string(got) != string(want) {
				t.Errorf("stale embedded source: %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(Source) != 64 || Source != sourceDigest() {
		t.Fatal("invalid or nondeterministic fingerprint")
	}
}
