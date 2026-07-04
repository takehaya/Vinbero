package netresource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A missing state file is a fresh install, not an error.
func TestLoadState_MissingFileStartsEmpty(t *testing.T) {
	m, err := NewResourceManager(filepath.Join(t.TempDir(), "state.json"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewResourceManager on a missing file: %v", err)
	}
	if len(m.ListVrfs()) != 0 || len(m.ListBridges()) != 0 {
		t.Errorf("fresh state not empty: vrfs=%v bridges=%v", m.ListVrfs(), m.ListBridges())
	}
}

// A state file that exists but does not parse must refuse the boot with the
// path and a repair hint -- starting empty would silently abandon every
// managed device.
func TestNewResourceManager_CorruptStateFails(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"truncated": `{"vrfs": [{"name": "vrf1", "tab`,
		"garbage":   "not json at all",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := NewResourceManager(path, zap.NewNop())
			if err == nil {
				t.Fatal("corrupt state must fail NewResourceManager")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error should name the file, got: %v", err)
			}
			if !strings.Contains(err.Error(), "repair") {
				t.Errorf("error should carry the repair hint, got: %v", err)
			}
		})
	}
}

// The atomic write leaves the exact content and no temp-file droppings.
func TestWriteFileAtomic_SuccessLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, content := range []string{`{"a":1}`, `{"a":2,"b":3}`} {
		if err := writeFileAtomic(path, []byte(content)); err != nil {
			t.Fatalf("writeFileAtomic: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("content = %q (err %v), want %q", got, err, content)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("temp droppings left behind: %v", entries)
	}
}

// A failed write leaves the previous file byte-identical -- the property the
// temp+rename construction exists for. The old O_TRUNC write destroyed the
// file first and wrote second.
func TestWriteFileAtomic_FailurePreservesOldContent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection is bypassed by root (CAP_DAC_OVERRIDE)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	const old = `{"vrfs":[],"bridges":[]}`
	if err := writeFileAtomic(path, []byte(old)); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
	if err := writeFileAtomic(path, []byte(`{"new":true}`)); err == nil {
		t.Fatal("write into a read-only directory must fail")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != old {
		t.Errorf("old content damaged by a failed write: %q (err %v)", got, err)
	}
}

// persist failures surface as errors (works under root too: renaming a file
// onto a directory fails regardless of privileges).
func TestPersist_FailurePropagates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatalf("NewResourceManager: %v", err)
	}
	if err := m.persist(); err != nil {
		t.Fatalf("initial persist: %v", err)
	}
	// Replace the state file with a directory: the rename step cannot win.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := m.persist(); err == nil {
		t.Fatal("persist onto a directory must fail")
	}
}
