package cplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "plugins"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s
}

func storedRegistration(t *testing.T) Registration {
	t.Helper()
	return Registration{
		Name:         "declare",
		Module:       declareModule(t),
		Families:     []bgp.Family{bgp.FamilyVPNv4},
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(),
		TickInterval: 250 * time.Millisecond,
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	want := storedRegistration(t)
	if err := s.Save(want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("stored %d registrations, want 1", len(got))
	}
	r := got[0]
	if r.Name != want.Name {
		t.Errorf("name = %q, want %q", r.Name, want.Name)
	}
	if len(r.Module) != len(want.Module) {
		t.Errorf("module is %d bytes, want %d", len(r.Module), len(want.Module))
	}
	if len(r.Families) != 1 || r.Families[0] != bgp.FamilyVPNv4 {
		t.Errorf("families = %v", r.Families)
	}
	if len(r.Behaviors) != 1 || r.Behaviors[0] != 0xFE01 {
		t.Errorf("behaviors = %v", r.Behaviors)
	}
	if !r.Capabilities.Has(wasm.CapHeadend) {
		t.Errorf("capabilities = %v, want the saved set", r.Capabilities.Names())
	}
	if r.TickInterval != 250*time.Millisecond {
		t.Errorf("tick interval = %s, want 250ms", r.TickInterval)
	}
}

// Saving the same name again replaces what was there, so an upgrade does
// not leave the previous module behind to be restored later.
func TestStoreSaveReplaces(t *testing.T) {
	s := newTestStore(t)
	reg := storedRegistration(t)
	if err := s.Save(reg); err != nil {
		t.Fatalf("first save: %v", err)
	}
	reg.Behaviors = []uint16{0xFE02}
	if err := s.Save(reg); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || len(got[0].Behaviors) != 1 || got[0].Behaviors[0] != 0xFE02 {
		t.Fatalf("stored %+v, want only the second save", got)
	}
}

func TestStoreRemove(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save(storedRegistration(t)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.Remove("declare"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("store still holds %d registrations", len(got))
	}
	// Removing what is not there is how unregistering a plugin the store
	// never held has to behave.
	if err := s.Remove("declare"); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
}

// A bundle name is the file name too, so a name that could leave the
// directory must be refused rather than written wherever it points.
func TestStoreRefusesUnsafeNames(t *testing.T) {
	s := newTestStore(t)
	for _, name := range []string{"../escape", "with/slash", ".hidden", ""} {
		if err := s.Save(Registration{Name: name, Module: []byte{0}}); err == nil {
			t.Errorf("name %q was accepted", name)
		}
		if err := s.Remove(name); err == nil {
			t.Errorf("removing name %q was accepted", name)
		}
	}
}

// A manifest from a format this daemon does not write is reported rather
// than misread.
func TestStoreRefusesAnUnknownManifestVersion(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save(storedRegistration(t)); err != nil {
		t.Fatalf("save: %v", err)
	}
	path := filepath.Join(s.Dir(), "declare.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	bumped := bytes.Replace(body, []byte(`"version": 1`), []byte(`"version": 99`), 1)
	if bytes.Equal(bumped, body) {
		t.Fatalf("could not find the version field in %s", body)
	}
	if err := os.WriteFile(path, bumped, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a manifest from an unknown version was accepted")
	}
}

// A nil store is the "no persistence" configuration, and every call has
// to be safe on it so the manager needs no branch of its own.
func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	if err := s.Save(Registration{Name: "declare"}); err != nil {
		t.Errorf("save on a nil store: %v", err)
	}
	if err := s.Remove("declare"); err != nil {
		t.Errorf("remove on a nil store: %v", err)
	}
	got, err := s.List()
	if err != nil || got != nil {
		t.Errorf("list on a nil store = (%v, %v)", got, err)
	}
}

// The point of the store: a plugin registered before a restart is running
// after it, without anyone re-pushing it.
func TestManagerRestoresFromTheStore(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	first, _ := newTestManagerWithStore(t, src, store)
	if err := first.Register(context.Background(), storedRegistration(t)); err != nil {
		t.Fatalf("register: %v", err)
	}
	first.Close(context.Background())

	// A new daemon: fresh manager, same store.
	src2 := newFakeSource()
	second, ops := newTestManagerWithStore(t, src2, store)
	if err := second.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if names := second.List(); len(names) != 1 || names[0] != "declare" {
		t.Fatalf("after restore the manager runs %v, want the stored plugin", names)
	}
	// And it is really running: an event reaches it and it declares.
	src2.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, second, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("the restored plugin declared %d entries, want 1", ops.countV4())
	}
}

// Unregistering is what tells the store to forget: a plugin an operator
// took away must not come back on the next restart.
func TestUnregisterRemovesFromTheStore(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	m, _ := newTestManagerWithStore(t, src, store)
	if err := m.Register(context.Background(), storedRegistration(t)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := m.Unregister(context.Background(), "declare"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	got, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the store still holds %d registrations", len(got))
	}
}

// Shutting the daemon down is not unregistering, so the store keeps what
// it had and the next start brings it back.
func TestCloseKeepsTheStore(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	m, _ := newTestManagerWithStore(t, src, store)
	if err := m.Register(context.Background(), storedRegistration(t)); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.Close(context.Background())
	got, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("close left %d registrations in the store, want 1", len(got))
	}
}

// An upgrade must never leave one registration's settings paired with
// another's module. The manifest names the module file, so replacing the
// manifest is what switches versions -- and until it does, the old pair is
// still intact on disk.
func TestUpgradeKeepsManifestAndModuleTogether(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	first := Registration{Name: "p", Module: []byte("module-v1"), Config: []byte("v1")}
	if err := s.Save(first); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	v1Manifest, err := s.readManifest("p")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	second := Registration{Name: "p", Module: []byte("module-v2"), Config: []byte("v2")}
	if err := s.Save(second); err != nil {
		t.Fatalf("save v2: %v", err)
	}
	v2Manifest, err := s.readManifest("p")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if v1Manifest.Module == v2Manifest.Module {
		t.Fatal("the upgrade wrote over the module the old manifest named")
	}
	// The superseded file is gone, so an upgrade does not accumulate one
	// module per version forever.
	if _, err := os.Stat(filepath.Join(dir, v1Manifest.Module)); !os.IsNotExist(err) {
		t.Errorf("the superseded module is still on disk: %v", err)
	}

	got, err := s.load("p")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got.Module) != "module-v2" || string(got.Config) != "v2" {
		t.Fatalf("loaded module %q with config %q, want the v2 pair",
			got.Module, got.Config)
	}
}

// A manifest written before the store named its module still resolves: it
// refers to the single <name>.wasm the store used to keep.
func TestLegacyManifestWithoutAModuleNameStillLoads(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.Save(Registration{Name: "p", Module: []byte("legacy")}); err != nil {
		t.Fatalf("save: %v", err)
	}
	m, err := s.readManifest("p")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	// Rewrite it the way the older store did: module beside the manifest
	// under the plugin's own name, and no module field.
	if err := os.Rename(filepath.Join(dir, m.Module), s.modulePath("p")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	m.Module = ""
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(s.manifestPath("p"), body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := s.load("p")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got.Module) != "legacy" {
		t.Fatalf("module = %q, want the legacy file's contents", got.Module)
	}
}
