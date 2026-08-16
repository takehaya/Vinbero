package cplane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// A Store keeps registered plugins across a daemon restart.
//
// Without one, every plugin disappears when vinberod does, and the state
// it wrote does not: pinned maps outlive the process, so the daemon would
// come back holding forwarding entries under an owner that no longer
// exists and that nothing can reconcile or remove. The local-SID sweep
// exists precisely because that can happen, and a store is what keeps it
// from being the normal case.
//
// This is a deliberate departure from the daemon's usual stance that an
// external controller is the source of truth (docs/design/ja/persistence.md).
// A plugin is not state an external controller can re-push, because the
// plugin is what the controller would be: the whole point of loading one
// is that the logic lives here. An operator who prefers the other model
// can disable the store and re-register on boot.
type Store struct {
	dir string
}

// storeManifestVersion is stamped into every manifest so a future format
// change can be recognised rather than misread.
const storeManifestVersion = 1

// manifest is what is written beside a plugin's module.
type manifest struct {
	Version      int      `json:"version"`
	Name         string   `json:"name"`
	Config       []byte   `json:"config,omitempty"`
	Families     []string `json:"families,omitempty"`
	Behaviors    []uint16 `json:"behaviors,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	TickMillis   int64    `json:"tick_millis,omitempty"`
	// Limits are persisted too, so a plugin registered with a budget of
	// its own comes back with it rather than silently on the defaults.
	MaxModuleBytes int    `json:"max_module_bytes,omitempty"`
	MaxMemoryPages uint32 `json:"max_memory_pages,omitempty"`
	CallTimeoutMs  int64  `json:"call_timeout_ms,omitempty"`
	MaxBufferBytes int    `json:"max_buffer_bytes,omitempty"`
	SavedAt        string `json:"saved_at"`
}

// NewStore opens (creating if needed) the directory a store lives in.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("cplane store: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cplane store: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir is where the store keeps its files.
func (s *Store) Dir() string { return s.dir }

// Save records a registration so a restart can bring it back.
//
// The module is written first and the manifest second, because the
// manifest is what List looks for: a crash between the two leaves an
// orphan module rather than a manifest promising one that is not there.
func (s *Store) Save(reg Registration) error {
	if s == nil {
		return nil
	}
	if err := bpf.ValidatePluginBundleName(reg.Name); err != nil {
		return err
	}
	if err := os.WriteFile(s.modulePath(reg.Name), reg.Module, 0o600); err != nil {
		return fmt.Errorf("cplane store: write module for %q: %w", reg.Name, err)
	}

	m := manifest{
		Version:        storeManifestVersion,
		Name:           reg.Name,
		Config:         reg.Config,
		Behaviors:      reg.Behaviors,
		Capabilities:   reg.Capabilities.Names(),
		TickMillis:     reg.TickInterval.Milliseconds(),
		MaxModuleBytes: reg.Limits.MaxModuleBytes,
		MaxMemoryPages: reg.Limits.MaxMemoryPages,
		CallTimeoutMs:  reg.Limits.CallTimeout.Milliseconds(),
		MaxBufferBytes: reg.Limits.MaxBufferBytes,
		SavedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range reg.Families {
		m.Families = append(m.Families, string(f))
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("cplane store: encode manifest for %q: %w", reg.Name, err)
	}
	if err := os.WriteFile(s.manifestPath(reg.Name), body, 0o600); err != nil {
		return fmt.Errorf("cplane store: write manifest for %q: %w", reg.Name, err)
	}
	return nil
}

// Remove drops a plugin from the store. Missing files are not an error:
// unregistering something the store never held should still succeed.
func (s *Store) Remove(name string) error {
	if s == nil {
		return nil
	}
	if err := bpf.ValidatePluginBundleName(name); err != nil {
		return err
	}
	// Manifest first: it is what List reads, so removing it makes the
	// plugin gone even if the module removal then fails.
	if err := os.Remove(s.manifestPath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cplane store: remove manifest for %q: %w", name, err)
	}
	if err := os.Remove(s.modulePath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cplane store: remove module for %q: %w", name, err)
	}
	return nil
}

// List returns every stored registration, sorted by name so a boot
// sequence is reproducible.
//
// An entry that cannot be read is reported rather than skipped silently:
// a plugin the operator expects to be running and which is not is worth
// an error, and the caller decides whether to carry on without it.
func (s *Store) List() ([]Registration, error) {
	if s == nil {
		return nil, nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("cplane store: read %s: %w", s.dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name()[:len(e.Name())-len(".json")])
	}
	sort.Strings(names)

	out := make([]Registration, 0, len(names))
	for _, name := range names {
		reg, err := s.load(name)
		if err != nil {
			return out, err
		}
		out = append(out, reg)
	}
	return out, nil
}

// load reads one stored registration.
func (s *Store) load(name string) (Registration, error) {
	if err := bpf.ValidatePluginBundleName(name); err != nil {
		return Registration{}, fmt.Errorf("cplane store: %w", err)
	}
	body, err := os.ReadFile(s.manifestPath(name))
	if err != nil {
		return Registration{}, fmt.Errorf("cplane store: read manifest for %q: %w", name, err)
	}
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Registration{}, fmt.Errorf("cplane store: decode manifest for %q: %w", name, err)
	}
	if m.Version != storeManifestVersion {
		return Registration{}, fmt.Errorf("cplane store: manifest for %q is version %d, this daemon writes %d",
			name, m.Version, storeManifestVersion)
	}
	module, err := os.ReadFile(s.modulePath(name))
	if err != nil {
		return Registration{}, fmt.Errorf("cplane store: read module for %q: %w", name, err)
	}

	reg := Registration{
		Name:         m.Name,
		Module:       module,
		Config:       m.Config,
		Behaviors:    m.Behaviors,
		TickInterval: time.Duration(m.TickMillis) * time.Millisecond,
		Limits: wasm.Limits{
			MaxModuleBytes: m.MaxModuleBytes,
			MaxMemoryPages: m.MaxMemoryPages,
			CallTimeout:    time.Duration(m.CallTimeoutMs) * time.Millisecond,
			MaxBufferBytes: m.MaxBufferBytes,
		},
	}
	for _, f := range m.Families {
		fam, err := bgp.ParseFamily(f)
		if err != nil {
			return Registration{}, fmt.Errorf("cplane store: manifest for %q: %w", name, err)
		}
		reg.Families = append(reg.Families, fam)
	}
	caps, err := wasm.ParseCapabilities(m.Capabilities)
	if err != nil {
		return Registration{}, fmt.Errorf("cplane store: manifest for %q: %w", name, err)
	}
	reg.Capabilities = caps
	return reg, nil
}

func (s *Store) manifestPath(name string) string {
	return filepath.Join(s.dir, name+".json")
}

func (s *Store) modulePath(name string) string {
	return filepath.Join(s.dir, name+".wasm")
}
