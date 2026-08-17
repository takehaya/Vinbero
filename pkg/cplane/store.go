package cplane

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
	// Module is the file holding this registration's WebAssembly, named
	// after its content. The manifest naming the file is what makes an
	// upgrade atomic: a new registration writes a new file and only then
	// replaces the manifest, so a crash at any point leaves a manifest
	// beside the module it was saved with, never the old settings paired
	// with the new bytes.
	//
	// Empty in manifests written before this field existed; those refer to
	// the single <name>.wasm the store used to keep.
	Module  string `json:"module,omitempty"`
	SavedAt string `json:"saved_at"`
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
// The module goes to a file named after its content, and the manifest that
// names that file is replaced last and atomically. Every intermediate
// state is therefore a readable one: the old manifest still points at the
// old module until the moment the new manifest lands. Writing the module
// in place instead would leave an upgrade that died between the two with
// the previous registration's capabilities and config paired with the new
// module's bytes.
func (s *Store) Save(reg Registration) error {
	if s == nil {
		return nil
	}
	if err := bpf.ValidatePluginBundleName(reg.Name); err != nil {
		return err
	}
	// The previous module is read before anything is written, so it can be
	// removed once the manifest no longer refers to it.
	var previous string
	if old, err := s.readManifest(reg.Name); err == nil && old.Module != "" {
		// Resolved through the same check as any other read: a manifest
		// naming a path rather than a name must not send this remove
		// outside the store.
		if path, err := s.modulePathFor(reg.Name, old); err == nil {
			previous = path
		}
	}
	moduleFile := moduleFileName(reg.Name, reg.Module)
	if err := writeFileAtomic(filepath.Join(s.dir, moduleFile), reg.Module); err != nil {
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
		Module:         moduleFile,
		SavedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range reg.Families {
		m.Families = append(m.Families, string(f))
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("cplane store: encode manifest for %q: %w", reg.Name, err)
	}
	if err := writeFileAtomic(s.manifestPath(reg.Name), body); err != nil {
		return fmt.Errorf("cplane store: write manifest for %q: %w", reg.Name, err)
	}
	// Nothing refers to the old module now. Failing to remove it costs
	// disk, not correctness, so it is not worth failing the save over.
	if previous != "" && previous != filepath.Join(s.dir, moduleFile) {
		_ = os.Remove(previous)
	}
	return nil
}

// writeFileAtomic writes a file so a reader sees either the whole new
// content or the whole old one, never a partial write.
//
// The temporary file is fsynced before the rename: without that, a crash
// can leave the rename durable and the bytes it points at not, which is
// exactly the inconsistency the rename is there to prevent.
func writeFileAtomic(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	// Both are cleanup after a successful rename has already moved the
	// file away, or after an error that is being returned: there is
	// nothing a failure here would add.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// The directory entry the rename created is itself buffered. Without
	// this the rename can be lost on a crash even though the bytes it
	// points at are safely on disk, which is the half of the guarantee
	// that matters here: the manifest is what says the plugin exists.
	return syncDir(filepath.Dir(path))
}

// modulePathFor resolves the module a manifest names, refusing anything
// that is not a name this store could have written.
//
// The value comes off disk, and a path is not a name: a manifest saying
// "../../etc/something" would send the join outside the store, where the
// daemon then reads it and, on the next upgrade, deletes it. Requiring the
// exact shape Save produces means nothing else is reachable, whatever the
// file says.
func (s *Store) modulePathFor(name string, m manifest) (string, error) {
	if m.Module == "" {
		// Written before the store named its module: the single file it
		// used to keep, whose name this store builds itself.
		return s.modulePath(name), nil
	}
	// Checked against what this plugin's file would be named rather than
	// against a pattern of its own: the bundle name's allowed characters
	// live in one place, and a second spelling of them here would let a
	// name that registers fail to restore.
	digest, ok := strings.CutPrefix(m.Module, name+"-")
	if !ok {
		return "", fmt.Errorf("cplane store: manifest for %q names module %q, which belongs to another plugin",
			name, m.Module)
	}
	digest, ok = strings.CutSuffix(digest, ".wasm")
	if !ok || !moduleDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("cplane store: manifest for %q names module %q, which is not a name this store writes",
			name, m.Module)
	}
	return filepath.Join(s.dir, m.Module), nil
}

// moduleDigestPattern is the content hash moduleFileName appends. Fixed
// length and hex only, so nothing between the plugin's name and the
// extension can be a path separator.
var moduleDigestPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// moduleFileName names a module after its content, so an upgrade writes a
// new file rather than overwriting the one the current manifest names.
func moduleFileName(name string, module []byte) string {
	sum := sha256.Sum256(module)
	return fmt.Sprintf("%s-%x.wasm", name, sum[:8])
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
	// The module is located before the manifest goes, since the manifest
	// is what names it.
	module := s.modulePath(name)
	if m, err := s.readManifest(name); err == nil {
		if path, err := s.modulePathFor(name, m); err == nil {
			module = path
		}
	}
	// Manifest first: it is what List reads, so removing it makes the
	// plugin gone even if the module removal then fails.
	if err := os.Remove(s.manifestPath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cplane store: remove manifest for %q: %w", name, err)
	}
	if err := os.Remove(module); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cplane store: remove module for %q: %w", name, err)
	}
	// The unlinks are directory entries like any other, and buffered like
	// any other. Without this a power loss just after a successful
	// unregister can bring the plugin back on the next boot.
	return syncDir(s.dir)
}

// syncDir flushes a directory's own entries, so a create or an unlink in
// it survives a crash.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	// Opened read-only for the sync; nothing was written through it, so a
	// close failure has nothing to report.
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// readManifest reads and decodes one manifest without touching its module.
func (s *Store) readManifest(name string) (manifest, error) {
	body, err := os.ReadFile(s.manifestPath(name))
	if err != nil {
		return manifest{}, err
	}
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return manifest{}, err
	}
	return m, nil
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
	names, err := s.names()
	if err != nil {
		return nil, err
	}

	// Every manifest is attempted, and the failures are collected rather
	// than returned at the first one. Stopping there would leave every
	// plugin later in the order unregistered while the state it wrote is
	// still pinned in the maps, owned by nobody -- one unreadable file
	// would take the rest down with it.
	out := make([]Registration, 0, len(names))
	var errs []error
	for _, name := range names {
		reg, err := s.load(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, reg)
	}
	return out, errors.Join(errs...)
}

// names lists the stored plugins, sorted so a boot sequence is
// reproducible.
func (s *Store) names() ([]string, error) {
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
	return names, nil
}

// StoredClaim is what a stored plugin claims, without its module.
type StoredClaim struct {
	Name      string
	Behaviors []uint16
}

// ListClaims returns the behaviors every stored plugin claims.
//
// It deliberately does not read the modules. A registration whose module
// is missing or corrupt is one that will fail to restore, and its
// codepoints are exactly the ones that must stay claimed: a private
// behavior nothing implements has to be withheld from the built-in
// appliers, which would otherwise install those routes as ordinary
// service SIDs. Reading through List would drop such a registration from
// the list entirely and reserve nothing for it.
func (s *Store) ListClaims() ([]StoredClaim, error) {
	if s == nil {
		return nil, nil
	}
	names, err := s.names()
	if err != nil {
		return nil, err
	}
	out := make([]StoredClaim, 0, len(names))
	var errs []error
	for _, name := range names {
		m, err := s.readManifest(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("cplane store: read manifest for %q: %w", name, err))
			continue
		}
		if m.Version != storeManifestVersion {
			errs = append(errs, fmt.Errorf("cplane store: manifest for %q is version %d, this daemon writes %d",
				name, m.Version, storeManifestVersion))
			continue
		}
		if len(m.Behaviors) == 0 {
			continue
		}
		out = append(out, StoredClaim{Name: m.Name, Behaviors: m.Behaviors})
	}
	return out, errors.Join(errs...)
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
	modulePath, err := s.modulePathFor(name, m)
	if err != nil {
		return Registration{}, err
	}
	module, err := os.ReadFile(modulePath)
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
