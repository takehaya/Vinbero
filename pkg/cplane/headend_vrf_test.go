package cplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/vrf"
	"google.golang.org/protobuf/proto"
)

// vrfHeadendOps is a headend backend keyed by {vrf_id, prefix}, as the BPF
// maps are; the prefix-only methods are the global VRF.
type vrfHeadendOps struct {
	mu     sync.Mutex
	v4, v6 map[bpf.HeadendID]*bpf.HeadendEntry
	o4, o6 map[bpf.HeadendID]bpf.OwnerTag
}

func newVRFHeadendOps() *vrfHeadendOps {
	return &vrfHeadendOps{
		v4: map[bpf.HeadendID]*bpf.HeadendEntry{}, v6: map[bpf.HeadendID]*bpf.HeadendEntry{},
		o4: map[bpf.HeadendID]bpf.OwnerTag{}, o6: map[bpf.HeadendID]bpf.OwnerTag{},
	}
}

func (f *vrfHeadendOps) tables(v6 bool) (map[bpf.HeadendID]*bpf.HeadendEntry, map[bpf.HeadendID]bpf.OwnerTag) {
	if v6 {
		return f.v6, f.o6
	}
	return f.v4, f.o4
}

func vrfKey(vrf uint32, prefix string) bpf.HeadendID {
	if p, err := netip.ParsePrefix(prefix); err == nil {
		prefix = p.Masked().String()
	}
	return bpf.HeadendID{VRF: vrf, Prefix: prefix}
}

func (f *vrfHeadendOps) ids(v6 bool) (map[bpf.HeadendID]*bpf.HeadendEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	main, _ := f.tables(v6)
	out := map[bpf.HeadendID]*bpf.HeadendEntry{}
	for k, v := range main {
		out[k] = v
	}
	return out, nil
}

func (f *vrfHeadendOps) owners(v6 bool) (map[bpf.HeadendID]bpf.OwnerTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, owners := f.tables(v6)
	out := map[bpf.HeadendID]bpf.OwnerTag{}
	for k, v := range owners {
		out[k] = v
	}
	return out, nil
}

func (f *vrfHeadendOps) ownerIn(v6 bool, vrf uint32, p string) (bpf.OwnerTag, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, owners := f.tables(v6)
	o, ok := owners[vrfKey(vrf, p)]
	return o, ok, nil
}

func (f *vrfHeadendOps) createIn(v6 bool, vrf uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	main, owners := f.tables(v6)
	k := vrfKey(vrf, p)
	if cur, ok := owners[k]; ok && cur != o {
		return bpf.ErrEntryOwnerMismatch
	}
	main[k], owners[k] = e, o
	return nil
}

func (f *vrfHeadendOps) deleteIn(v6 bool, vrf uint32, p string, o bpf.OwnerTag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	main, owners := f.tables(v6)
	k := vrfKey(vrf, p)
	if cur, ok := owners[k]; ok && cur != o {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(main, k)
	delete(owners, k)
	return nil
}

func (f *vrfHeadendOps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) {
	return f.global(false)
}
func (f *vrfHeadendOps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) {
	return f.global(true)
}
func (f *vrfHeadendOps) global(v6 bool) (map[string]*bpf.HeadendEntry, error) {
	all, err := f.ids(v6)
	out := map[string]*bpf.HeadendEntry{}
	for k, v := range all {
		if k.VRF == 0 {
			out[k.Prefix] = v
		}
	}
	return out, err
}
func (f *vrfHeadendOps) GetHeadendV4Owner(p string) (bpf.OwnerTag, bool, error) {
	return f.ownerIn(false, 0, p)
}
func (f *vrfHeadendOps) GetHeadendV6Owner(p string) (bpf.OwnerTag, bool, error) {
	return f.ownerIn(true, 0, p)
}
func (f *vrfHeadendOps) CreateHeadendV4(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.createIn(false, 0, p, e, o)
}
func (f *vrfHeadendOps) CreateHeadendV6(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.createIn(true, 0, p, e, o)
}
func (f *vrfHeadendOps) DeleteHeadendV4(p string, o bpf.OwnerTag) error {
	return f.deleteIn(false, 0, p, o)
}
func (f *vrfHeadendOps) DeleteHeadendV6(p string, o bpf.OwnerTag) error {
	return f.deleteIn(true, 0, p, o)
}
func (f *vrfHeadendOps) ListHeadendV4IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error) {
	return f.ids(false)
}
func (f *vrfHeadendOps) ListHeadendV6IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error) {
	return f.ids(true)
}
func (f *vrfHeadendOps) ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return f.owners(false)
}
func (f *vrfHeadendOps) ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return f.owners(true)
}
func (f *vrfHeadendOps) GetHeadendV4OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return f.ownerIn(false, v, p)
}
func (f *vrfHeadendOps) GetHeadendV6OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return f.ownerIn(true, v, p)
}
func (f *vrfHeadendOps) CreateHeadendV4In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.createIn(false, v, p, e, o)
}
func (f *vrfHeadendOps) CreateHeadendV6In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.createIn(true, v, p, e, o)
}
func (f *vrfHeadendOps) DeleteHeadendV4In(v uint32, p string, o bpf.OwnerTag) error {
	return f.deleteIn(false, v, p, o)
}
func (f *vrfHeadendOps) DeleteHeadendV6In(v uint32, p string, o bpf.OwnerTag) error {
	return f.deleteIn(true, v, p, o)
}

var _ headend.VRFMapOps = (*vrfHeadendOps)(nil)

// fakeVRFs is a VRF directory with fixed names; holds counts the HoldIDs
// that are open.
type fakeVRFs struct {
	mu    sync.Mutex
	ids   map[string]uint32
	holds int
	max   int
}

func (f *fakeVRFs) LookupID(name string) (uint32, error) {
	if name == "" || name == "global" {
		return 0, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.ids[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown VRF %q", name)
}

func (f *fakeVRFs) NameOf(id uint32) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, v := range f.ids {
		if v == id {
			return name, true
		}
	}
	return "", false
}

func (f *fakeVRFs) HoldIDs() func() {
	f.mu.Lock()
	f.holds++
	if f.holds > f.max {
		f.max = f.holds
	}
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.holds--
		f.mu.Unlock()
	}
}

func vrfPluginOps(t *testing.T, maps HeadendMapOps, vrfs vrf.Directory, scope ScopeSpec) *PluginOps {
	t.Helper()
	s, err := ParseScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: maps, VRFs: vrfs,
		Capabilities: wasm.Capabilities{wasm.CapHeadend: {}},
		Guard:        NewGuard(s, nil, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	return p
}

// declareV4 commits one IPv4 headend set through the guest-facing calls,
// each entry with the VRF it names.
func declareV4(p *PluginOps, entries ...*v1.PluginHeadendEntry) error {
	return putChunk(p, v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4, &v1.PluginApplyChunk{HeadendEntries: entries})
}

func putChunk(p *PluginOps, kind v1.PluginApplyKind, chunk *v1.PluginApplyChunk) error {
	g, err := p.ApplyBegin(uint32(kind))
	if err != nil {
		return err
	}
	b, err := proto.Marshal(chunk)
	if err != nil {
		return err
	}
	if err := p.ApplyPut(g, b); err != nil {
		p.ApplyAbort(g)
		return err
	}
	return p.ApplyCommit(g)
}

func headendIn(vrf, prefix, seg string) *v1.PluginHeadendEntry {
	return &v1.PluginHeadendEntry{TriggerPrefix: prefix, Segments: []string{seg}, SrcAddr: "fd00::1", Vrf: vrf}
}

// A plugin names the VRF of a headend entry. The global VRF needs no
// grant; another VRF must be in the scope's VRF list and must exist. The
// same prefix in the global VRF and a granted one is two entries, the VRF
// is held while the set is written, and a refused set changes nothing.
func TestPluginHeadendEntriesNameGrantedVRFs(t *testing.T) {
	maps := newVRFHeadendOps()
	vrfs := &fakeVRFs{ids: map[string]uint32{"tenant-a": 5, "tenant-b": 6}}
	p := vrfPluginOps(t, maps, vrfs, ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}, VRFs: []string{"tenant-a", "tenant-x"}})

	if err := declareV4(p, headendIn("", "10.1.0.0/16", "fd00:a::1"), headendIn("tenant-a", "10.1.0.0/16", "fd00:b::1"), headendIn("global", "10.2.0.0/16", "fd00:a::1")); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if len(maps.v4) != 3 || maps.o4[bpf.HeadendID{VRF: 5, Prefix: "10.1.0.0/16"}] != ownerA || maps.o4[bpf.HeadendID{Prefix: "10.1.0.0/16"}] != ownerA {
		t.Fatalf("entries = %v", maps.o4)
	}
	if vrfs.max != 1 || vrfs.holds != 0 {
		t.Errorf("VRF holds: max %d open %d, want one hold released", vrfs.max, vrfs.holds)
	}

	for _, tc := range []struct {
		vrf, want string
	}{
		{"tenant-b", "outside this plugin's scope"}, // exists, not granted
		{"tenant-x", "unknown VRF"},                 // granted, does not exist
	} {
		err := declareV4(p, headendIn(tc.vrf, "10.1.0.0/16", "fd00:c::1"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("declare in %s = %v, want %q", tc.vrf, err, tc.want)
		}
		if len(maps.v4) != 3 {
			t.Errorf("a refused set in %s changed the entries: %v", tc.vrf, maps.o4)
		}
	}

	// Narrowing the scope prunes the entries of a VRF it no longer grants
	// and keeps the global ones.
	narrowed, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	p.guard = NewGuard(narrowed, nil, nil)
	if n, err := p.PruneOutOfScope(context.Background()); err != nil || n != 1 {
		t.Fatalf("prune out of scope = %d %v, want 1", n, err)
	}
	if _, ok := maps.v4[bpf.HeadendID{VRF: 5, Prefix: "10.1.0.0/16"}]; ok || len(maps.v4) != 2 {
		t.Errorf("after the narrowing: %v", maps.o4)
	}
}

// A VRF whose name is gone is outside every scope: its entries are pruned.
func TestPluginHeadendScopePrunesUnnamedVRF(t *testing.T) {
	maps := newVRFHeadendOps()
	vrfs := &fakeVRFs{ids: map[string]uint32{"tenant-a": 5}}
	p := vrfPluginOps(t, maps, vrfs, ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}, VRFs: []string{"tenant-a"}})
	if err := declareV4(p, headendIn("tenant-a", "10.1.0.0/16", "fd00:b::1")); err != nil {
		t.Fatal(err)
	}
	vrfs.ids = map[string]uint32{}
	if n, err := p.PruneOutOfScope(context.Background()); err != nil || n != 1 || len(maps.v4) != 0 {
		t.Errorf("prune = %d %v, entries %v", n, err, maps.o4)
	}
}

// Without a VRF directory, or on a backend that holds the global VRF only,
// a named VRF is refused rather than written into the global VRF.
func TestPluginHeadendVRFRefusedWithoutSupport(t *testing.T) {
	scope := ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}, VRFs: []string{"tenant-a"}}
	p := vrfPluginOps(t, newVRFHeadendOps(), nil, scope)
	if err := declareV4(p, headendIn("tenant-a", "10.1.0.0/16", "fd00:b::1")); err == nil || !errors.Is(err, errNoVRFDirectory) {
		t.Errorf("declare without a VRF directory = %v", err)
	}
	global := newFakeHeadendOps()
	p = vrfPluginOps(t, global, &fakeVRFs{ids: map[string]uint32{"tenant-a": 5}}, scope)
	if err := declareV4(p, headendIn("tenant-a", "10.1.0.0/16", "fd00:b::1")); !errors.Is(err, headend.ErrGlobalVRFOnly) {
		t.Errorf("declare on a global-only backend = %v, want ErrGlobalVRFOnly", err)
	}
	if len(global.v4) != 0 {
		t.Errorf("global entries = %v", global.v4)
	}
}

// The conformance check refuses a VRF the scope does not grant, and lets
// the global VRF through without one.
func TestValidateChunkInScopeChecksHeadendVRF(t *testing.T) {
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}, VRFs: []string{"tenant-a"}})
	if err != nil {
		t.Fatal(err)
	}
	for vrf, ok := range map[string]bool{"": true, "global": true, "tenant-a": true, "tenant-b": false} {
		err := ValidateChunkInScope(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4,
			&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{headendIn(vrf, "10.1.0.0/16", "fd00:b::1")}}, scope)
		if (err == nil) != ok {
			t.Errorf("vrf %q: %v, want accepted %v", vrf, err, ok)
		}
	}
}

// A composition may declare one prefix in two VRFs; the conflict check is
// per {vrf, prefix}, and the resolved ids are part of the digest.
func TestCompositionHeadendPerVRF(t *testing.T) {
	p, _ := compositionOps(t)
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}, VRFs: []string{"tenant-a"}})
	if err != nil {
		t.Fatal(err)
	}
	p.guard = NewGuard(scope, nil, nil)
	m := desiredComposition(1)
	other := &v1.PluginForwardingHeadend{Context: "mobile", Entry: headendIn("tenant-a", "10.0.0.1/32", "fd00:d::1")}
	m.ForwardingHeadends = append(m.ForwardingHeadends, other)
	if _, err := p.normalizeComposition(m); !errors.Is(err, errNoVRFDirectory) {
		t.Fatalf("normalize without a VRF directory = %v", err)
	}
	vrfs := &fakeVRFs{ids: map[string]uint32{"tenant-a": 5}}
	p.vrfs = vrfs
	d, err := p.normalizeComposition(m)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(d.v4) != 2 || d.v4[1].VRF != 5 {
		t.Errorf("v4 = %+v", d.v4)
	}
	before, err := compositionDigest(m, d)
	if err != nil {
		t.Fatal(err)
	}
	vrfs.ids["tenant-a"] = 9
	d, _ = p.normalizeComposition(m)
	after, _ := compositionDigest(m, d)
	if before == after {
		t.Error("the digest does not change with the resolved VRF id")
	}
	other.Entry.Vrf = "tenant-b"
	if _, err := p.normalizeComposition(m); err == nil {
		t.Error("a composition naming an ungranted VRF was accepted")
	}
}
