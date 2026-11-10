package headend

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/ownership"
)

// globalMaps is a headend backend keyed by prefix alone, as a backend
// without VRFMapOps is: it holds the global VRF only.
type globalMaps struct {
	mu     sync.Mutex
	v4, v6 map[string]*bpf.HeadendEntry
	o4, o6 map[string]bpf.OwnerTag
	writes []string
}

func newGlobalMaps() *globalMaps {
	return &globalMaps{
		v4: map[string]*bpf.HeadendEntry{}, v6: map[string]*bpf.HeadendEntry{},
		o4: map[string]bpf.OwnerTag{}, o6: map[string]bpf.OwnerTag{},
	}
}

func (g *globalMaps) tables(v6 bool) (map[string]*bpf.HeadendEntry, map[string]bpf.OwnerTag) {
	if v6 {
		return g.v6, g.o6
	}
	return g.v4, g.o4
}

func (g *globalMaps) list(v6 bool) (map[string]*bpf.HeadendEntry, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	main, _ := g.tables(v6)
	out := make(map[string]*bpf.HeadendEntry, len(main))
	for k, v := range main {
		out[k] = v
	}
	return out, nil
}

func (g *globalMaps) owner(v6 bool, prefix string) (bpf.OwnerTag, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, owners := g.tables(v6)
	o, ok := owners[prefix]
	return o, ok, nil
}

func (g *globalMaps) create(v6 bool, prefix string, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	main, owners := g.tables(v6)
	if cur, ok := owners[prefix]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	g.writes = append(g.writes, "create "+prefix)
	main[prefix], owners[prefix] = e, owner
	return nil
}

func (g *globalMaps) remove(v6 bool, prefix string, owner bpf.OwnerTag) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	main, owners := g.tables(v6)
	if cur, ok := owners[prefix]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	g.writes = append(g.writes, "delete "+prefix)
	delete(main, prefix)
	delete(owners, prefix)
	return nil
}

func (g *globalMaps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) { return g.list(false) }
func (g *globalMaps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) { return g.list(true) }
func (g *globalMaps) GetHeadendV4Owner(p string) (bpf.OwnerTag, bool, error) {
	return g.owner(false, p)
}
func (g *globalMaps) GetHeadendV6Owner(p string) (bpf.OwnerTag, bool, error) {
	return g.owner(true, p)
}
func (g *globalMaps) CreateHeadendV4(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return g.create(false, p, e, o)
}
func (g *globalMaps) CreateHeadendV6(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return g.create(true, p, e, o)
}
func (g *globalMaps) DeleteHeadendV4(p string, o bpf.OwnerTag) error { return g.remove(false, p, o) }
func (g *globalMaps) DeleteHeadendV6(p string, o bpf.OwnerTag) error { return g.remove(true, p, o) }

// vrfMaps keys its entries by {vrf_id, prefix}, as the BPF maps do. The
// prefix-only methods are the global VRF.
type vrfMaps struct {
	mu     sync.Mutex
	v4, v6 map[ID]*bpf.HeadendEntry
	o4, o6 map[ID]bpf.OwnerTag
	writes []string // "create v4 <id>" / "delete v4 <id>", in order
}

func newVRFMaps() *vrfMaps {
	return &vrfMaps{
		v4: map[ID]*bpf.HeadendEntry{}, v6: map[ID]*bpf.HeadendEntry{},
		o4: map[ID]bpf.OwnerTag{}, o6: map[ID]bpf.OwnerTag{},
	}
}

func (m *vrfMaps) tables(v6 bool) (map[ID]*bpf.HeadendEntry, map[ID]bpf.OwnerTag, string) {
	if v6 {
		return m.v6, m.o6, "v6"
	}
	return m.v4, m.o4, "v4"
}

func masked(prefix string) string {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return prefix
	}
	return p.Masked().String()
}

func (m *vrfMaps) listIDs(v6 bool) (map[ID]*bpf.HeadendEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	main, _, _ := m.tables(v6)
	out := make(map[ID]*bpf.HeadendEntry, len(main))
	for k, v := range main {
		out[k] = v
	}
	return out, nil
}

func (m *vrfMaps) ownerIDs(v6 bool) (map[ID]bpf.OwnerTag, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, owners, _ := m.tables(v6)
	out := make(map[ID]bpf.OwnerTag, len(owners))
	for k, v := range owners {
		out[k] = v
	}
	return out, nil
}

func (m *vrfMaps) ownerIn(v6 bool, vrf uint32, prefix string) (bpf.OwnerTag, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, owners, _ := m.tables(v6)
	o, ok := owners[ID{VRF: vrf, Prefix: masked(prefix)}]
	return o, ok, nil
}

func (m *vrfMaps) createIn(v6 bool, vrf uint32, prefix string, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	main, owners, fam := m.tables(v6)
	id := ID{VRF: vrf, Prefix: masked(prefix)}
	if cur, ok := owners[id]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	m.writes = append(m.writes, fmt.Sprintf("create %s %s", fam, id))
	main[id], owners[id] = e, owner
	return nil
}

func (m *vrfMaps) deleteIn(v6 bool, vrf uint32, prefix string, owner bpf.OwnerTag) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	main, owners, fam := m.tables(v6)
	id := ID{VRF: vrf, Prefix: masked(prefix)}
	if cur, ok := owners[id]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	m.writes = append(m.writes, fmt.Sprintf("delete %s %s", fam, id))
	delete(main, id)
	delete(owners, id)
	return nil
}

func (m *vrfMaps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) {
	all, err := m.listIDs(false)
	return globalOf(all), err
}
func (m *vrfMaps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) {
	all, err := m.listIDs(true)
	return globalOf(all), err
}
func (m *vrfMaps) GetHeadendV4Owner(p string) (bpf.OwnerTag, bool, error) {
	return m.ownerIn(false, 0, p)
}
func (m *vrfMaps) GetHeadendV6Owner(p string) (bpf.OwnerTag, bool, error) {
	return m.ownerIn(true, 0, p)
}
func (m *vrfMaps) CreateHeadendV4(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return m.createIn(false, 0, p, e, o)
}
func (m *vrfMaps) CreateHeadendV6(p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return m.createIn(true, 0, p, e, o)
}
func (m *vrfMaps) DeleteHeadendV4(p string, o bpf.OwnerTag) error { return m.deleteIn(false, 0, p, o) }
func (m *vrfMaps) DeleteHeadendV6(p string, o bpf.OwnerTag) error { return m.deleteIn(true, 0, p, o) }
func (m *vrfMaps) ListHeadendV4IDs() (map[ID]*bpf.HeadendEntry, error) {
	return m.listIDs(false)
}
func (m *vrfMaps) ListHeadendV6IDs() (map[ID]*bpf.HeadendEntry, error) {
	return m.listIDs(true)
}
func (m *vrfMaps) ListHeadendV4OwnerIDs() (map[ID]bpf.OwnerTag, error) { return m.ownerIDs(false) }
func (m *vrfMaps) ListHeadendV6OwnerIDs() (map[ID]bpf.OwnerTag, error) { return m.ownerIDs(true) }
func (m *vrfMaps) GetHeadendV4OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return m.ownerIn(false, v, p)
}
func (m *vrfMaps) GetHeadendV6OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return m.ownerIn(true, v, p)
}
func (m *vrfMaps) CreateHeadendV4In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return m.createIn(false, v, p, e, o)
}
func (m *vrfMaps) CreateHeadendV6In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return m.createIn(true, v, p, e, o)
}
func (m *vrfMaps) DeleteHeadendV4In(v uint32, p string, o bpf.OwnerTag) error {
	return m.deleteIn(false, v, p, o)
}
func (m *vrfMaps) DeleteHeadendV6In(v uint32, p string, o bpf.OwnerTag) error {
	return m.deleteIn(true, v, p, o)
}

func globalOf(all map[ID]*bpf.HeadendEntry) map[string]*bpf.HeadendEntry {
	out := map[string]*bpf.HeadendEntry{}
	for id, e := range all {
		if id.VRF == 0 {
			out[id.Prefix] = e
		}
	}
	return out
}

func (m *vrfMaps) takeWrites() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.writes
	m.writes = nil
	return out
}

const (
	ownerA bpf.OwnerTag = "plugin:a"
	ownerB bpf.OwnerTag = "plugin:b"
)

func entry(seg byte) *bpf.HeadendEntry {
	e := &bpf.HeadendEntry{Mode: 1, NumSegments: 1}
	e.Segments[0][15] = seg
	return e
}

// One trigger prefix in the global VRF and in two named ones is three
// entries: a set declares them together, each keeps its own encap, a
// re-declaration touches only what changed, and pruning one VRF's entry
// leaves the others alone.
func TestApplySetSamePrefixAcrossVRFs(t *testing.T) {
	maps := newVRFMaps()
	leases := ownership.NewLeases()
	set := []Desired{
		{TriggerPrefix: "10.0.0.0/24", Entry: entry(1)},
		{VRF: 5, TriggerPrefix: "10.0.0.0/24", Entry: entry(5)},
		{VRF: 6, TriggerPrefix: "10.0.0.7/24", Entry: entry(6)},
	}
	res, err := ApplySet(maps, leases, ownerA, AFv4, set, -1)
	if err != nil || res.Created != 3 {
		t.Fatalf("apply = %+v %v, want 3 created", res, err)
	}
	if got, want := maps.takeWrites(), []string{"create v4 10.0.0.0/24", "create v4 vrf 5 10.0.0.0/24", "create v4 vrf 6 10.0.0.0/24"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	for vrf, seg := range map[uint32]byte{0: 1, 5: 5, 6: 6} {
		if e := maps.v4[ID{VRF: vrf, Prefix: "10.0.0.0/24"}]; e == nil || e.Segments[0][15] != seg {
			t.Errorf("vrf %d entry = %v, want segment %d", vrf, e, seg)
		}
	}
	owned, err := OwnedEntries(maps, ownerA, AFv4)
	if err != nil || len(owned) != 3 {
		t.Fatalf("owned = %v %v", owned, err)
	}
	if owned[0].VRF != 0 || owned[1].VRF != 5 || owned[2].VRF != 6 {
		t.Errorf("owned entries out of VRF order: %+v", owned)
	}

	// Re-declaring the set without vrf 5 deletes that one entry only; the
	// rest are rewritten in place, never deleted first.
	res, err = ApplySet(maps, leases, ownerA, AFv4, []Desired{set[0], set[2]}, -1)
	if err != nil || res.Pruned != 1 || res.Updated != 2 {
		t.Fatalf("re-apply = %+v %v, want 1 pruned and 2 updated", res, err)
	}
	if got, want := maps.takeWrites(), []string{"delete v4 vrf 5 10.0.0.0/24", "create v4 10.0.0.0/24", "create v4 vrf 6 10.0.0.0/24"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
	if _, held := leases.HolderOf(ownership.LeaseHeadendV4, "vrf 5 10.0.0.0/24"); held {
		t.Error("the pruned entry's lease is still held")
	}

	// Another owner may take the prefix in a VRF the first does not hold,
	// but not in one it does.
	if _, err := ApplySet(maps, leases, ownerB, AFv4, []Desired{{VRF: 5, TriggerPrefix: "10.0.0.0/24", Entry: entry(9)}}, -1); err != nil {
		t.Fatalf("owner B in vrf 5: %v", err)
	}
	_, err = ApplySet(maps, leases, ownerB, AFv4, []Desired{{VRF: 6, TriggerPrefix: "10.0.0.0/24", Entry: entry(9)}}, -1)
	var lerr *ownership.LeaseError
	if !errors.As(err, &lerr) {
		t.Errorf("owner B in vrf 6 = %v, want a lease conflict", err)
	}
	if n, err := ownedCount(maps, ownerA); err != nil || n != 2 {
		t.Errorf("owner A holds %d %v, want 2", n, err)
	}

	// The owner cleanup reaches every VRF and nothing of another owner's.
	if n, err := PruneOwner(maps, leases, ownerA, AFv4); err != nil || n != 2 {
		t.Errorf("prune owner = %d %v, want 2", n, err)
	}
	if len(maps.v4) != 1 || maps.o4[ID{VRF: 5, Prefix: "10.0.0.0/24"}] != ownerB {
		t.Errorf("after the prune: %v", maps.o4)
	}
}

func ownedCount(maps MapOps, owner bpf.OwnerTag) (int, error) {
	ids, err := ownedIDs(maps, owner, AFv4)
	return len(ids), err
}

// A declaration naming no VRF reads and writes the global VRF through the
// prefix-only methods exactly as before, and the global lease keeps the
// bare prefix as its key.
func TestApplySetGlobalOnlyUsesPrefixMethods(t *testing.T) {
	maps := newGlobalMaps()
	leases := ownership.NewLeases()
	if _, err := ApplySet(maps, leases, ownerA, AFv6, []Desired{{TriggerPrefix: "2001:db8::/32", Entry: entry(1)}}, -1); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(maps.writes) != "[create 2001:db8::/32]" {
		t.Errorf("writes = %v", maps.writes)
	}
	if holder, held := leases.HolderOf(ownership.LeaseHeadendV6, "2001:db8::/32"); !held || holder != ownerA {
		t.Errorf("lease of the global entry = %q %v", holder, held)
	}
	owned, err := OwnedEntries(maps, ownerA, AFv6)
	if err != nil || len(owned) != 1 || owned[0].VRF != 0 || owned[0].TriggerPrefix != "2001:db8::/32" {
		t.Errorf("owned = %+v %v", owned, err)
	}
}

// A backend that holds the global VRF only refuses an entry of another VRF
// before anything is written, rather than writing it into the global VRF.
func TestApplySetRefusesVRFOnGlobalOnlyBackend(t *testing.T) {
	maps := newGlobalMaps()
	_, err := ApplySet(maps, ownership.NewLeases(), ownerA, AFv4, []Desired{
		{TriggerPrefix: "10.1.0.0/16", Entry: entry(1)},
		{VRF: 3, TriggerPrefix: "10.2.0.0/16", Entry: entry(2)},
	}, -1)
	if !errors.Is(err, ErrGlobalVRFOnly) {
		t.Fatalf("apply = %v, want ErrGlobalVRFOnly", err)
	}
	if len(maps.writes) != 0 {
		t.Errorf("writes = %v, want none", maps.writes)
	}
}

// The same prefix declared twice in one VRF is refused; in two VRFs it is
// two entries.
func TestApplySetDuplicateIsPerVRF(t *testing.T) {
	maps := newVRFMaps()
	_, err := ApplySet(maps, nil, ownerA, AFv4, []Desired{
		{VRF: 2, TriggerPrefix: "10.0.0.0/8", Entry: entry(1)},
		{VRF: 2, TriggerPrefix: "10.0.0.0/8", Entry: entry(2)},
	}, -1)
	if err == nil {
		t.Error("a prefix declared twice in one VRF was accepted")
	}
	res, err := ApplySet(maps, nil, ownerA, AFv4, []Desired{
		{VRF: 2, TriggerPrefix: "10.0.0.0/8", Entry: entry(1)},
		{VRF: 3, TriggerPrefix: "10.0.0.0/8", Entry: entry(2)},
	}, 1)
	var qerr *ownership.QuotaError
	if !errors.As(err, &qerr) || qerr.Declared != 2 {
		t.Errorf("apply over a quota of 1 = %+v %v, want the two entries counted", res, err)
	}
}

// The incremental writer the built-in appliers use stays in the global VRF.
func TestReconcilerWriterIsGlobal(t *testing.T) {
	maps := newVRFMaps()
	r, err := NewReconciler(maps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplySets(ownerA, []Desired{{VRF: 4, TriggerPrefix: "192.0.2.0/24", Entry: entry(4)}}, nil, -1); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateHeadendV4("192.0.2.0/24", entry(1), ownerB); err != nil {
		t.Fatalf("built-in write next to a vrf 4 entry of the same prefix: %v", err)
	}
	if o, ok, _ := r.GetHeadendV4Owner("192.0.2.0/24"); !ok || o != ownerB {
		t.Errorf("global owner = %q %v", o, ok)
	}
	if err := r.DeleteHeadendV4("192.0.2.0/24", ownerB); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0)
	for id := range maps.v4 {
		keys = append(keys, id.String())
	}
	sort.Strings(keys)
	if fmt.Sprint(keys) != "[vrf 4 192.0.2.0/24]" {
		t.Errorf("entries = %v", keys)
	}
	if n, err := r.OwnedCount(ownerA, AFv4); err != nil || n != 1 {
		t.Errorf("owned count = %d %v, want 1", n, err)
	}
}
