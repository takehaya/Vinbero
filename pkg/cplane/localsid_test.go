package cplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// fakeAllocator hands out sequential SIDs from a pretend locator and
// records what came back.
type fakeAllocator struct {
	mu       sync.Mutex
	next     int
	released []netip.Addr
	failOn   string // locator whose allocation fails
}

func (f *fakeAllocator) AllocateSID(locatorName string, _ *uint32) (netip.Addr, locator.Binding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if locatorName == f.failOn {
		return netip.Addr{}, locator.Binding{}, errors.New("no space left in locator")
	}
	f.next++
	// One address space per locator name, so a move between locators is a
	// visibly different address.
	sid := netip.MustParseAddr(fmt.Sprintf("fd00:%s::%d", locatorSuffix(locatorName), f.next))
	return sid, locator.Binding{LocatorName: locatorName}, nil
}

func (f *fakeAllocator) ReleaseSID(sid netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, sid)
}

func (f *fakeAllocator) releasedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.released)
}

// locatorSuffix keeps the fake's addresses distinguishable per locator.
func locatorSuffix(name string) string {
	if name == "second" {
		return "2"
	}
	return "1"
}

// fakeSIDOps records the dispatch entries a reconcile installs.
type fakeSIDOps struct {
	mu       sync.Mutex
	entries  map[string]*bpf.SidFunctionEntry
	owners   map[string]bpf.OwnerTag
	failOn   string // prefix whose install fails
	installs int
	ops      []string
}

func newFakeSIDOps() *fakeSIDOps {
	return &fakeSIDOps{
		entries: map[string]*bpf.SidFunctionEntry{},
		owners:  map[string]bpf.OwnerTag{},
	}
}

func (f *fakeSIDOps) CreateSidFunction(prefix string, e *bpf.SidFunctionEntry, _ *bpf.SidAuxEntry, owner bpf.OwnerTag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prefix == f.failOn {
		return errors.New("simulated install failure")
	}
	if cur, ok := f.owners[prefix]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	f.entries[prefix] = e
	f.owners[prefix] = owner
	f.installs++
	f.ops = append(f.ops, "create "+prefix)
	return nil
}

func (f *fakeSIDOps) DeleteSidFunction(prefix string, requester bpf.OwnerTag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.owners[prefix]; ok && cur != requester {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(f.entries, prefix)
	delete(f.owners, prefix)
	f.ops = append(f.ops, "delete "+prefix)
	return nil
}

func (f *fakeSIDOps) ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*bpf.SidFunctionEntry, len(f.entries))
	for k, v := range f.entries {
		out[k] = v
	}
	return out, nil
}

func (f *fakeSIDOps) GetSidFunctionOwner(prefix string) (bpf.OwnerTag, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.owners[prefix]
	return o, ok, nil
}

// installCount and log record what was actually written, so a test can
// tell a rewrite from a no-op.
func (f *fakeSIDOps) installCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installs
}

func (f *fakeSIDOps) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func (f *fakeSIDOps) resetLog() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = nil
}

func (f *fakeSIDOps) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func (f *fakeSIDOps) entryFor(prefix string) (*bpf.SidFunctionEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[prefix]
	return e, ok
}

// The two halves of a plugin meet here: a declared SID is allocated, the
// dispatch entry points it at the plugin's own slot, and the plugin is
// told the address it got.
func TestLocalSIDAllocatesAndInstalls(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)

	got, res, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("result = %+v, want one allocation", res)
	}
	if len(got) != 1 || got[0].Name != "svc-a" {
		t.Fatalf("reported %+v, want the declared name", got)
	}
	entry, ok := sids.entryFor(got[0].SID.String() + "/128")
	if !ok {
		t.Fatalf("no dispatch entry installed for %v", got[0].SID)
	}
	if entry.Action != 33 {
		t.Errorf("dispatch action = %d, want the plugin's slot 33", entry.Action)
	}
}

// A plugin that comes back with no memory declares the same names and is
// handed the same addresses, because the host never forgot them. That is
// what keeps allocation idempotent despite not being declarative.
func TestLocalSIDRedeclarationKeepsTheAddress(t *testing.T) {
	alloc := &fakeAllocator{}
	set := NewLocalSIDSet(alloc, newFakeSIDOps())
	first, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, res, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if res.Created != 0 || res.Updated != 1 {
		t.Fatalf("result = %+v, want the existing allocation kept", res)
	}
	if first[0].SID != second[0].SID {
		t.Fatalf("address changed on redeclaration: %v then %v", first[0].SID, second[0].SID)
	}
	if alloc.releasedCount() != 0 {
		t.Errorf("a redeclaration released an address")
	}
}

// A name dropped from the set gives its address back.
func TestLocalSIDReleasesWhatIsNoLongerDeclared(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)
	if _, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33},
		{Name: "svc-b", Locator: "main", Slot: 34},
	}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, res, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Pruned != 1 {
		t.Fatalf("result = %+v, want one release", res)
	}
	if alloc.releasedCount() != 1 {
		t.Fatalf("released %d addresses, want 1", alloc.releasedCount())
	}
	if sids.count() != 1 {
		t.Fatalf("%d dispatch entries left, want 1", sids.count())
	}
}

// Changing a SID's slot rewrites the dispatch entry without moving the
// address, so the advertisement the plugin already made stays valid.
func TestLocalSIDSlotChangeKeepsTheAddress(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)
	first, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 40}}, unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if first[0].SID != second[0].SID {
		t.Fatal("changing the slot moved the address")
	}
	entry, _ := sids.entryFor(second[0].SID.String() + "/128")
	if entry.Action != 40 {
		t.Fatalf("dispatch action = %d, want the new slot", entry.Action)
	}
}

// Moving a SID to another locator is a different address, so the old one
// is given back.
func TestLocalSIDLocatorChangeReallocates(t *testing.T) {
	alloc := &fakeAllocator{}
	set := NewLocalSIDSet(alloc, newFakeSIDOps())
	first, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "second", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if first[0].SID == second[0].SID {
		t.Fatal("moving to another locator kept the same address")
	}
	if alloc.releasedCount() != 1 {
		t.Fatalf("released %d addresses, want the old one back", alloc.releasedCount())
	}
}

// An address whose dispatch entry could not be installed is given back
// rather than leaked: nothing points at it and the pool is finite.
func TestLocalSIDReleasesOnFailedInstall(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	sids.failOn = "fd00:1::1/128"
	set := NewLocalSIDSet(alloc, sids)
	if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited); err == nil {
		t.Fatal("a failed install was reported as success")
	}
	if alloc.releasedCount() != 1 {
		t.Fatalf("released %d addresses, want the unusable one back", alloc.releasedCount())
	}
}

func TestLocalSIDReleaseOwner(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)
	if _, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33},
		{Name: "svc-b", Locator: "main", Slot: 34},
	}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := set.ReleaseOwner(ownerA); err != nil {
		t.Fatalf("release owner: %v", err)
	}
	if sids.count() != 0 {
		t.Fatalf("%d dispatch entries left behind", sids.count())
	}
	if alloc.releasedCount() != 2 {
		t.Fatalf("released %d addresses, want 2", alloc.releasedCount())
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("the owner still holds local SIDs")
	}
}

// A SID pointing at a built-in behavior would let a plugin borrow
// vinbero's forwarding under its own address.
func TestLocalSIDRejectsNonPluginSlot(t *testing.T) {
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps())
	if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 1}}, unlimited); err == nil {
		t.Fatal("a SID pointing at a built-in slot was accepted")
	}
}

func TestLocalSIDRejectsMalformed(t *testing.T) {
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps())
	tests := []struct {
		name string
		sid  LocalSID
	}{
		{name: "no name", sid: LocalSID{Locator: "main", Slot: 33}},
		{name: "no locator", sid: LocalSID{Name: "svc-a", Slot: 33}},
		{name: "oversized aux", sid: LocalSID{
			Name: "svc-a", Locator: "main", Slot: 33,
			AuxRaw: make([]byte, bpf.SidAuxPluginRawMax+1),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := set.Apply(ownerA, []LocalSID{tt.sid}, unlimited); err == nil {
				t.Fatal("a malformed declaration was accepted")
			}
		})
	}
	if _, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33},
		{Name: "svc-a", Locator: "main", Slot: 34},
	}, unlimited); err == nil {
		t.Fatal("the same name declared twice was accepted")
	}
}

// A daemon with no locator manager says so rather than accepting a
// declaration it cannot serve.
func TestLocalSIDWithoutAnAllocator(t *testing.T) {
	set := NewLocalSIDSet(nil, nil)
	if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited); err == nil {
		t.Fatal("a declaration was accepted with no allocator")
	}
	if _, _, err := set.Apply(ownerA, nil, unlimited); err != nil {
		t.Fatalf("an empty declaration should still be fine: %v", err)
	}
}

func TestDecodeLocalSID(t *testing.T) {
	got, err := DecodeLocalSID(&v1.PluginLocalSid{
		Name: "svc-a", Locator: "main", Slot: 33, AuxRaw: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "svc-a" || got.Locator != "main" || got.Slot != 33 {
		t.Fatalf("decoded %+v", got)
	}
	if len(got.AuxRaw) != 3 {
		t.Errorf("aux = %v", got.AuxRaw)
	}
	if _, err := DecodeLocalSID(nil); err == nil {
		t.Error("nil was accepted")
	}
	if _, err := DecodeLocalSID(&v1.PluginLocalSid{Locator: "main", Slot: 33}); err == nil {
		t.Error("a declaration with no name was accepted")
	}
}

// With pinned maps a previous daemon run's dispatch entries survive, and
// the names that produced them do not. A plugin redeclaring the same names
// is handed new addresses, so the old entries would sit in the map with
// nothing dispatching to them and nothing able to remove them.
func TestLocalSIDSweepsLeftoversFromAPreviousRun(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	// As if a previous run had installed these under the same owner.
	if err := sids.CreateSidFunction("fd00:9::1/128", &bpf.SidFunctionEntry{Action: 33}, nil, ownerA); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := sids.CreateSidFunction("fd00:9::2/128", &bpf.SidFunctionEntry{Action: 33}, nil, ownerA); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Another owner's entry must survive the sweep.
	if err := sids.CreateSidFunction("fd00:9::9/128", &bpf.SidFunctionEntry{Action: 34}, nil, ownerB); err != nil {
		t.Fatalf("seed: %v", err)
	}

	set := NewLocalSIDSet(alloc, sids)
	got, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := sids.entryFor("fd00:9::1/128"); ok {
		t.Error("a leftover entry from a previous run survived")
	}
	if _, ok := sids.entryFor("fd00:9::2/128"); ok {
		t.Error("a leftover entry from a previous run survived")
	}
	if _, ok := sids.entryFor("fd00:9::9/128"); !ok {
		t.Error("the sweep removed another owner's entry")
	}
	if _, ok := sids.entryFor(got[0].SID.String() + "/128"); !ok {
		t.Error("the newly declared SID was not installed")
	}
}

// The sweep runs once. A later apply must not go looking again, or a
// plugin's own entries would be at risk every time it declares.
func TestLocalSIDSweepsOnlyOnce(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)

	first, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33}}, unlimited)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// A second declaration adding a name must leave the first alone.
	if _, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33},
		{Name: "svc-b", Locator: "main", Slot: 34},
	}, unlimited); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if _, ok := sids.entryFor(first[0].SID.String() + "/128"); !ok {
		t.Fatal("the plugin's own entry was swept by a later apply")
	}
	if sids.count() != 2 {
		t.Fatalf("%d entries installed, want both declared SIDs", sids.count())
	}
}

// Installing an entry with aux allocates a fresh aux index every time and
// frees the previous one only on delete. A plugin redeclaring its set on
// every event -- which is what the desired-set model asks for -- would
// therefore leak an index per apply, so an unchanged declaration must not
// be rewritten at all.
func TestLocalSIDRedeclarationWithAuxDoesNotRewrite(t *testing.T) {
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(&fakeAllocator{}, sids)
	declared := []LocalSID{{Name: "svc-a", Locator: "main", Slot: 33, AuxRaw: []byte{1, 2, 3}}}

	if _, _, err := set.Apply(ownerA, declared, unlimited); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	installs := sids.installCount()

	for i := 0; i < 5; i++ {
		if _, _, err := set.Apply(ownerA, declared, unlimited); err != nil {
			t.Fatalf("redeclaration %d: %v", i, err)
		}
	}
	if got := sids.installCount(); got != installs {
		t.Fatalf("%d installs after redeclaring an unchanged set, want the original %d", got, installs)
	}
}

// A changed aux is written, and the old entry is removed first so the aux
// index it held is freed rather than orphaned by the rebind.
func TestLocalSIDChangedAuxRemovesBeforeInstalling(t *testing.T) {
	sids := newFakeSIDOps()
	alloc := &fakeAllocator{}
	set := NewLocalSIDSet(alloc, sids)
	first, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33, AuxRaw: []byte{1}},
	}, unlimited)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	sids.resetLog()

	second, _, err := set.Apply(ownerA, []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33, AuxRaw: []byte{2}},
	}, unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if first[0].SID != second[0].SID {
		t.Fatal("changing the aux moved the address")
	}
	if got := sids.log(); len(got) != 2 || got[0][:6] != "delete" || got[1][:6] != "create" {
		t.Fatalf("operations = %v, want a delete then a create", got)
	}
	// The address stayed, so nothing was released back to the pool.
	if alloc.releasedCount() != 0 {
		t.Errorf("released %d addresses for an in-place change", alloc.releasedCount())
	}
}
