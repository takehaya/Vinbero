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
	mu        sync.Mutex
	entries   map[string]*bpf.SidFunctionEntry
	owners    map[string]bpf.OwnerTag
	failOn    string // prefix whose install fails
	delFailOn string // prefix whose delete fails (every time)
	delSkip   int    // number of successful deletes of delFailOn before it starts failing
	delSeen   int    // deletes of delFailOn observed so far
	installs  int
	auxNext   uint16 // next aux index to stamp when an entry carries aux
	ops       []string
}

func newFakeSIDOps() *fakeSIDOps {
	return &fakeSIDOps{
		entries: map[string]*bpf.SidFunctionEntry{},
		owners:  map[string]bpf.OwnerTag{},
	}
}

func (f *fakeSIDOps) CreateSidFunction(prefix string, e *bpf.SidFunctionEntry, aux *bpf.SidAuxEntry, owner bpf.OwnerTag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prefix == f.failOn {
		return errors.New("simulated install failure")
	}
	if cur, ok := f.owners[prefix]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	// Mirror allocAndPutBuiltinAux: an entry carrying aux gets a non-zero
	// aux index stamped, which is what a decap-VRF grant keys on.
	if aux != nil {
		f.auxNext++
		e.AuxIndex = f.auxNext
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
	if prefix == f.delFailOn {
		if f.delSeen >= f.delSkip {
			return errors.New("simulated delete failure")
		}
		f.delSeen++
	}
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

// fakeGrantOps records the decap-VRF grants a reconcile writes, keyed by the
// dispatch entry's aux index.
type fakeGrantOps struct {
	mu      sync.Mutex
	grants  map[uint32]uint32 // auxIndex -> vrfIfindex
	putErr  error             // when set, PutEndtVRFGrant fails
	putHook func()            // when set, runs inside PutEndtVRFGrant before the write
	ops     []string
}

func newFakeGrantOps() *fakeGrantOps {
	return &fakeGrantOps{grants: map[uint32]uint32{}}
}

func (f *fakeGrantOps) PutEndtVRFGrant(auxIndex, vrfIfindex uint32) error {
	if f.putHook != nil {
		f.putHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	if auxIndex == 0 {
		return errors.New("aux index must be non-zero")
	}
	f.grants[auxIndex] = vrfIfindex
	f.ops = append(f.ops, fmt.Sprintf("put %d=%d", auxIndex, vrfIfindex))
	return nil
}

func (f *fakeGrantOps) DeleteEndtVRFGrant(auxIndex uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.grants, auxIndex)
	f.ops = append(f.ops, fmt.Sprintf("delete %d", auxIndex))
	return nil
}

func (f *fakeGrantOps) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.grants)
}

// A decap-VRF SID writes a grant at install and withdraws it at release; the
// grant records the VRF ifindex the resolver returned, keyed by the dispatch
// entry's aux index.
func TestLocalSIDDecapVRFGrant(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	grants := newFakeGrantOps()
	resolve := func(name string) (uint32, error) {
		if name == "vrf-cust" {
			return 42, nil
		}
		return 0, fmt.Errorf("unknown vrf %q", name)
	}
	set := NewLocalSIDSet(alloc, sids, grants, resolve)
	owner := bpf.OwnerTag("plugin:demo")

	out, _, err := set.Apply(owner, []LocalSID{{
		Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-cust",
	}}, -1)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 allocated, got %d", len(out))
	}
	entry, ok := sids.entryFor(out[0].SID.String() + "/128")
	if !ok || entry.AuxIndex == 0 {
		t.Fatalf("dispatch entry missing or has no aux index: %+v", entry)
	}
	if got := grants.grants[uint32(entry.AuxIndex)]; got != 42 {
		t.Fatalf("grant for aux %d = %d, want 42", entry.AuxIndex, got)
	}

	// Dropping the SID from the declared set withdraws its grant.
	if _, _, err := set.Apply(owner, nil, -1); err != nil {
		t.Fatalf("apply empty: %v", err)
	}
	if grants.count() != 0 {
		t.Fatalf("grant not withdrawn: %v", grants.ops)
	}
}

// The grant lease is held across the resolve and the grant write, so a
// concurrent VrfDelete taking the same lock cannot free the ifindex between
// them. The resolver runs inside install's critical section, so a TryLock of
// the shared lease from there must fail.
func TestLocalSIDDecapVRFGrantHeldDuringResolve(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	grants := newFakeGrantOps()
	var lease sync.Mutex
	resolveCalled := false
	resolve := func(string) (uint32, error) {
		resolveCalled = true
		if lease.TryLock() {
			lease.Unlock()
			t.Error("grant lease was not held while install resolved the VRF")
		}
		return 42, nil
	}
	// The lease must also be held through the grant write, not just the
	// resolve: unlocking in between would reopen the very window this closes.
	putHooked := false
	grants.putHook = func() {
		putHooked = true
		if lease.TryLock() {
			lease.Unlock()
			t.Error("grant lease was not held while install wrote the grant")
		}
	}
	set := NewLocalSIDSet(alloc, sids, grants, resolve)
	set.grantLease = &lease
	owner := bpf.OwnerTag("plugin:demo")

	if _, _, err := set.Apply(owner, []LocalSID{{
		Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-cust",
	}}, -1); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !resolveCalled {
		t.Fatal("resolver never ran")
	}
	if !putHooked {
		t.Fatal("grant write never ran")
	}
	// The lease is released once install returns.
	if !lease.TryLock() {
		t.Fatal("grant lease still held after install returned")
	}
	lease.Unlock()
}

// A redeclaration that does not change the decap VRF rewrites nothing, so no
// aux index leaks and the grant stays put.
func TestLocalSIDDecapVRFIdempotent(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	grants := newFakeGrantOps()
	resolve := func(string) (uint32, error) { return 7, nil }
	set := NewLocalSIDSet(alloc, sids, grants, resolve)
	owner := bpf.OwnerTag("plugin:demo")
	decl := []LocalSID{{Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-cust"}}

	if _, _, err := set.Apply(owner, decl, -1); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	firstInstalls := sids.installCount()
	if _, _, err := set.Apply(owner, decl, -1); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if sids.installCount() != firstInstalls {
		t.Fatalf("redeclaration rewrote the entry: installs %d -> %d", firstInstalls, sids.installCount())
	}
	if grants.count() != 1 {
		t.Fatalf("want 1 grant held, got %d", grants.count())
	}
}

// A DecapVRF declaration on a daemon that cannot grant one is refused rather
// than installed as a SID the data plane would drop on.
func TestLocalSIDDecapVRFUnsupported(t *testing.T) {
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps(), nil, nil)
	_, _, err := set.Apply(bpf.OwnerTag("plugin:demo"), []LocalSID{{
		Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-cust",
	}}, -1)
	if err == nil {
		t.Fatal("want error for decap VRF with no grant support, got nil")
	}
}

// A rebind that strands must not carry the old, already-freed aux index into
// its tracking record. If it did, the next reconcile's removeEntry would
// delete a grant at that index -- which the allocator may have handed to
// another SID -- wrongly withdrawing an unrelated plugin's live grant. The
// stranded record must record auxIndex 0 (like the fresh-install strand) and
// defer grant cleanup to the map layer.
func TestLocalSIDRebindStrandDoesNotDeleteReusedGrant(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	grants := newFakeGrantOps()
	resolve := func(name string) (uint32, error) {
		if name == "vrf-a" {
			return 11, nil
		}
		return 22, nil
	}
	set := NewLocalSIDSet(alloc, sids, grants, resolve)
	owner := bpf.OwnerTag("plugin:demo")

	// 1. Install "a" with decap vrf-a: grant lands at aux index 1.
	if _, _, err := set.Apply(owner, []LocalSID{{Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-a"}}, -1); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// 2. Redeclare "a" with a different decap VRF (a rebind: same locator,
	// changed contents). The rebind removes the old entry (freeing index 1),
	// then the reinstall strands -- grant write and its rollback both fail.
	grants.putErr = errors.New("grant map full")
	// The rebind deletes the old entry (1st delete of this prefix, succeeds)
	// then the reinstall's rollback deletes it again (2nd, fails) -> stranded.
	sids.delFailOn = "fd00:1::1/128"
	sids.delSkip = 1
	_, _, err := set.Apply(owner, []LocalSID{{Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-b"}}, -1)
	if !errors.Is(err, errInstallEntryStranded) {
		t.Fatalf("want errInstallEntryStranded from the rebind, got %v", err)
	}

	// 3. Simulate the freed index 1 being handed to another plugin's live
	// decap-VRF SID: a foreign grant now occupies index 1.
	grants.mu.Lock()
	grants.grants[1] = 9999
	grants.mu.Unlock()

	// 4. The plugin drops the set. The stranded "a" is pruned; its removeEntry
	// must NOT delete the foreign grant at index 1.
	grants.putErr = nil
	sids.delFailOn = ""
	if _, _, err := set.Apply(owner, nil, -1); err != nil {
		t.Fatalf("cleanup apply: %v", err)
	}
	grants.mu.Lock()
	_, foreignSurvives := grants.grants[1]
	grants.mu.Unlock()
	if !foreignSurvives {
		t.Fatal("the rebind-strand removeEntry deleted a foreign grant at the reused aux index")
	}
}

// When the grant write fails and the rollback of the dispatch entry also
// fails, the entry is still live in the map. The address must not be released
// -- a later allocation would collide with the entry nothing else tracks --
// and the SID stays tracked so a later reconcile removes it by prefix.
func TestLocalSIDDecapVRFStrandedEntryKeepsAddress(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	grants := newFakeGrantOps()
	grants.putErr = errors.New("grant map full")
	set := NewLocalSIDSet(alloc, sids, grants, func(string) (uint32, error) { return 9, nil })
	owner := bpf.OwnerTag("plugin:demo")

	// The rollback delete of the just-created entry also fails, so the entry
	// is stranded.
	decl := []LocalSID{{Name: "a", Locator: "main", Slot: 32, DecapVRF: "vrf-cust"}}
	// The address the allocator will hand out, so the delete of its prefix can
	// be made to fail.
	sids.delFailOn = "fd00:1::1/128"

	_, _, err := set.Apply(owner, decl, -1)
	if err == nil {
		t.Fatal("want an error when the grant write and its rollback both fail")
	}
	if !errors.Is(err, errInstallEntryStranded) {
		t.Fatalf("want errInstallEntryStranded, got %v", err)
	}
	if alloc.releasedCount() != 0 {
		t.Fatalf("released %d addresses; a stranded entry's address must be kept", alloc.releasedCount())
	}

	// Redeclaring the SAME set must not be mistaken for already-installed: the
	// stranded entry has no grant, so the reconcile has to remove and reinstall
	// it. With the failures cleared it now converges, grant and all.
	sids.delFailOn = ""
	grants.putErr = nil
	out, _, err := set.Apply(owner, decl, -1)
	if err != nil {
		t.Fatalf("re-apply after strand: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("re-apply produced %d SIDs, want 1", len(out))
	}
	entry, ok := sids.entryFor(out[0].SID.String() + "/128")
	if !ok {
		t.Fatal("re-apply left no dispatch entry")
	}
	if grants.grants[uint32(entry.AuxIndex)] != 9 {
		t.Fatalf("re-apply did not write the grant; a stranded entry was mistaken for up to date: %v", grants.ops)
	}

	// And it can still be cleaned up.
	if _, _, err := set.Apply(owner, nil, -1); err != nil {
		t.Fatalf("cleanup apply: %v", err)
	}
	if sids.count() != 0 {
		t.Fatalf("entry not cleaned up: %d entries remain", sids.count())
	}
}

// The two halves of a plugin meet here: a declared SID is allocated, the
// dispatch entry points it at the plugin's own slot, and the plugin is
// told the address it got.
func TestLocalSIDAllocatesAndInstalls(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids, nil, nil)

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
	set := NewLocalSIDSet(alloc, newFakeSIDOps(), nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
	set := NewLocalSIDSet(alloc, newFakeSIDOps(), nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps(), nil, nil)
	if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "svc-a", Locator: "main", Slot: 1}}, unlimited); err == nil {
		t.Fatal("a SID pointing at a built-in slot was accepted")
	}
}

func TestLocalSIDRejectsMalformed(t *testing.T) {
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps(), nil, nil)
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
	set := NewLocalSIDSet(nil, nil, nil, nil)
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

	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)

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
	set := NewLocalSIDSet(&fakeAllocator{}, sids, nil, nil)
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
	set := NewLocalSIDSet(alloc, sids, nil, nil)
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
