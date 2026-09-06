package cplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// fakeHeadendOps is an in-memory stand-in for the headend maps, holding
// the entry and its owner per prefix so cross-owner rules can be exercised
// without a live BPF collection.
type fakeHeadendOps struct {
	// mu guards everything below: the manager tests drive this from a
	// plugin's worker goroutine while the test itself reads it.
	mu      sync.Mutex
	v4      map[string]*bpf.HeadendEntry
	v6      map[string]*bpf.HeadendEntry
	owner4  map[string]bpf.OwnerTag
	owner6  map[string]bpf.OwnerTag
	writes  []string // "create v4 <prefix>" / "delete v4 <prefix>", in order
	failOn  string   // prefix whose create fails
	failDel string   // prefix whose delete fails
	listErr error
}

// maskKey is what the real map does to a prefix before it becomes a key.
//
// The BPF headend maps are LPM tries: they store the masked network and
// report it back that way, so 10.0.0.7/24 goes in and 10.0.0.0/24 comes
// out. A fake keyed on the raw string would accept an unmasked spelling
// and hand it straight back, hiding exactly the mismatch that leaks leases
// in production.
func maskKey(prefix string) string {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return prefix // the caller is testing the rejection; leave it alone
	}
	return pfx.Masked().String()
}

func newFakeHeadendOps() *fakeHeadendOps {
	return &fakeHeadendOps{
		v4:     map[string]*bpf.HeadendEntry{},
		v6:     map[string]*bpf.HeadendEntry{},
		owner4: map[string]bpf.OwnerTag{},
		owner6: map[string]bpf.OwnerTag{},
	}
}

func (f *fakeHeadendOps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*bpf.HeadendEntry, len(f.v4))
	for k, v := range f.v4 {
		out[k] = v
	}
	return out, f.listErr
}
func (f *fakeHeadendOps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*bpf.HeadendEntry, len(f.v6))
	for k, v := range f.v6 {
		out[k] = v
	}
	return out, f.listErr
}
func (f *fakeHeadendOps) GetHeadendV4Owner(rawPrefix string) (bpf.OwnerTag, bool, error) {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.owner4[p]
	return o, ok, nil
}
func (f *fakeHeadendOps) GetHeadendV6Owner(rawPrefix string) (bpf.OwnerTag, bool, error) {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.owner6[p]
	return o, ok, nil
}

func (f *fakeHeadendOps) CreateHeadendV4(rawPrefix string, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	if p == f.failOn {
		return fmt.Errorf("simulated write failure for %q", p)
	}
	if cur, ok := f.owner4[p]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	f.writes = append(f.writes, "create v4 "+p)
	f.v4[p] = e
	f.owner4[p] = owner
	return nil
}

func (f *fakeHeadendOps) CreateHeadendV6(rawPrefix string, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.owner6[p]; ok && cur != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	f.writes = append(f.writes, "create v6 "+p)
	f.v6[p] = e
	f.owner6[p] = owner
	return nil
}

// failDelete makes the map refuse to remove one prefix, which is how the
// flush and prune failure paths are reached at all.
func (f *fakeHeadendOps) failDelete(prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDel = maskKey(prefix)
}

func (f *fakeHeadendOps) DeleteHeadendV4(rawPrefix string, requester bpf.OwnerTag) error {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	if p == f.failDel {
		return fmt.Errorf("simulated delete failure for %q", p)
	}
	if cur, ok := f.owner4[p]; ok && cur != requester {
		return bpf.ErrEntryOwnerMismatch
	}
	f.writes = append(f.writes, "delete v4 "+p)
	delete(f.v4, p)
	delete(f.owner4, p)
	return nil
}

func (f *fakeHeadendOps) DeleteHeadendV6(rawPrefix string, requester bpf.OwnerTag) error {
	p := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.owner6[p]; ok && cur != requester {
		return bpf.ErrEntryOwnerMismatch
	}
	f.writes = append(f.writes, "delete v6 "+p)
	delete(f.v6, p)
	delete(f.owner6, p)
	return nil
}

// seedV4 puts an entry in the v4 map under the given owner, as if a
// previous apply had written it.
func (f *fakeHeadendOps) seedV4(rawPrefix string, owner bpf.OwnerTag) {
	prefix := maskKey(rawPrefix)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v4[prefix] = &bpf.HeadendEntry{}
	f.owner4[prefix] = owner
}

func desire(prefixes ...string) []HeadendDesired {
	out := make([]HeadendDesired, 0, len(prefixes))
	for i, p := range prefixes {
		// PolicyId varies per entry so an update is distinguishable.
		out = append(out, HeadendDesired{TriggerPrefix: p, Entry: &bpf.HeadendEntry{PolicyId: uint32(i + 1)}})
	}
	return out
}

// countV4 and getV4 exist because the manager tests read this fake while a
// plugin's worker goroutine writes it.
func (f *fakeHeadendOps) countV4() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.v4)
}

func (f *fakeHeadendOps) getV4(prefix string) (*bpf.HeadendEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.v4[prefix]
	return e, ok
}

func (f *fakeHeadendOps) snapshotV4() map[string]*bpf.HeadendEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*bpf.HeadendEntry, len(f.v4))
	for k, v := range f.v4 {
		out[k] = v
	}
	return out
}

func (f *fakeHeadendOps) v4Owners() map[string]bpf.OwnerTag {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bpf.OwnerTag, len(f.owner4))
	for k, v := range f.owner4 {
		out[k] = v
	}
	return out
}

func sortedV4(f *fakeHeadendOps) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.v4))
	for p := range f.v4 {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func TestApplyHeadendSetCreates(t *testing.T) {
	ops := newFakeHeadendOps()
	res, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Created != 2 || res.Updated != 0 || res.Pruned != 0 {
		t.Fatalf("result = %+v, want 2 created", res)
	}
	if got := sortedV4(ops); len(got) != 2 {
		t.Fatalf("map holds %v, want both prefixes", got)
	}
}

// The core derives the diff, so an owner re-declaring a shrunken set has
// the dropped entry pruned without ever issuing a delete.
func TestApplyHeadendSetPrunesWhatIsNoLongerDeclared(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	res, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24"), unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if res.Pruned != 1 || res.Updated != 1 {
		t.Fatalf("result = %+v, want 1 pruned and 1 updated", res)
	}
	if got := sortedV4(ops); len(got) != 1 || got[0] != "10.0.1.0/24" {
		t.Fatalf("map holds %v, want only 10.0.1.0/24", got)
	}
	// The pruned key's lease is released, so another owner may take it.
	if err := leases.Acquire(LeaseHeadendV4, "10.0.2.0/24", ownerB); err != nil {
		t.Errorf("pruned key is still leased: %v", err)
	}
}

// An owner's reconcile must not touch entries another owner holds, even
// though they live in the same map.
func TestApplyHeadendSetIgnoresOtherOwnersEntries(t *testing.T) {
	ops := newFakeHeadendOps()
	ops.seedV4("10.9.9.0/24", ownerB)
	if _, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := ops.v4["10.9.9.0/24"]; !ok {
		t.Fatal("the reconcile pruned another owner's entry")
	}
}

// Entries with no recorded owner predate owner tracking; a plugin must not
// be able to prune state it never wrote.
func TestApplyHeadendSetIgnoresUnownedEntries(t *testing.T) {
	ops := newFakeHeadendOps()
	ops.v4["10.9.9.0/24"] = &bpf.HeadendEntry{} // present, no owner recorded
	if _, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv4, nil, unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := ops.v4["10.9.9.0/24"]; !ok {
		t.Fatal("the reconcile pruned an entry with no recorded owner")
	}
}

// A set overlapping another owner's key must be rejected before anything
// is written, so a rejected declaration leaves no partial state.
func TestApplyHeadendSetRejectsLeasedKeyBeforeWriting(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	if err := leases.Acquire(LeaseHeadendV4, "10.0.2.0/24", ownerB); err != nil {
		t.Fatalf("setup lease: %v", err)
	}
	_, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited)
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("apply = %v, want ErrLeaseHeld", err)
	}
	if len(ops.writes) != 0 {
		t.Fatalf("a rejected set wrote to the data plane: %v", ops.writes)
	}
}

// Prunes precede writes so a prefix being re-pointed is never present
// twice, and both phases run in sorted order so a retry repeats the same
// sequence instead of a map-iteration reshuffle.
func TestApplyHeadendSetOrdersPrunesBeforeWrites(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.8.0/24", "10.0.9.0/24"), unlimited); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	ops.writes = nil
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := []string{
		"delete v4 10.0.8.0/24",
		"delete v4 10.0.9.0/24",
		"create v4 10.0.1.0/24",
		"create v4 10.0.2.0/24",
	}
	if len(ops.writes) != len(want) {
		t.Fatalf("writes = %v, want %v", ops.writes, want)
	}
	for i := range want {
		if ops.writes[i] != want[i] {
			t.Fatalf("writes = %v, want %v", ops.writes, want)
		}
	}
}

// A failure partway leaves earlier writes in place (BPF maps offer no
// multi-entry atomicity), but the apply is idempotent, so retrying the
// same set converges once the cause is gone.
func TestApplyHeadendSetIsRetryableAfterPartialFailure(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	ops.failOn = "10.0.2.0/24"
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited); err == nil {
		t.Fatal("apply should have failed on the seeded write failure")
	}
	if _, ok := ops.v4["10.0.1.0/24"]; !ok {
		t.Fatal("the write that succeeded before the failure was rolled back")
	}

	ops.failOn = ""
	res, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if res.Created+res.Updated != 2 || res.Pruned != 0 {
		t.Fatalf("retry result = %+v, want both entries present and nothing pruned", res)
	}
}

func TestApplyHeadendSetRejectsMalformedDeclarations(t *testing.T) {
	ops := newFakeHeadendOps()
	tests := []struct {
		name    string
		desired []HeadendDesired
	}{
		{name: "empty prefix", desired: []HeadendDesired{{Entry: &bpf.HeadendEntry{}}}},
		{name: "nil entry", desired: []HeadendDesired{{TriggerPrefix: "10.0.1.0/24"}}},
		{name: "duplicate prefix", desired: append(desire("10.0.1.0/24"), desire("10.0.1.0/24")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv4, tt.desired, unlimited); err == nil {
				t.Fatal("malformed declaration was accepted")
			}
			if len(ops.writes) != 0 {
				t.Fatalf("a malformed declaration wrote to the data plane: %v", ops.writes)
			}
		})
	}
}

func TestApplyHeadendSetRejectsEmptyOwner(t *testing.T) {
	ops := newFakeHeadendOps()
	if _, err := ApplyHeadendSet(ops, NewLeases(), "", AFv4, desire("10.0.1.0/24"), unlimited); !errors.Is(err, bpf.ErrEmptyOwner) {
		t.Fatalf("apply with an empty owner = %v, want ErrEmptyOwner", err)
	}
}

func TestApplyHeadendSetV6(t *testing.T) {
	ops := newFakeHeadendOps()
	res, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv6, desire("2001:db8:1::/48"), unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("result = %+v, want 1 created", res)
	}
	if _, ok := ops.v6["2001:db8:1::/48"]; !ok {
		t.Fatal("entry did not land in the v6 map")
	}
	if len(ops.v4) != 0 {
		t.Fatal("a v6 apply wrote into the v4 map")
	}
}

func TestPruneHeadendOwnerRemovesOnlyItsOwn(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	ops.seedV4("10.9.9.0/24", ownerB)

	pruned, err := PruneHeadendOwner(ops, leases, ownerA, AFv4)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned %d entries, want 2", pruned)
	}
	if got := sortedV4(ops); len(got) != 1 || got[0] != "10.9.9.0/24" {
		t.Fatalf("map holds %v, want only the other owner's entry", got)
	}
	if len(leases.KeysOf(LeaseHeadendV4, ownerA)) != 0 {
		t.Error("prune left leases behind")
	}
}

// A second owner must not be able to take a prefix the first one holds by
// spelling it with host bits set. The lease key and the map key have to be
// the same string, which is what canonicalizing at decode time gives.
func TestUnmaskedSpellingCannotEvadeTheLease(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	src := netip.MustParseAddr("fd00:1::1")

	declare := func(owner bpf.OwnerTag, spelling string) error {
		prefix, entry, err := DecodeHeadendEntry(&v1.PluginHeadendEntry{
			TriggerPrefix: spelling,
			Segments:      []string{"fd00:2::1"},
		}, AFv4, src)
		if err != nil {
			return err
		}
		_, err = ApplyHeadendSet(ops, leases, owner, AFv4,
			[]HeadendDesired{{TriggerPrefix: prefix, Entry: entry}}, unlimited)
		return err
	}

	if err := declare(ownerA, "10.0.1.0/24"); err != nil {
		t.Fatalf("owner A: %v", err)
	}
	if err := declare(ownerB, "10.0.1.9/24"); err == nil {
		t.Fatal("a second owner took the prefix by spelling it with host bits")
	}
}

// Redeclaring the same set must not churn. With the raw spelling as the
// key, the owner would fail to recognize the entry it just wrote and would
// prune and rewrite it on every apply.
func TestRedeclaringAnUnmaskedPrefixDoesNotChurn(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	src := netip.MustParseAddr("fd00:1::1")

	apply := func() ApplyResult {
		t.Helper()
		prefix, entry, err := DecodeHeadendEntry(&v1.PluginHeadendEntry{
			TriggerPrefix: "10.0.1.7/24",
			Segments:      []string{"fd00:2::1"},
		}, AFv4, src)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		res, err := ApplyHeadendSet(ops, leases, ownerA, AFv4,
			[]HeadendDesired{{TriggerPrefix: prefix, Entry: entry}}, unlimited)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		return res
	}

	apply()
	second := apply()
	if second.Pruned != 0 {
		t.Errorf("redeclaring the same set pruned %d entries", second.Pruned)
	}
	if second.Created != 0 {
		t.Errorf("redeclaring the same set created %d entries again", second.Created)
	}
}
