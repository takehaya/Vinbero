package cplane

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
)

func sharedHeadend(t *testing.T, maps HeadendMapOps) *headend.Reconciler {
	t.Helper()
	r, err := headend.NewReconciler(maps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSharedHeadendRejectsConflictBeforePruning(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprintf("pinned=%t", pinned), func(t *testing.T) {
			maps := newFakeHeadendOps()
			r := sharedHeadend(t, maps)
			if _, err := r.ApplySet(ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
				t.Fatal(err)
			}
			writer := r.CreateHeadendV4
			if pinned {
				writer = maps.CreateHeadendV4 // no in-memory lease after restart
			}
			if err := writer("10.0.2.0/24", &bpf.HeadendEntry{}, bpf.OwnerBuiltin); err != nil {
				t.Fatal(err)
			}
			res, err := r.ApplySet(ownerA, AFv4, desire("10.0.2.0/24"), unlimited)
			if !errors.Is(err, bpf.ErrEntryOwnerMismatch) || res.Total() != 0 {
				t.Fatalf("conflict = %+v, %v; want refusal before mutation", res, err)
			}
			if got := maps.v4Owners(); got["10.0.1.0/24"] != ownerA || got["10.0.2.0/24"] != bpf.OwnerBuiltin {
				t.Fatalf("conflict changed working routes: %v", got)
			}
		})
	}
}

func TestSharedHeadendCanonicalKeysAndHandoff(t *testing.T) {
	for _, tc := range []struct {
		af          AddressFamily
		raw, masked string
	}{
		{AFv4, "10.0.1.7/24", "10.0.1.0/24"},
		{AFv6, "2001:db8:1::7/48", "2001:db8:1::/48"},
	} {
		t.Run(tc.af.String(), func(t *testing.T) {
			maps := newFakeHeadendOps()
			r := sharedHeadend(t, maps)
			put, remove := r.CreateHeadendV4, r.DeleteHeadendV4
			kind := LeaseHeadendV4
			if tc.af == AFv6 {
				put, remove = r.CreateHeadendV6, r.DeleteHeadendV6
				kind = LeaseHeadendV6
			}
			if err := put(tc.raw, &bpf.HeadendEntry{}, bpf.OwnerBuiltin); err != nil {
				t.Fatal(err)
			}
			if holder, ok := r.Leases().HolderOf(kind, tc.masked); !ok || holder != bpf.OwnerBuiltin {
				t.Fatalf("lease = %q, %t", holder, ok)
			}
			if _, err := r.ApplySet(ownerA, tc.af, desire(tc.masked), unlimited); err == nil {
				t.Fatal("plugin stole a built-in key")
			}
			if err := remove(tc.raw, bpf.OwnerBuiltin); err != nil {
				t.Fatal(err)
			}
			if _, err := r.ApplySet(ownerA, tc.af, desire(tc.raw), unlimited); err != nil {
				t.Fatalf("plugin could not acquire released key: %v", err)
			}
			if err := remove(tc.masked, bpf.OwnerBuiltin); err == nil {
				t.Fatal("old owner's withdrawal deleted the plugin's entry")
			}
			if _, err := r.PruneOwner(ownerA, tc.af); err != nil {
				t.Fatal(err)
			}
			if err := put(tc.masked, &bpf.HeadendEntry{}, bpf.OwnerBuiltin); err != nil {
				t.Fatalf("built-in could not reacquire after plugin flush: %v", err)
			}
		})
	}
}

func TestSharedHeadendFailureRetainsOnlyLiveReservations(t *testing.T) {
	maps := newFakeHeadendOps()
	r := sharedHeadend(t, maps)
	const key = "10.0.1.0/24"
	maps.failOn = key
	if err := r.CreateHeadendV4(key, &bpf.HeadendEntry{}, bpf.OwnerBuiltin); err == nil {
		t.Fatal("expected create failure")
	}
	if _, held := r.Leases().HolderOf(LeaseHeadendV4, key); held {
		t.Fatal("failed creation leaked a lease")
	}
	maps.failOn = ""
	if err := r.CreateHeadendV4(key, &bpf.HeadendEntry{}, bpf.OwnerBuiltin); err != nil {
		t.Fatal(err)
	}
	maps.failDel = key
	if err := r.DeleteHeadendV4(key, bpf.OwnerBuiltin); err == nil {
		t.Fatal("expected delete failure")
	}
	if holder, held := r.Leases().HolderOf(LeaseHeadendV4, key); !held || holder != bpf.OwnerBuiltin {
		t.Fatal("failed deletion lost a live reservation")
	}
	maps.failDel = ""
	if err := r.DeleteHeadendV4(key, bpf.OwnerBuiltin); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplySet(ownerA, AFv4, desire(key), unlimited); err != nil {
		t.Fatalf("failed-delete retry stranded the key: %v", err)
	}
}

type stalledHeadendScan struct {
	*fakeHeadendOps
	started, resume chan struct{}
	once            sync.Once
}

func (m *stalledHeadendScan) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) {
	m.once.Do(func() { close(m.started); <-m.resume })
	return m.fakeHeadendOps.ListHeadendV4()
}

func TestSharedHeadendScanDoesNotBlockBuiltinAndReservesPendingKeys(t *testing.T) {
	maps := &stalledHeadendScan{fakeHeadendOps: newFakeHeadendOps(), started: make(chan struct{}), resume: make(chan struct{})}
	r := sharedHeadend(t, maps)
	var resume sync.Once
	release := func() { resume.Do(func() { close(maps.resume) }) }
	t.Cleanup(release)
	applied := make(chan error, 1)
	go func() {
		_, err := r.ApplySet(ownerA, AFv4, desire("10.0.1.0/24"), unlimited)
		applied <- err
	}()
	<-maps.started
	builtin := make(chan error, 1)
	go func() {
		// The plugin reserved its key but has not written its owner record.
		if err := r.DeleteHeadendV4("10.0.1.0/24", bpf.OwnerBuiltin); !errors.Is(err, ErrLeaseHeld) {
			builtin <- fmt.Errorf("pending plugin key was not protected: %v", err)
			return
		}
		builtin <- r.CreateHeadendV4("10.0.2.0/24", &bpf.HeadendEntry{}, bpf.OwnerBuiltin)
	}()
	select {
	case err := <-builtin:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("synchronous BGP writer waited for another owner's full-map scan")
		release()
		<-builtin
	}
	release()
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if got := maps.v4Owners(); len(got) != 2 {
		t.Fatalf("independent writers lost entries: %v", got)
	}
}

func TestSharedHeadendSerializesSameOwnerSets(t *testing.T) {
	maps := newFakeHeadendOps()
	r := sharedHeadend(t, maps)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set := desire(fmt.Sprintf("10.%d.1.0/24", i), fmt.Sprintf("10.%d.2.0/24", i))
			if _, err := r.ApplySet(ownerA, AFv4, set, unlimited); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if keys := sortedV4(maps); len(keys) != 2 || strings.Split(keys[0], ".")[1] != strings.Split(keys[1], ".")[1] {
		t.Fatalf("concurrent whole sets produced a mixed declaration: %v", keys)
	}
	if got := r.Leases().CountOf(LeaseHeadendV4, ownerA); got != 2 {
		t.Fatalf("map and leases diverged: %d leases", got)
	}
}

func TestSharedHeadendValidatesWholeDeclarationBeforeMutation(t *testing.T) {
	for _, set := range [][]HeadendDesired{
		desire("10.0.2.1/24", "10.0.2.7/24"),
		desire("10.0.2.0/24", "2001:db8::/32"),
		desire("10.0.2.0/24", "::ffff:10.0.3.0/120"),
	} {
		maps := newFakeHeadendOps()
		r := sharedHeadend(t, maps)
		if _, err := r.ApplySet(ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ApplySet(ownerA, AFv4, set, unlimited); err == nil {
			t.Fatal("invalid set was accepted")
		}
		if got := sortedV4(maps); len(got) != 1 || got[0] != "10.0.1.0/24" {
			t.Fatalf("validation pruned a working entry: %v", got)
		}
	}
}

func TestManagerSharesHeadendReconcilerAndRejectsAmbiguousConfig(t *testing.T) {
	maps := newFakeHeadendOps()
	r := sharedHeadend(t, maps)
	m, err := NewManager(ManagerConfig{HeadendReconciler: r})
	if err != nil {
		t.Fatal(err)
	}
	if m.headend != r || m.leases != r.Leases() {
		t.Fatal("manager created a separate writer or lease table")
	}
	if _, err := NewManager(ManagerConfig{Headend: maps, HeadendReconciler: r}); err == nil {
		t.Fatal("ambiguous map configuration was accepted")
	}
	if _, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, HeadendReconciler: r, Leases: NewLeases()}); err == nil {
		t.Fatal("split lease tables were accepted")
	}
}
