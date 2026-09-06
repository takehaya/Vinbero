package cplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

func inventoryLocator() locator.Locator {
	return locator.Locator{Name: "main", Prefix: netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64, Behavior: locator.BehaviorClassic,
		FunctionAutoStart: 1, FunctionAutoEnd: 16,
	}
}

func inventoryAllocator(t *testing.T) *locator.Manager {
	t.Helper()
	a := locator.NewManager()
	loc := inventoryLocator()
	if err := a.Add(&loc); err != nil {
		t.Fatal(err)
	}
	return a
}

func persistentSet(t *testing.T, store *Store, alloc *locator.Manager, sids SIDFunctionOps, grants EndtVRFGrantOps, resolve func(string) (uint32, error)) *LocalSIDSet {
	t.Helper()
	s := NewLocalSIDSet(alloc, sids, grants, resolve)
	if err := s.enablePersistence(store); err != nil {
		t.Fatal(err)
	}
	return s
}

func reopenInventory(t *testing.T, store *Store) *Store {
	t.Helper()
	s, err := NewStore(store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLocalSIDInventoryRestoresIdentityAndRebuildsGrants(t *testing.T) {
	for _, mode := range []string{"pinned", "legacy ownerless", "unpinned"} {
		t.Run(mode, func(t *testing.T) {
			store := newTestStore(t)
			a := inventoryAllocator(t)
			maps := newFakeSIDOps()
			first := persistentSet(t, store, a, maps, newFakeGrantOps(), func(string) (uint32, error) { return 19, nil })
			want := []LocalSID{{Name: "z", Locator: "main", Slot: 33, AuxRaw: []byte{1, 2}, DecapVRF: "blue"}}
			initial, _, err := first.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, LocalSID{Name: "a", Locator: "main", Slot: 34})
			if _, _, err := first.Apply(ownerA, want, unlimited); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unpinned":
				maps = newFakeSIDOps()
			case "legacy ownerless":
				maps.owners = map[string]bpf.OwnerTag{}
			}
			store = reopenInventory(t, store)
			nextAlloc := locator.NewManager()
			grants := newFakeGrantOps()
			next := persistentSet(t, store, nextAlloc, maps, grants, func(string) (uint32, error) { return 99, nil })
			if next.OwnsSID(ownerA, initial[0].SID) {
				t.Fatal("unconfirmed inventory authorized advertisement")
			}
			if _, _, err := next.Apply(ownerA, want, unlimited); !errors.Is(err, locator.ErrLocatorNotFound) {
				t.Fatalf("missing locator: %v", err)
			}
			loc := inventoryLocator()
			if err := nextAlloc.Add(&loc); err != nil {
				t.Fatal(err)
			}
			fn := uint32(1)
			if _, _, err := nextAlloc.AllocateSID("main", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
				t.Fatalf("startup reused saved SID: %v", err)
			}
			got, _, err := next.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			if got[1].Name != "z" || got[1].SID != initial[0].SID {
				t.Fatalf("identity changed: %+v -> %+v", initial, got)
			}
			if grants.grants[got[1].auxIndex] != 99 {
				t.Fatalf("grant was not resolved again: %v", grants.grants)
			}
			writes := maps.installCount()
			if _, _, err := next.Apply(ownerA, want, unlimited); err != nil {
				t.Fatal(err)
			}
			if maps.installCount() != writes {
				t.Fatal("unchanged live SID was reinstalled")
			}
		})
	}
}

func TestLocalSIDInventoryWriteFailureRetainsReservation(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "before rename", true: "after rename"}[afterRename], func(t *testing.T) {
			store := newTestStore(t)
			a := inventoryAllocator(t)
			maps := newFakeSIDOps()
			set := persistentSet(t, store, a, maps, nil, nil)
			store.sids.write = func(path string, body []byte) error {
				if afterRename {
					if err := writeFileAtomic(path, body); err != nil {
						return err
					}
				}
				return errors.New("injected write or directory sync failure")
			}
			want := []LocalSID{{Name: "self", Locator: "main", Slot: 33}}
			if out, _, err := set.Apply(ownerA, want, unlimited); err == nil || len(out) != 0 {
				t.Fatalf("failed save reported success: %v %v", out, err)
			}
			got := set.live[ownerA]["self"]
			if set.OwnsSID(ownerA, got.SID) || maps.count() != 0 {
				t.Fatal("failed save installed or advertised SID")
			}
			fn := got.reservation.Function
			if _, _, err := a.AllocateSID("main", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
				t.Fatalf("failed save released SID: %v", err)
			}
			// A new process sees whichever complete snapshot reached disk.
			reloaded := reopenInventory(t, store)
			records, err := reloaded.sids.load()
			if err != nil {
				t.Fatal(err)
			}
			if (len(records) == 1) != afterRename {
				t.Fatalf("disk outcome: %v", records)
			}
			store.sids.write = writeFileAtomic
			out, _, err := set.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			if out[0].SID != got.SID {
				t.Fatal("retry changed reserved address")
			}
		})
	}
}

func TestLocalSIDInventoryCleanupFailureRetainsAddress(t *testing.T) {
	for _, failure := range []string{"map delete", "snapshot before rename", "snapshot after rename"} {
		t.Run(failure, func(t *testing.T) {
			store := newTestStore(t)
			a := inventoryAllocator(t)
			maps := newFakeSIDOps()
			set := persistentSet(t, store, a, maps, nil, nil)
			want := []LocalSID{{Name: "self", Locator: "main", Slot: 33}}
			out, _, err := set.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			sid := out[0].SID
			fn := out[0].reservation.Function
			if failure == "map delete" {
				maps.delFailOn = sid.String() + "/128"
			} else {
				store.sids.write = func(path string, body []byte) error {
					if failure == "snapshot after rename" {
						if err := writeFileAtomic(path, body); err != nil {
							return err
						}
					}
					return errors.New("injected snapshot failure")
				}
			}
			if err := set.ReleaseOwner(ownerA); err == nil {
				t.Fatal("cleanup unexpectedly succeeded")
			}
			if set.LiveCount(ownerA) != 1 || set.OwnsSID(ownerA, sid) {
				t.Fatal("failed cleanup lost tracking or remained confirmed")
			}
			if _, _, err := a.AllocateSID("main", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
				t.Fatalf("failed cleanup returned address: %v", err)
			}
			// Restart at the failed boundary. A pre-rename failure still
			// reserves the address; a committed removal may release it only
			// because the exact dispatch has already been removed.
			bootStore := reopenInventory(t, store)
			bootAlloc := locator.NewManager()
			if err := ReserveStoredLocalSIDs(bootStore, bootAlloc); err != nil {
				t.Fatal(err)
			}
			loc := inventoryLocator()
			if err := bootAlloc.Add(&loc); err != nil {
				t.Fatal(err)
			}
			_, _, bootErr := bootAlloc.AllocateSID("main", &fn)
			if failure == "snapshot after rename" {
				if bootErr != nil || maps.count() != 0 {
					t.Fatalf("committed cleanup restart: %v", bootErr)
				}
			} else if !errors.Is(bootErr, locator.ErrFunctionInUse) {
				t.Fatalf("restart released incomplete cleanup: %v", bootErr)
			}
			maps.delFailOn = ""
			store.sids.write = writeFileAtomic
			if err := set.ReleaseOwner(ownerA); err != nil {
				t.Fatal(err)
			}
			if _, _, err := a.AllocateSID("main", &fn); err != nil {
				t.Fatalf("successful cleanup did not return address: %v", err)
			}
			records, err := reopenInventory(t, store).sids.load()
			if err != nil || len(records) != 0 {
				t.Fatalf("cleanup disk state: %v %v", records, err)
			}
		})
	}
}

type interruptedSIDInstall struct {
	*fakeSIDOps
	afterCreate bool
	dropOwner   bool
}

func (f *interruptedSIDInstall) CreateSidFunction(prefix string, e *bpf.SidFunctionEntry, aux *bpf.SidAuxEntry, owner bpf.OwnerTag) error {
	if f.afterCreate {
		if err := f.fakeSIDOps.CreateSidFunction(prefix, e, aux, owner); err != nil {
			return err
		}
		if f.dropOwner {
			delete(f.owners, prefix)
		}
	}
	return errors.New("interrupted SID installation")
}

func TestLocalSIDInventoryRecoversInterruptedInstallation(t *testing.T) {
	for _, point := range []string{"before create", "after create", "owner write and rollback failure", "grant and rollback failure", "missing VRF"} {
		t.Run(point, func(t *testing.T) {
			store := newTestStore(t)
			a := inventoryAllocator(t)
			maps := newFakeSIDOps()
			grants := newFakeGrantOps()
			var ops SIDFunctionOps = maps
			resolve := func(string) (uint32, error) { return 19, nil }
			switch point {
			case "before create":
				ops = &interruptedSIDInstall{fakeSIDOps: maps}
			case "after create":
				ops = &interruptedSIDInstall{fakeSIDOps: maps, afterCreate: true}
			case "owner write and rollback failure":
				ops = &interruptedSIDInstall{fakeSIDOps: maps, afterCreate: true, dropOwner: true}
			case "grant and rollback failure":
				grants.putErr = errors.New("grant write failed")
				loc := inventoryLocator()
				sid, _ := loc.BuildSID(1)
				maps.delFailOn = sid.String() + "/128"
			case "missing VRF":
				resolve = func(string) (uint32, error) { return 0, errors.New("VRF unavailable") }
			}
			set := persistentSet(t, store, a, ops, grants, resolve)
			want := []LocalSID{{Name: "self", Locator: "main", Slot: 33, DecapVRF: "blue"}}
			if out, _, err := set.Apply(ownerA, want, unlimited); err == nil || len(out) != 0 {
				t.Fatal("interrupted install reported success")
			}
			held := set.live[ownerA]["self"]
			if set.OwnsSID(ownerA, held.SID) {
				t.Fatal("unfinished SID authorized advertisement")
			}
			if _, _, err := a.AllocateSID("main", &held.reservation.Function); !errors.Is(err, locator.ErrFunctionInUse) {
				t.Fatalf("interrupted install freed its address: %v", err)
			}
			maps.delFailOn = ""
			if point == "owner write and rollback failure" {
				set.sids = maps
				if _, _, err := set.Apply(ownerA, want, unlimited); err != nil {
					t.Fatalf("retry of ownerless partial write: %v", err)
				}
			}
			next := persistentSet(t, reopenInventory(t, store), inventoryAllocator(t), maps, newFakeGrantOps(), func(string) (uint32, error) { return 99, nil })
			out, _, err := next.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			if out[0].SID != held.SID || !next.OwnsSID(ownerA, held.SID) {
				t.Fatal("restart did not recover reserved SID")
			}
		})
	}
}

func TestNewSIDCannotClaimUnownedDispatchThroughInventory(t *testing.T) {
	store := newTestStore(t)
	maps := newFakeSIDOps()
	loc := inventoryLocator()
	sid, _ := loc.BuildSID(1)
	prefix := sid.String() + "/128"
	maps.entries[prefix] = &bpf.SidFunctionEntry{Action: 33}
	set := persistentSet(t, store, inventoryAllocator(t), maps, nil, nil)
	if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "self", Locator: "main", Slot: 33}}, unlimited); err == nil {
		t.Fatal("claimed preexisting unowned dispatch")
	}
	records, err := reopenInventory(t, store).sids.load()
	if err != nil || len(records) != 0 {
		t.Fatalf("failed claim became durable recovery authority: %v %v", records, err)
	}
	if maps.entries[prefix].Action != 33 {
		t.Fatal("existing dispatch was modified")
	}
}

func TestLocalSIDInventoryRejectsForeignDispatch(t *testing.T) {
	for _, kind := range []string{"foreign owner", "ownerless wrong slot", "ownerless wrong flavor"} {
		t.Run(kind, func(t *testing.T) {
			store := newTestStore(t)
			maps := newFakeSIDOps()
			set := persistentSet(t, store, inventoryAllocator(t), maps, nil, nil)
			want := []LocalSID{{Name: "self", Locator: "main", Slot: 33}}
			out, _, err := set.Apply(ownerA, want, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			prefix := out[0].SID.String() + "/128"
			switch kind {
			case "foreign owner":
				maps.owners[prefix] = ownerB
			case "ownerless wrong slot":
				delete(maps.owners, prefix)
				maps.entries[prefix].Action = 34
			case "ownerless wrong flavor":
				delete(maps.owners, prefix)
				maps.entries[prefix].Flavor = 1
			}
			before := *maps.entries[prefix]
			next := persistentSet(t, reopenInventory(t, store), inventoryAllocator(t), maps, nil, nil)
			if _, _, err := next.Apply(ownerA, want, unlimited); err == nil {
				t.Fatal("accepted foreign dispatch")
			}
			if err := next.ReleaseOwner(ownerA); err == nil {
				t.Fatal("deleted foreign dispatch")
			}
			if *maps.entries[prefix] != before {
				t.Fatal("foreign dispatch changed")
			}
		})
	}
}

func TestLocalSIDInventoryPrunesWithoutRestoringKeptSID(t *testing.T) {
	store := newTestStore(t)
	maps := newFakeSIDOps()
	first := persistentSet(t, store, inventoryAllocator(t), maps, nil, nil)
	if _, _, err := first.Apply(ownerA, []LocalSID{{Name: "keep", Locator: "main", Slot: 33}, {Name: "drop", Locator: "main", Slot: 34}}, unlimited); err != nil {
		t.Fatal(err)
	}
	next := persistentSet(t, reopenInventory(t, store), locator.NewManager(), maps, nil, nil)
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: newFakeHeadendOps(), LocalSIDs: next, Capabilities: testCaps(), Guard: NewGuard(Scope{Locators: []string{"main"}, EndpointSlots: []uint32{33}}, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	n, err := ops.PruneOutOfScope(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if next.LiveCount(ownerA) != 1 || next.LiveSIDs(ownerA)[0].Name != "keep" || maps.count() != 1 {
		t.Fatal("prune changed retained pending SID")
	}
	if err := next.ReleaseOwner(ownerA); err != nil {
		t.Fatalf("unregister needed a locator: %v", err)
	}
}

func TestLocalSIDInventoryUnregistersWithoutGuestOrManifest(t *testing.T) {
	for _, hasManifest := range []bool{false, true} {
		t.Run(map[bool]string{false: "orphan inventory", true: "unloadable guest"}[hasManifest], func(t *testing.T) {
			store := newTestStore(t)
			maps := newFakeSIDOps()
			first := persistentSet(t, store, inventoryAllocator(t), maps, nil, nil)
			out, _, err := first.Apply(ownerA, []LocalSID{{Name: "self", Locator: "main", Slot: 33}}, unlimited)
			if err != nil {
				t.Fatal(err)
			}
			if hasManifest {
				if err := store.Save(Registration{Name: "a", Module: []byte("bad wasm")}); err != nil {
					t.Fatal(err)
				}
			}
			m, err := NewManager(ManagerConfig{Store: reopenInventory(t, store), Headend: newFakeHeadendOps(), Locators: locator.NewManager(), SIDFunctions: maps, Source: newFakeSource()})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Restore(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := m.Forget("a"); err == nil {
				t.Fatal("forget released inventory without cleanup")
			}
			maps.delFailOn = out[0].SID.String() + "/128"
			if err := m.Unregister(context.Background(), "a"); err == nil {
				t.Fatal("unregister ignored failed cleanup")
			}
			maps.delFailOn = ""
			if err := m.Unregister(context.Background(), "a"); err != nil {
				t.Fatal(err)
			}
			if m.localSIDs.LiveCount(ownerA) != 0 || maps.count() != 0 || len(m.Unrestored()) != 0 {
				t.Fatal("cleanup left owner state")
			}
			records, err := reopenInventory(t, store).sids.load()
			if err != nil || len(records) != 0 {
				t.Fatalf("inventory: %v %v", records, err)
			}
		})
	}
}

func TestLocalSIDInventoryRefusesMissingAndCorruptState(t *testing.T) {
	for _, kind := range []string{"missing file", "missing directory", "invalid JSON", "unknown version", "duplicate", "wrong address", "unknown field"} {
		t.Run(kind, func(t *testing.T) {
			store := newTestStore(t)
			set := persistentSet(t, store, inventoryAllocator(t), newFakeSIDOps(), nil, nil)
			if _, _, err := set.Apply(ownerA, []LocalSID{{Name: "self", Locator: "main", Slot: 33}}, unlimited); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(Registration{Name: "a", Module: []byte("module")}); err != nil {
				t.Fatal(err)
			}
			path := store.sids.path
			switch kind {
			case "missing file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "missing directory":
				if err := os.RemoveAll(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			default:
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(body, &doc); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "invalid JSON":
					body = []byte("{")
				case "unknown version":
					doc["version"] = 99
				case "duplicate":
					r := doc["records"].([]any)
					doc["records"] = append(r, r[0])
				case "wrong address":
					doc["records"].([]any)[0].(map[string]any)["sid"] = "fd00::1234"
				case "unknown field":
					doc["mystery"] = true
				}
				if kind != "invalid JSON" {
					body, err = json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewStore(store.Dir()); err == nil {
				t.Fatal("started with an empty or invalid inventory")
			}
		})
	}
}

func TestFlushRetainsSIDWhenAdvertisementWithdrawalFails(t *testing.T) {
	f := newSIDDependencyFixture(t)
	f.advertiser.failWithdraw = "10.7.0.0/24"
	if err := f.ops.Flush(); err == nil {
		t.Fatal("flush ignored failed withdrawal")
	}
	f.assertReferencesOwned(t)
	if !f.sids.OwnsSID(ownerA, f.oldSID) {
		t.Fatal("flush removed the advertised SID")
	}
	f.advertiser.failWithdraw = ""
	if err := f.ops.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.sids.LiveCount(ownerA) != 0 {
		t.Fatal("flush retry retained SID")
	}
}
