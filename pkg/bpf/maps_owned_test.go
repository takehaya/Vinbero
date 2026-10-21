package bpf

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// These tests need only maps, not the full program's verifier load.
func newOwnedTestMaps(t *testing.T) *MapOperations {
	t.Helper()
	newMap := func(typ ebpf.MapType, key, value uint32) *ebpf.Map {
		spec := &ebpf.MapSpec{Type: typ, KeySize: key, ValueSize: value, MaxEntries: 32}
		if typ == ebpf.LPMTrie {
			spec.Flags = 1
		}
		m, err := ebpf.NewMap(spec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	o := &BpfObjects{}
	o.MupUplinkV4Map = newMap(ebpf.LPMTrie, uint32(binary.Size(MupUplinkV4Key{})), uint32(binary.Size(HeadendEntry{})))
	o.MupUplinkV6Map = newMap(ebpf.LPMTrie, uint32(binary.Size(MupUplinkV6Key{})), uint32(binary.Size(HeadendEntry{})))
	o.MupUplinkV4OwnerMap = newMap(ebpf.Hash, uint32(binary.Size(MupUplinkV4Key{})), auxOwnerTagBytes)
	o.MupUplinkV6OwnerMap = newMap(ebpf.Hash, uint32(binary.Size(MupUplinkV6Key{})), auxOwnerTagBytes)
	o.FdbMap = newMap(ebpf.Hash, uint32(binary.Size(FdbKey{})), uint32(binary.Size(FdbEntry{})))
	o.FdbOwnerMap = newMap(ebpf.Hash, uint32(binary.Size(FdbKey{})), auxOwnerTagBytes)
	o.BdPeerMap = newMap(ebpf.Hash, uint32(binary.Size(BdPeerKey{})), uint32(binary.Size(HeadendEntry{})))
	o.BdPeerOwnerMap = newMap(ebpf.Hash, uint32(binary.Size(BdPeerKey{})), auxOwnerTagBytes)
	o.BdPeerReverseMap = newMap(ebpf.Hash, uint32(binary.Size(BdPeerReverseKey{})), uint32(binary.Size(BdPeerReverseVal{})))
	o.BdPeerL2ExtMap = newMap(ebpf.Hash, uint32(binary.Size(BpfBdPeerL2ExtKey{})), uint32(binary.Size(BpfBdPeerL2ExtVal{})))
	return reopenOwnedTestMaps(o)
}
func reopenOwnedTestMaps(o *BpfObjects) *MapOperations {
	return &MapOperations{objs: o, mupUplinkV4Owners: newEntryOwnerMap(o.MupUplinkV4OwnerMap), mupUplinkV6Owners: newEntryOwnerMap(o.MupUplinkV6OwnerMap), fdbOwners: newEntryOwnerMap(o.FdbOwnerMap), bdPeerOwners: newEntryOwnerMap(o.BdPeerOwnerMap)}
}
func requireOwnerMismatch(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrEntryOwnerMismatch) {
		t.Fatalf("got %v, want owner mismatch", err)
	}
}

func TestOwnedMupUplink(t *testing.T) {
	m := newOwnedTestMaps(t)
	owner := OwnerPluginBundle("routes")
	for _, v6 := range []bool{false, true} {
		create, del, get := m.CreateMupUplinkV4Owned, m.DeleteMupUplinkV4Owned, m.GetMupUplinkV4Owner
		endpoint := "192.0.2.1"
		if v6 {
			create, del, get = m.CreateMupUplinkV6Owned, m.DeleteMupUplinkV6Owned, m.GetMupUplinkV6Owner
			endpoint = "2001:db8::1"
		}
		if err := create(7, endpoint, 100, 32, &HeadendEntry{}, owner); err != nil {
			t.Fatal(err)
		}
		requireOwnerMismatch(t, create(7, endpoint, 100, 32, &HeadendEntry{}, OwnerRPC))
		requireOwnerMismatch(t, del(7, endpoint, 100, 32, OwnerRPC))
		if tag, ok, err := get(7, endpoint, 100, 32); err != nil || !ok || tag != owner {
			t.Fatalf("owner %q %v %v", tag, ok, err)
		}
		if err := del(7, endpoint, 100, 32, owner); err != nil {
			t.Fatal(err)
		}
		if tag, ok, err := get(7, endpoint, 100, 32); err != nil || ok || tag != "" {
			t.Fatalf("owner survived: %q %v %v", tag, ok, err)
		}
	}
	key, _ := buildMupUplinkV4Key(7, "192.0.2.1", 0, 0)
	if err := m.objs.MupUplinkV4Map.Put(key, &HeadendEntry{}); err != nil {
		t.Fatal(err)
	}
	requireOwnerMismatch(t, m.CreateMupUplinkV4Owned(7, "192.0.2.1", 0, 0, &HeadendEntry{}, owner))
	requireOwnerMismatch(t, m.DeleteMupUplinkV4Owned(7, "192.0.2.1", 0, 0, owner))
	// A covering legacy prefix is not the exact entry being claimed.
	if err := m.CreateMupUplinkV4Owned(7, "192.0.2.1", 100, 32, &HeadendEntry{}, owner); err != nil {
		t.Fatal(err)
	}
	restarted := reopenOwnedTestMaps(m.objs)
	inventory, err := restarted.ListMupUplinkV4Owners()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("restart inventory %v %v", inventory, err)
	}
	if err := m.objs.MupUplinkV4Map.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteMupUplinkV4Owned(7, "192.0.2.1", 100, 32, owner); err == nil {
		t.Fatal("delete on frozen map succeeded")
	}
	inventory, err = restarted.ListMupUplinkV4Owners()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("failed-delete owner lost %v %v", inventory, err)
	}
}
func TestOwnedFdb(t *testing.T) {
	m := newOwnedTestMaps(t)
	owner := OwnerPluginBundle("routes")
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	operatorMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	if err := m.CreateFdbOwned(100, mac, &FdbEntry{IsRemote: 1, LastSeen: 1}, owner); err != nil {
		t.Fatal(err)
	}
	entry, err := m.GetFdb(100, mac)
	if err != nil || entry.IsStatic != 1 || entry.LastSeen != 0 {
		t.Fatalf("control entry isn't protected: %+v %v", entry, err)
	}
	requireOwnerMismatch(t, m.CreateFdb(100, mac, &FdbEntry{}))
	requireOwnerMismatch(t, m.DeleteFdb(100, mac))
	if err := m.CreateFdb(100, operatorMAC, &FdbEntry{IsStatic: 1}); err != nil {
		t.Fatal(err)
	}
	if n, err := m.FlushFdb(100, false); err != nil || n != 1 {
		t.Fatalf("flush %d %v", n, err)
	}
	if aged, err := m.AgeFdbEntries(1); err != nil || len(aged) != 0 {
		t.Fatalf("ager touched owned entry %v %v", aged, err)
	}
	inventory, err := reopenOwnedTestMaps(m.objs).ListFdbOwners()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("restart inventory %v %v", inventory, err)
	}
	if err := m.objs.FdbMap.Put(buildFdbKey(100, operatorMAC), &FdbEntry{}); err != nil {
		t.Fatal(err)
	}
	requireOwnerMismatch(t, m.CreateFdbOwned(100, operatorMAC, &FdbEntry{}, owner))
	requireOwnerMismatch(t, m.DeleteFdbOwned(100, operatorMAC, owner))
	if err := m.objs.FdbMap.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteFdbOwned(100, mac, owner); err == nil {
		t.Fatal("delete on frozen map succeeded")
	}
	if tag, ok, err := m.GetFdbOwner(100, mac); err != nil || !ok || tag != owner {
		t.Fatalf("failed-delete owner lost %q %v %v", tag, ok, err)
	}
}
func TestOwnedBdPeer(t *testing.T) {
	m := newOwnedTestMaps(t)
	owner := OwnerPluginBundle("routes")
	src := [16]byte{0x20, 1}
	esi := [10]byte{}
	index, err := m.CreateBdPeerAtFreeIndexOwned(100, &HeadendEntry{}, esi, src, true, owner)
	if err != nil {
		t.Fatal(err)
	}
	requireOwnerMismatch(t, m.CreateBdPeer(100, index, &HeadendEntry{}, esi, src, true))
	_, err = m.DeleteBdPeer(100, index)
	requireOwnerMismatch(t, err)
	// A different forward slot must not steal the reverse key.
	requireOwnerMismatch(t, m.CreateBdPeerOwned(100, index+1, &HeadendEntry{}, esi, src, true, OwnerBGPEVPN(65000)))
	if n, err := m.FlushBdPeers(100); err != nil || n != 0 {
		t.Fatalf("flush %d %v", n, err)
	}
	inventory, err := reopenOwnedTestMaps(m.objs).ListBdPeerOwners()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("restart inventory %v %v", inventory, err)
	}
	// Owner cleanup failure leaves an inventoried, unreusable slot.
	if err := m.objs.BdPeerOwnerMap.Freeze(); err != nil {
		t.Fatal(err)
	}
	if occupied, err := m.DeleteBdPeerOwned(100, index, owner); !occupied || err == nil {
		t.Fatalf("cleanup failure %v %v", occupied, err)
	}
	if got := m.FindFreeBdPeerIndex(100); got == index {
		t.Fatal("reused a slot with pending owner cleanup")
	}
	inventory, err = m.ListBdPeerOwners()
	if err != nil || len(inventory) != 1 {
		t.Fatalf("cleanup tombstone lost %v %v", inventory, err)
	}
}
func TestOwnedCreationRequiresOwnerPersistence(t *testing.T) {
	m := newOwnedTestMaps(t)
	owner := OwnerPluginBundle("routes")
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if err := m.objs.FdbOwnerMap.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdbOwned(100, mac, &FdbEntry{}, owner); err == nil {
		t.Fatal("write succeeded without persisted owner")
	}
	if _, err := m.GetFdb(100, mac); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("main map changed: %v", err)
	}
}

func TestOrdinaryOwnerInventoryAfterPartialDeletion(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "v4"
		if v6 {
			name = "v6"
		}
		t.Run(name, func(t *testing.T) {
			keySize := uint32(binary.Size(LpmKeyV4{}))
			if v6 {
				keySize = uint32(binary.Size(LpmKeyV6{}))
			}
			main, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: keySize, ValueSize: uint32(binary.Size(HeadendEntry{})), MaxEntries: 4, Flags: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = main.Close() })
			owners, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: keySize, ValueSize: auxOwnerTagBytes, MaxEntries: 4})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owners.Close() })
			objects := &BpfObjects{}
			if v6 {
				objects.HeadendV6Map, objects.HeadendV6OwnerMap = main, owners
			} else {
				objects.HeadendV4Map, objects.HeadendV4OwnerMap = main, owners
			}
			fresh := func() *MapOperations {
				return &MapOperations{objs: objects, headendV4Owners: newEntryOwnerMap(objects.HeadendV4OwnerMap), headendV6Owners: newEntryOwnerMap(objects.HeadendV6OwnerMap)}
			}
			m := fresh()
			create, del, list, live := m.CreateHeadendV4, m.DeleteHeadendV4, m.ListHeadendV4Owners, m.ListHeadendV4
			prefix := "10.0.0.1/32"
			if v6 {
				create, del, list, live = m.CreateHeadendV6, m.DeleteHeadendV6, m.ListHeadendV6Owners, m.ListHeadendV6
				prefix = "fd00:10::1/128"
			}
			owner := OwnerPluginBundle("ordinary")
			if err := create(prefix, &HeadendEntry{}, owner); err != nil {
				t.Fatal(err)
			}
			if err := owners.Freeze(); err != nil {
				t.Fatal(err)
			}
			if err := del(prefix, owner); err == nil {
				t.Fatal("frozen owner accepted deletion")
			}
			if entries, err := live(); err != nil || len(entries) != 0 {
				t.Fatalf("main deletion did not precede owner failure: %v %v", entries, err)
			}
			for _, scan := range []func() (map[string]OwnerTag, error){list, func() (map[string]OwnerTag, error) {
				if v6 {
					return fresh().ListHeadendV6Owners()
				}
				return fresh().ListHeadendV4Owners()
			}} {
				inventory, err := scan()
				if err != nil || len(inventory) != 1 || inventory[prefix] != owner {
					t.Fatalf("owner-only reservation missing: %v %v", inventory, err)
				}
			}
			if err := owners.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := list(); err == nil {
				t.Fatal("closed owner inventory reported success")
			}
		})
	}
}
