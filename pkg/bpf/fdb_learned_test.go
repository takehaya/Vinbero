package bpf

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLearnFdbUnownedAndBGPReplacement(t *testing.T) {
	m := newOwnedTestMaps(t)
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, oif := range []uint32{3, 4} {
		if local, err := m.LearnFdb(100, mac, oif); err != nil || !local {
			t.Fatalf("learn on %d: local=%v err=%v", oif, local, err)
		}
		entry, err := m.GetFdb(100, mac)
		if err != nil || entry.Oif != oif || entry.IsRemote != 0 || entry.IsStatic != 0 || entry.LastSeen == 0 {
			t.Fatalf("learned entry: %+v err=%v", entry, err)
		}
		if tag, owned, err := m.GetFdbOwner(100, mac); err != nil || owned {
			t.Fatalf("learning claimed owner: %q %v %v", tag, owned, err)
		}
	}
	if err := m.DeleteLearnedFdb(100, mac, 3); err != nil {
		t.Fatal(err)
	}
	if entry, err := m.GetFdb(100, mac); err != nil || entry.Oif != 4 {
		t.Fatalf("stale interface DEL removed moved MAC: %+v %v", entry, err)
	}
	owner := OwnerBGPEVPN(65100)
	if err := m.CreateFdbOwned(100, mac, &FdbEntry{IsRemote: 1, PeerIndex: 7}, owner); err != nil {
		t.Fatalf("BGP could not replace unowned dynamic learning: %v", err)
	}
	if err := m.DeleteLearnedFdb(100, mac, 4); err != nil {
		t.Fatal(err)
	}
	if local, err := m.LearnFdb(100, mac, 9); err != nil || local {
		t.Fatalf("learn replaced BGP: local=%v err=%v", local, err)
	}
	if entry, err := m.GetFdb(100, mac); err != nil || entry.IsRemote != 1 || entry.PeerIndex != 7 || entry.IsStatic != 1 {
		t.Fatalf("BGP forwarding changed: %+v %v", entry, err)
	}
	if tag, owned, err := m.GetFdbOwner(100, mac); err != nil || !owned || tag != owner {
		t.Fatalf("BGP owner changed: %q %v %v", tag, owned, err)
	}
}

func TestLearnFdbPreservesProtectedEntries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner OwnerTag
		entry FdbEntry
	}{
		{"RPC_dynamic", OwnerRPC, FdbEntry{Oif: 3, LastSeen: 1}},
		{"RPC_static", OwnerRPC, FdbEntry{Oif: 3, IsStatic: 1}},
		{"BGP", OwnerBGPEVPN(65100), FdbEntry{IsRemote: 1, PeerIndex: 7}},
		{"plugin", OwnerPluginBundle("test"), FdbEntry{Oif: 3}},
		{"legacy_static", "", FdbEntry{Oif: 3, IsStatic: 1}},
		{"unowned_remote", "", FdbEntry{IsRemote: 1, PeerIndex: 7, LastSeen: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newOwnedTestMaps(t)
			mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
			if tc.owner != "" {
				if err := m.CreateFdbOwned(100, mac, &tc.entry, tc.owner); err != nil {
					t.Fatal(err)
				}
			} else if err := m.objs.FdbMap.Put(buildFdbKey(100, mac), &tc.entry); err != nil {
				t.Fatal(err)
			}
			before, err := m.GetFdb(100, mac)
			if err != nil {
				t.Fatal(err)
			}
			if local, err := m.LearnFdb(100, mac, 9); err != nil || local {
				t.Fatalf("protected learn: local=%v err=%v", local, err)
			}
			if err := m.DeleteLearnedFdb(100, mac, 3); err != nil {
				t.Fatal(err)
			}
			after, err := m.GetFdb(100, mac)
			if err != nil || *after != *before {
				t.Fatalf("protected entry changed: before=%+v after=%+v err=%v", before, after, err)
			}
			if tag, owned, err := m.GetFdbOwner(100, mac); err != nil || tag != tc.owner || owned != (tc.owner != "") {
				t.Fatalf("protected owner changed: %q %v %v", tag, owned, err)
			}
		})
	}
}

func TestLearnFdbDeleteAndErrors(t *testing.T) {
	m := newOwnedTestMaps(t)
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	if local, err := m.LearnFdb(100, mac, 3); err != nil || !local {
		t.Fatalf("learn: %v %v", local, err)
	}
	for range 2 {
		if err := m.DeleteLearnedFdb(100, mac, 3); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.GetFdb(100, mac); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("dynamic local not removed: %v", err)
	}
	if _, err := m.LearnFdb(0, mac, 3); err == nil {
		t.Fatal("accepted zero bridge domain")
	}
	if _, err := m.LearnFdb(100, nil, 3); err == nil {
		t.Fatal("accepted invalid MAC")
	}
	if _, err := m.LearnFdb(100, mac, 0); err == nil {
		t.Fatal("accepted zero interface")
	}
	if err := m.objs.FdbMap.Freeze(); err != nil {
		t.Fatal(err)
	}
	if local, err := m.LearnFdb(100, mac, 3); err == nil || local {
		t.Fatalf("frozen map accepted local learning: %v %v", local, err)
	}
	if _, owned, err := m.GetFdbOwner(100, mac); err != nil || owned {
		t.Fatalf("failed learning left owner: %v %v", owned, err)
	}
}

func TestLearnFdbConcurrentManagedPublication(t *testing.T) {
	m := newOwnedTestMaps(t)
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	owner := OwnerBGPEVPN(65100)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, work := range []func() error{
		func() error {
			for range 100 {
				if _, err := m.LearnFdb(100, mac, 3); err != nil {
					return err
				}
				if err := m.DeleteLearnedFdb(100, mac, 3); err != nil {
					return err
				}
			}
			return nil
		},
		func() error {
			for range 100 {
				if err := m.CreateFdbOwned(100, mac, &FdbEntry{IsRemote: 1, PeerIndex: 7}, owner); err != nil {
					return err
				}
			}
			return nil
		},
	} {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- work() }()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if entry, err := m.GetFdb(100, mac); err != nil || entry.IsRemote != 1 || entry.PeerIndex != 7 || entry.IsStatic != 1 {
		t.Fatalf("learning raced managed publication: %+v %v", entry, err)
	}
}

func TestXDPProgLearnedFdbBGPReplacement(t *testing.T) {
	f := newFdbAtomicFixture(t)
	m := f.h.mapOps
	if local, err := m.LearnFdb(100, f.mac, 3); err != nil || !local {
		t.Fatalf("learn: %v %v", local, err)
	}
	probe, err := buildVlanTaggedARPPacket(100, net.HardwareAddr{0, 0, 0, 0, 0, 3}, f.mac)
	if err != nil {
		t.Fatal(err)
	}
	if ret, _ := f.h.run(probe); ret != XDP_PASS {
		t.Fatalf("local destination unexpectedly encapsulated: %d", ret)
	}
	if err := m.CreateFdbOwned(100, f.mac, &FdbEntry{IsRemote: 1, PeerIndex: 1}, OwnerBGPEVPN(65100)); err != nil {
		t.Fatal(err)
	}
	if local, err := m.LearnFdb(100, f.mac, 9); err != nil || local {
		t.Fatalf("late kernel NEW displaced BGP: %v %v", local, err)
	}
	if err := m.DeleteLearnedFdb(100, f.mac, 3); err != nil {
		t.Fatal(err)
	}
	// Neither actual BPF learner may replace the newly managed identity.
	f.h.run(f.local)
	f.h.run(f.remote[0])
	ret, out := f.h.run(probe)
	if ret != XDP_DROP && ret != XDP_REDIRECT {
		t.Fatalf("BGP destination no longer encapsulated: %d", ret)
	}
	if got := outerIPv6DA(t, out); got != f.peerSID[1] {
		t.Fatalf("wrong BGP peer after kernel/BPF learning: got=%v want=%v", got, f.peerSID[1])
	}
}
