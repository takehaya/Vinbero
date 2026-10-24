package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// Check the shipped object, including the packed-layout load's lowering.
func TestFdbForwardingInstructions(t *testing.T) {
	spec, err := LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	if size := spec.Maps["fdb_map"].ValueSize; size != 32 || binary.Size(FdbEntry{}) != 32 {
		t.Fatalf("FDB ABI changed: map=%d Go encoding=%d", size, binary.Size(FdbEntry{}))
	}
	var snapshots, swaps int
	for _, prog := range spec.Programs {
		for _, ins := range prog.Instructions {
			if source := ins.Source(); source != nil && strings.Contains(source.String(), "*(const volatile __u64 *)") &&
				ins.OpCode.Class() == asm.LdXClass && ins.Offset == 0 {
				if ins.OpCode.Size() != asm.DWord {
					t.Fatalf("split FDB snapshot: %v", ins)
				}
				snapshots++
			}
			if ins.OpCode.AtomicOp() == asm.CmpXchg {
				if ins.OpCode.Size() != asm.DWord || ins.Offset != 0 {
					t.Fatalf("unaligned/non-word FDB CAS: %v", ins)
				}
				swaps++
			}
		}
	}
	if snapshots < 2 || swaps < 2 {
		t.Fatalf("missing atomic learning/snapshots: snapshots=%d CAS=%d", snapshots, swaps)
	}
	t.Logf("FDB object: %d aligned snapshots, %d word CAS sites", snapshots, swaps)
}

type fdbAtomicFixture struct {
	h       *xdpTestHelper
	mac     net.HardwareAddr
	local   []byte
	remote  [2][]byte
	peerSID [2][16]byte
}

func newFdbAtomicFixture(t *testing.T) *fdbAtomicFixture {
	t.Helper()
	f := &fdbAtomicFixture{h: newXDPTestHelper(t), mac: net.HardwareAddr{0, 0, 0, 0, 0, 1}}
	src, _ := ParseIPv6("fc00::1")
	segments, n, _ := ParseSegments([]string{"fc00::200"})
	f.h.createHeadendL2Entry(1, 100, src, segments, n, 100)
	f.h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2, 100)
	var err error
	f.local, err = buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		outerSrc := net.ParseIP(fmt.Sprintf("fd00:1:%d::1", i+1))
		f.peerSID[i], _ = ParseIPv6(fmt.Sprintf("fd00:2:%d::1", i+1))
		var segs [MaxSegments][IPv6AddrLen]byte
		segs[0] = f.peerSID[i]
		entry := &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
			NumSegments: 1, SrcAddr: src, Segments: segs, BdId: 100,
		}
		var remoteSrc [16]byte
		copy(remoteSrc[:], outerSrc.To16())
		if err := f.h.mapOps.CreateBdPeer(100, uint16(i), entry, [ESILen]byte{}, remoteSrc, true); err != nil {
			t.Fatal(err)
		}
		f.remote[i], err = buildL2EncapsulatedPacket(outerSrc, net.ParseIP("fd00:1:100::10"),
			[]net.IP{net.ParseIP("fd00:1:100::10")}, 0, 100,
			net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.1"), true)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestXDPProgFDBAtomicLearning(t *testing.T) {
	f := newFdbAtomicFixture(t)
	// A legacy local node has no value.BdId. Moving its forwarding word
	// must still resolve the BD's remote peer, including after a peer move.
	if err := f.h.mapOps.CreateFdb(100, f.mac, &FdbEntry{Oif: 2}); err != nil {
		t.Fatal(err)
	}
	probe, err := buildVlanTaggedARPPacket(100, net.HardwareAddr{0, 0, 0, 0, 0, 3}, f.mac)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		f.h.run(f.remote[i])
		got, err := f.h.mapOps.GetFdb(100, f.mac)
		if err != nil || got.IsRemote != 1 || got.Oif != 0 || got.PeerIndex != uint16(i) || got.BdId != 100 || got.LastSeen == 0 {
			t.Fatalf("remote move %d: entry=%+v err=%v", i, got, err)
		}
		var raw FdbEntry
		if err := f.h.objs.FdbMap.Lookup(buildFdbKey(100, f.mac), &raw); err != nil || raw.BdId != 0 {
			t.Fatalf("legacy node must remain ABI-compatible: %+v, %v", raw, err)
		}
		entries, err := f.h.mapOps.ListFdb()
		if err != nil || entries[*buildFdbKey(100, f.mac)].BdId != 100 {
			t.Fatalf("ListFdb must derive BD from key: %v", err)
		}
		// Local observations retain the existing remote identity.
		f.h.run(f.local)
		ret, out := f.h.run(probe)
		if ret != XDP_DROP && ret != XDP_REDIRECT {
			t.Fatalf("remote forwarding missed: action=%d", ret)
		}
		if got := outerIPv6DA(t, out); got != f.peerSID[i] {
			t.Fatalf("wrong BD/peer after move: got=%v want=%v", got, f.peerSID[i])
		}
	}
	// Local-to-local learning still updates the output interface.
	if err := f.h.mapOps.CreateFdb(100, f.mac, &FdbEntry{Oif: 2}); err != nil {
		t.Fatal(err)
	}
	f.h.run(f.local)
	got, err := f.h.mapOps.GetFdb(100, f.mac)
	if err != nil || got.Oif != 1 || got.IsRemote != 0 || got.PeerIndex != 0 || got.LastSeen == 0 {
		t.Fatalf("local move: %+v, %v", got, err)
	}
	// Legacy synthetic peers predate is_static. Neither learner may make
	// them ageable or replace their forwarding identity/ESI.
	alias := FdbEntry{IsRemote: 1, PeerIndex: uint16(EsPeerIndexBase), BdId: 100, Esi: [ESILen]byte{1, 2, 3}}
	if err := f.h.mapOps.CreateFdb(100, f.mac, &alias); err != nil {
		t.Fatal(err)
	}
	f.h.run(f.local)
	f.h.run(f.remote[0])
	got, err = f.h.mapOps.GetFdb(100, f.mac)
	if err != nil || *got != alias {
		t.Fatalf("learner changed legacy synthetic control: %+v, %v", got, err)
	}
}

func TestXDPProgFDBConcurrentControlPublication(t *testing.T) {
	f := newFdbAtomicFixture(t)
	key := buildFdbKey(100, f.mac)
	if err := f.h.mapOps.CreateFdb(100, f.mac, &FdbEntry{Oif: 2}); err != nil {
		t.Fatal(err)
	}
	control := FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: uint16(EsPeerIndexBase), BdId: 100, Esi: [ESILen]byte{1, 2, 3}}
	start := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	launch := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- fn()
		}()
	}
	for _, packets := range [][][]byte{{f.local}, {f.remote[0], f.remote[1]}} {
		launch(func() error {
			for i := range 1000 {
				opts := ebpf.RunOptions{Data: packets[i%len(packets)], DataOut: make([]byte, 1500), Repeat: 1}
				if _, err := f.h.objs.VinberoMain.Run(&opts); err != nil {
					return err
				}
			}
			return nil
		})
	}
	launch(func() error {
		for range 500 {
			if err := f.h.mapOps.CreateFdb(100, f.mac, &control); err != nil {
				return err
			}
			got, err := f.h.mapOps.GetFdb(100, f.mac)
			if err != nil || *got != control {
				return fmt.Errorf("learner changed published control entry: %+v, %v", got, err)
			}
			if err := f.h.mapOps.CreateFdb(100, f.mac, &FdbEntry{Oif: 2}); err != nil {
				return err
			}
		}
		return nil
	})
	launch(func() error {
		check := func(entry *FdbEntry) error {
			local := entry.IsStatic == 0 && entry.IsRemote == 0 && (entry.Oif == 1 || entry.Oif == 2) && entry.PeerIndex == 0
			remote := entry.IsStatic == 0 && entry.IsRemote == 1 && entry.Oif == 0 && entry.PeerIndex < 2 && entry.BdId == 100
			static := entry.IsStatic == 1 && entry.IsRemote == 1 && entry.Oif == 0 && entry.PeerIndex == control.PeerIndex && entry.BdId == 100
			if !local && !remote && !static {
				return fmt.Errorf("mixed forwarding snapshot: %+v", entry)
			}
			return nil
		}
		for range 1000 {
			got, err := f.h.mapOps.GetFdb(100, f.mac)
			if err != nil {
				return err
			}
			if err := check(got); err != nil {
				return err
			}
			entries, err := f.h.mapOps.ListFdb()
			if err != nil {
				return err
			}
			if err := check(entries[*key]); err != nil {
				return err
			}
		}
		return nil
	})
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}
