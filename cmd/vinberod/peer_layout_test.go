package main

import (
	"net"
	"strings"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Pinned maps of a run with the earlier peer index layout (flood slots and
// RT2 peers in [0, 8), ES peers in [8, 40)): the EVPN sweep before attach
// removes what the BGP applier wrote there, the unowned ES leftovers and the
// learned MACs that named a removed peer; the operator's flood peer keeps its
// slot. An ES peer of another ASN left in [8, 32) stops the start, named by
// BD and index, until it is removed. Needs root (it loads the BPF
// collection).
func TestBootMigratesAnEarlierPeerLayout(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	m := bpf.NewMapOperations(objs)

	const asn = 65100
	entry := func(floodExclude uint8, group uint32) *bpf.HeadendEntry {
		segs, n, _ := bpf.ParseSegments([]string{"fd00:2::1"})
		return &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n, Segments: segs, BdId: 100, FloodExclude: floodExclude, GroupId: group}
	}
	// putPeer writes a peer the way the earlier layout's version did, past
	// this version's index check.
	putPeer := func(bd, index uint16, e *bpf.HeadendEntry, owner bpf.OwnerTag) {
		t.Helper()
		k := bpf.BdPeerKey{BdId: bd, Index: index}
		if err := objs.BdPeerMap.Put(&k, e); err != nil {
			t.Fatal(err)
		}
		if owner != "" {
			var v [64]byte
			copy(v[:63], owner)
			if err := objs.BdPeerOwnerMap.Put(&k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	mac := func(b byte) net.HardwareAddr { return net.HardwareAddr{0x02, 0, 0, 0, 0, b} }
	// putFdb writes an entry with no owner record, as the data plane's
	// learning and the versions before owner records did.
	putFdb := func(bd uint16, b byte, e bpf.FdbEntry) {
		t.Helper()
		e.BdId = bd
		k := bpf.FdbKey{BdId: bd}
		copy(k.Mac[:], mac(b))
		if err := objs.FdbMap.Put(&k, &e); err != nil {
			t.Fatal(err)
		}
	}
	mine, other := bpf.OwnerBGPEVPN(asn), bpf.OwnerBGPEVPN(65001)

	putPeer(100, 0, entry(0, 0), bpf.OwnerRPC) // the operator's flood peer
	putPeer(100, 1, entry(0, 0), mine)         // RT3
	putPeer(100, 2, entry(1, 0), mine)         // RT2, in a flood slot
	putPeer(100, 9, entry(1, 77), mine)        // ES peer
	putPeer(100, 12, entry(1, 78), "")         // ES peer of a version before owner records
	if err := m.CreateFdbOwned(100, mac(1), &bpf.FdbEntry{IsRemote: 1, PeerIndex: 2, BdId: 100}, mine); err != nil {
		t.Fatal(err)
	}
	putFdb(100, 2, bpf.FdbEntry{IsRemote: 1, PeerIndex: 12})             // pointer to the unowned ES peer
	putFdb(100, 3, bpf.FdbEntry{IsRemote: 1, PeerIndex: 2, LastSeen: 1}) // learned towards the old RT2 peer
	putFdb(100, 4, bpf.FdbEntry{IsRemote: 1, PeerIndex: 0, LastSeen: 1}) // learned towards the operator's peer
	putFdb(100, 5, bpf.FdbEntry{Oif: 7, LastSeen: 1})                    // local
	err = m.CheckBdPeerLayout()
	if err == nil || !strings.Contains(err.Error(), "peer {bd 100, index 9}") || !strings.Contains(err.Error(), "FDB entry {bd 100, 02:00:00:00:00:02} -> peer index 12") {
		t.Errorf("layout check before the sweep = %v, want the earlier layout's peers and pointers named", err)
	}
	if err := purgeBGPEVPN(m, asn, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Fatalf("layout check after the sweep: %v", err)
	}
	peers, err := m.ListBdPeers()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := peers[bpf.BdPeerKey{BdId: 100, Index: 0}]; !ok || len(peers) != 1 {
		t.Errorf("peers after the sweep = %v, want only the operator's at index 0", peers)
	}
	fdbs, err := m.ListFdb()
	if err != nil {
		t.Fatal(err)
	}
	for b, want := range map[byte]bool{1: false, 2: false, 3: false, 4: true, 5: true} {
		k := bpf.FdbKey{BdId: 100}
		copy(k.Mac[:], mac(b))
		if _, got := fdbs[k]; got != want {
			t.Errorf("FDB %s present = %v, want %v", mac(b), got, want)
		}
	}

	// Another ASN's ES peer is not this applier's to remove.
	putPeer(300, 10, entry(1, 79), other)
	if err := purgeBGPEVPN(m, asn, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	err = m.CheckBdPeerLayout()
	if err == nil || !strings.Contains(err.Error(), "peer {bd 300, index 10} ("+string(other)+")") {
		t.Fatalf("layout check = %v, want a refusal naming bd 300 index 10", err)
	}
	if err := purgeBGPEVPN(m, 65001, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Errorf("layout check after that ASN's sweep: %v", err)
	}
}
