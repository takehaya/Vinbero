package main

import (
	"net"
	"strings"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Pinned maps of a run with the earliest peer index layout (flood slots and
// RT2 peers in [0, 8), ES peers in [8, 40)), whose ES peers now sit in flood
// slots 8 to 31 and in today's ES range: the EVPN sweep before attach
// removes what the BGP applier wrote, the unowned ES leftovers and the FDB
// pointers to them, and the learned MACs that named a removed peer; the
// operator's flood peers keep their slots, slot 8 among them. An ES peer of
// another ASN left in a flood slot stops the start, named by BD and index,
// until it is removed, so no ES peer of that layout is ever served as a
// flood peer. Needs root (it loads the BPF collection).
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
	putPeer(100, 8, entry(1, 76), mine)        // ES peers, in flood slots now
	putPeer(100, 9, entry(1, 77), mine)
	putPeer(100, 12, entry(1, 78), "") // ES peer of a version before owner records
	putPeer(100, 31, entry(1, 79), "")
	putPeer(100, 39, entry(1, 80), "")         // in today's ES range
	putPeer(200, 8, entry(0, 0), bpf.OwnerRPC) // the operator's flood peer in slot 8 (this layout)
	if err := m.CreateFdbOwned(100, mac(1), &bpf.FdbEntry{IsRemote: 1, PeerIndex: 2, BdId: 100}, mine); err != nil {
		t.Fatal(err)
	}
	putFdb(100, 2, bpf.FdbEntry{IsRemote: 1, PeerIndex: 12})             // pointer to an unowned ES peer
	putFdb(100, 3, bpf.FdbEntry{IsRemote: 1, PeerIndex: 2, LastSeen: 1}) // learned towards the old RT2 peer
	putFdb(100, 4, bpf.FdbEntry{IsRemote: 1, PeerIndex: 0, LastSeen: 1}) // learned towards the operator's peer
	putFdb(100, 5, bpf.FdbEntry{Oif: 7, LastSeen: 1})                    // local
	putFdb(100, 6, bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 31})
	putFdb(100, 7, bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 39})
	putFdb(200, 8, bpf.FdbEntry{IsRemote: 1, PeerIndex: 8, LastSeen: 1}) // learned towards the operator's slot 8
	err = m.CheckBdPeerLayout()
	for _, want := range []string{"peer {bd 100, index 8} with ECMP group 76", "peer {bd 100, index 9}", "peer {bd 100, index 12}", "peer {bd 100, index 31} with ECMP group 79 (no owner)"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("layout check before the sweep = %v, want %q named", err, want)
		}
	}
	if err != nil && (strings.Contains(err.Error(), "index 39") || strings.Contains(err.Error(), "bd 200")) {
		t.Errorf("layout check names an ES-range peer or a flood peer: %v", err)
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
	_, op100 := peers[bpf.BdPeerKey{BdId: 100, Index: 0}]
	_, op200 := peers[bpf.BdPeerKey{BdId: 200, Index: 8}]
	if !op100 || !op200 || len(peers) != 2 {
		t.Errorf("peers after the sweep = %v, want only the operator's at bd 100 index 0 and bd 200 index 8", peers)
	}
	fdbs, err := m.ListFdb()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		bd   uint16
		b    byte
		want bool
	}{{100, 1, false}, {100, 2, false}, {100, 3, false}, {100, 4, true}, {100, 5, true}, {100, 6, false}, {100, 7, false}, {200, 8, true}} {
		k := bpf.FdbKey{BdId: c.bd}
		copy(k.Mac[:], mac(c.b))
		if _, got := fdbs[k]; got != c.want {
			t.Errorf("FDB {bd %d, %s} present = %v, want %v", c.bd, mac(c.b), got, c.want)
		}
	}
	// The freed slots take flood peers again, 8 to 31 included.
	if err := m.RecoverBdFloodSlots(); err != nil {
		t.Fatal(err)
	}
	for want := uint16(1); want < bpf.MaxBumNexthops; want++ {
		i, err := m.CreateBdPeerAtFreeIndex(100, entry(0, 0), [bpf.ESILen]byte{}, [bpf.IPv6AddrLen]byte{byte(want)}, true)
		if err != nil || i != want {
			t.Fatalf("flood peer %d: index %d, %v", want, i, err)
		}
	}

	// Another ASN's ES peer is not this applier's to remove.
	putPeer(300, 10, entry(1, 81), other)
	if err := purgeBGPEVPN(m, asn, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	err = m.CheckBdPeerLayout()
	if err == nil || !strings.Contains(err.Error(), "peer {bd 300, index 10} with ECMP group 81 ("+string(other)+")") {
		t.Fatalf("layout check = %v, want a refusal naming bd 300 index 10", err)
	}
	if err := purgeBGPEVPN(m, 65001, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Errorf("layout check after that ASN's sweep: %v", err)
	}
}
