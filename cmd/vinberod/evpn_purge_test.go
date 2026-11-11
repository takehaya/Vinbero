package main

import (
	"net"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// The EVPN state an earlier run's BGP applier left in the pinned maps goes
// before the data plane is attached: its remote MACs and peers, and the ES
// range. The operator's, a plugin's and another ASN's entries stay, and so
// does an FDB entry an operator pointed at a remaining peer. Needs root (it
// loads the BPF collection).
func TestPurgeBGPEVPNRemovesAnEarlierRunsEntries(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	m := bpf.NewMapOperations(objs)

	const asn = 65100
	peer := func() *bpf.HeadendEntry {
		segs, n, _ := bpf.ParseSegments([]string{"fd00:2::1"})
		return &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n, Segments: segs, BdId: 100}
	}
	mac := func(b byte) net.HardwareAddr { return net.HardwareAddr{0x02, 0, 0, 0, 0, b} }
	remote := func(bd, idx uint16) *bpf.FdbEntry { return &bpf.FdbEntry{IsRemote: 1, PeerIndex: idx, BdId: bd} }
	var noESI [bpf.ESILen]byte
	var noSrc [bpf.IPv6AddrLen]byte
	mine, other := bpf.OwnerBGPEVPN(asn), bpf.OwnerBGPEVPN(65001)
	plugin := bpf.OwnerPluginBundle("p")

	// The earlier run's: an RT2 peer and MAC, an ES-range peer and a MAC
	// aliased onto it.
	if err := m.CreateBdPeerOwned(100, 2, peer(), noESI, noSrc, false, mine); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdbOwned(100, mac(1), remote(100, 2), mine); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateBdPeerOwned(100, bpf.EsPeerIndexBase, peer(), noESI, noSrc, false, mine); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdbOwned(100, mac(2), remote(100, bpf.EsPeerIndexBase), mine); err != nil {
		t.Fatal(err)
	}
	// Everyone else's.
	if err := m.CreateBdPeer(100, 0, peer(), noESI, noSrc, true); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdb(100, mac(3), remote(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateBdPeerOwned(200, 1, peer(), noESI, noSrc, false, plugin); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdbOwned(200, mac(4), remote(200, 1), plugin); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateBdPeerOwned(300, 1, peer(), noESI, noSrc, false, other); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateFdbOwned(300, mac(5), remote(300, 1), other); err != nil {
		t.Fatal(err)
	}

	if err := purgeBGPEVPN(m, asn, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	fdbs, err := m.ListFdbOwners()
	if err != nil {
		t.Fatal(err)
	}
	wantFdb := map[bpf.FdbKey]bpf.OwnerTag{}
	for bd, e := range map[uint16]struct {
		b byte
		o bpf.OwnerTag
	}{100: {3, bpf.OwnerRPC}, 200: {4, plugin}, 300: {5, other}} {
		k := bpf.FdbKey{BdId: bd}
		copy(k.Mac[:], mac(e.b))
		wantFdb[k] = e.o
	}
	if len(fdbs) != len(wantFdb) {
		t.Errorf("FDB owners left = %v, want %v", fdbs, wantFdb)
	}
	for k, o := range wantFdb {
		if fdbs[k] != o {
			t.Errorf("FDB %v (%s) was removed", k, o)
		}
	}
	peers, err := m.ListBdPeers()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []bpf.BdPeerKey{{BdId: 100, Index: 2}, {BdId: 100, Index: bpf.EsPeerIndexBase}} {
		if _, ok := peers[k]; ok {
			t.Errorf("the earlier run's peer %v stays", k)
		}
	}
	for _, k := range []bpf.BdPeerKey{{BdId: 100, Index: 0}, {BdId: 200, Index: 1}, {BdId: 300, Index: 1}} {
		if _, ok := peers[k]; !ok {
			t.Errorf("peer %v of another owner was removed", k)
		}
	}
}
