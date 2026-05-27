package apply

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// evpnApplier builds an Applier with one VRF binding mapping import RT
// "65000:100" to bridge domain 100, the setup an RT2 needs to install.
func evpnApplier(t *testing.T) (*Applier, *fakeHeadend) {
	t.Helper()
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{VRFName: "evi-100", ImportRTs: []string{"65000:100"}, BDID: 100}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	return a, fh
}

func rt2(mac, sid string) *bgp.EVPNRoute {
	return &bgp.EVPNRoute{
		Type:    bgp.EVPNRouteTypeMACIP,
		RD:      "65000:100",
		RTs:     []string{"65000:100"},
		MAC:     mac,
		SRv6SID: sid,
	}
}

func TestApplier_EVPNRT2Install(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})

	fdb, ok := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	if !ok {
		t.Fatalf("CreateFdb not called; fdb=%v", fh.fdb)
	}
	if fdb.IsRemote != 1 || fdb.BdId != 100 {
		t.Errorf("fdb entry = %+v, want IsRemote=1 BdId=100", fdb)
	}
	peer, ok := fh.bdPeers[bdPeerKey{100, fdb.PeerIndex}]
	if !ok {
		t.Fatalf("bd_peer at index %d not created; peers=%v", fdb.PeerIndex, fh.bdPeers)
	}
	if peer.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2) {
		t.Errorf("bd_peer mode = %d, want H.Encaps.L2", peer.Mode)
	}
	if peer.SrcAddr != netip.MustParseAddr("fd00:1:1::").As16() {
		t.Errorf("bd_peer SrcAddr = %v, want local encap source fd00:1:1::", peer.SrcAddr)
	}
	if peer.Segments[0] != netip.MustParseAddr("fd00:2:2:d2::").As16() {
		t.Errorf("bd_peer Segments[0] = %v, want remote DT2U SID", peer.Segments[0])
	}
}

// Two MACs from the same remote PE share a single bd_peer; withdrawing one
// keeps the peer until the last MAC is withdrawn.
func TestApplier_EVPNRT2PeerSharedAndRefcounted(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:02", "fd00:2:2:d2::")})

	if len(fh.bdPeers) != 1 {
		t.Fatalf("two MACs from one PE must share one bd_peer; got %d", len(fh.bdPeers))
	}
	if len(fh.fdb) != 2 {
		t.Fatalf("want 2 FDB entries, got %d", len(fh.fdb))
	}

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 {
		t.Errorf("bd_peer removed while a MAC still references it; peers=%v", fh.bdPeers)
	}
	if len(fh.fdb) != 1 {
		t.Errorf("want 1 FDB entry after one withdraw, got %d", len(fh.fdb))
	}

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:02", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 0 {
		t.Errorf("bd_peer not freed after last MAC withdrawn; peers=%v", fh.bdPeers)
	}
	if len(fh.fdb) != 0 {
		t.Errorf("FDB not empty after both withdrawn; fdb=%v", fh.fdb)
	}
}

// A re-advertise of the same NLRI must not leak the bd_peer: the peer is
// refcounted, so a single withdraw after any number of re-advertises must
// free it (a missing "already installed" guard would bump refs unmatched).
func TestApplier_EVPNRT2ReadvertiseNoLeak(t *testing.T) {
	a, fh := evpnApplier(t)
	for i := 0; i < 3; i++ {
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	}
	if len(fh.bdPeers) != 1 || len(fh.fdb) != 1 {
		t.Fatalf("re-advertise must be idempotent; peers=%d fdb=%d", len(fh.bdPeers), len(fh.fdb))
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 0 || len(fh.fdb) != 0 {
		t.Errorf("one withdraw must free the peer after re-advertises; peers=%v fdb=%v", fh.bdPeers, fh.fdb)
	}
}

// A MAC moving to a different remote PE (new End.DT2U SID) re-points the FDB
// and releases the old peer's reference.
func TestApplier_EVPNRT2MacMove(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:3:3:d2::")})

	if len(fh.bdPeers) != 1 {
		t.Fatalf("MAC move must release the old bd_peer; peers=%v", fh.bdPeers)
	}
	if len(fh.fdb) != 1 {
		t.Fatalf("MAC move must keep one FDB entry; fdb=%v", fh.fdb)
	}
	fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}]
	peer := fh.bdPeers[bdPeerKey{100, fdb.PeerIndex}]
	if peer.Segments[0] != netip.MustParseAddr("fd00:3:3:d2::").As16() {
		t.Errorf("FDB must point at the new PE's SID; got Segments[0]=%v", peer.Segments[0])
	}
}

func TestApplier_EVPNRT2NoBindingDropped(t *testing.T) {
	fh := newFakeHeadend()
	// No EVPN binding registered -> no bridge domain to install into.
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("RT2 with no bridge-domain binding must not write; fdb=%v peers=%v", fh.fdb, fh.bdPeers)
	}
}

func TestApplier_EVPNRT2NoSIDSkipped(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "")})
	if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("RT2 with no SRv6 SID must not write; fdb=%v peers=%v", fh.fdb, fh.bdPeers)
	}
}

// An unspecified (::) or IPv4-mapped SID is not a usable SRv6 SID and must be
// rejected rather than installed as a black-hole bd_peer.
func TestApplier_EVPNRT2InvalidSIDSkipped(t *testing.T) {
	for _, sid := range []string{"::", "::ffff:10.0.0.1"} {
		a, fh := evpnApplier(t)
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", sid)})
		if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
			t.Errorf("SID %q must be rejected; fdb=%v peers=%v", sid, fh.fdb, fh.bdPeers)
		}
	}
}

// Two PEs (distinct End.DT2U SIDs) in one BD must get distinct bd_peer indices.
func TestApplier_EVPNRT2TwoPEsDistinctIndex(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:02", "fd00:3:3:d2::")})
	if len(fh.bdPeers) != 2 {
		t.Fatalf("two PEs must get two bd_peers; got %d", len(fh.bdPeers))
	}
	i1 := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}].PeerIndex
	i2 := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:02"}].PeerIndex
	if i1 == i2 {
		t.Errorf("distinct PEs must get distinct indices; both = %d", i1)
	}
}

// When the bridge domain is full (MaxBumNexthops peers), a further new PE is
// rejected without writing an FDB entry.
func TestApplier_EVPNRT2BdFull(t *testing.T) {
	a, fh := evpnApplier(t)
	for i := 0; i < bpf.MaxBumNexthops; i++ {
		mac := fmt.Sprintf("aa:bb:cc:00:00:%02x", i)
		sid := fmt.Sprintf("fd00:2:2:%x::", i)
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, sid)})
	}
	if len(fh.bdPeers) != bpf.MaxBumNexthops {
		t.Fatalf("want %d peers, got %d", bpf.MaxBumNexthops, len(fh.bdPeers))
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:ff", "fd00:2:2:ffff::")})
	if len(fh.bdPeers) != bpf.MaxBumNexthops {
		t.Errorf("BD-full must reject a further peer; got %d", len(fh.bdPeers))
	}
	if _, ok := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:ff"}]; ok {
		t.Error("BD-full must not write an FDB entry for the rejected MAC")
	}
}

// A CreateBdPeer failure must not leak the peer slot: a later successful
// install gets the slot, and no orphan bd_peer/FDB is left behind.
func TestApplier_EVPNRT2BdPeerErrorRollback(t *testing.T) {
	a, fh := evpnApplier(t)
	fh.bdPeerErr = errors.New("boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 0 || len(fh.fdb) != 0 {
		t.Fatalf("failed CreateBdPeer must leave no state; peers=%v fdb=%v", fh.bdPeers, fh.fdb)
	}
	fh.bdPeerErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 || len(fh.fdb) != 1 {
		t.Errorf("retry after error must install cleanly; peers=%v fdb=%v", fh.bdPeers, fh.fdb)
	}
}

// A CreateFdb failure must roll back the bd_peer it just created (no orphan).
func TestApplier_EVPNRT2FdbErrorRollback(t *testing.T) {
	a, fh := evpnApplier(t)
	fh.fdbErr = errors.New("boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 0 || len(fh.fdb) != 0 {
		t.Errorf("failed CreateFdb must roll back the bd_peer; peers=%v fdb=%v", fh.bdPeers, fh.fdb)
	}
}

// Withdrawing an unknown MAC (no prior install) is a no-op.
func TestApplier_EVPNRT2UnknownWithdrawNoop(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:09", "fd00:2:2:d2::")})
	if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("unknown withdraw must be a no-op; fdb=%v peers=%v", fh.fdb, fh.bdPeers)
	}
}

// A DeleteFdb failure on withdraw must keep the reverse index so a retry can
// still remove the MAC; dropping it would orphan the FDB entry and its peer.
func TestApplier_EVPNRT2WithdrawFdbDeleteErrorKeepsLedger(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})

	fh.fdbDelErr = errors.New("boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(a.evpn.fdb) != 1 || len(fh.bdPeers) != 1 {
		t.Fatalf("failed DeleteFdb must keep ledger and peer; ledger=%d peers=%v", len(a.evpn.fdb), fh.bdPeers)
	}

	// A retry once the map op recovers cleans everything up.
	fh.fdbDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	if len(a.evpn.fdb) != 0 || len(fh.bdPeers) != 0 || len(fh.fdb) != 0 {
		t.Errorf("retry withdraw must clear all state; ledger=%d peers=%v fdb=%v", len(a.evpn.fdb), fh.bdPeers, fh.fdb)
	}
}

// A DeleteBdPeer failure on the last withdraw leaves the bd_peer in the map,
// so the index must be re-pinned: a re-learn of the same PE reuses that
// surviving entry instead of allocating a duplicate and leaking the slot.
func TestApplier_EVPNRT2WithdrawBdPeerDeleteErrorRepinsIndex(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	peer := a.evpn.peers[evpnPeerKey{100, "fd00:2:2:d2::"}]
	if peer == nil {
		t.Fatal("peer state missing after install")
	}
	idx := peer.index

	fh.bdPeerDelErr = errors.New("boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	repinned := a.evpn.peers[evpnPeerKey{100, "fd00:2:2:d2::"}]
	if repinned == nil || repinned.index != idx || repinned.refs != 0 {
		t.Fatalf("failed DeleteBdPeer must re-pin index %d at refs 0; got %+v", idx, repinned)
	}

	// Re-learn the PE: it must reuse the surviving index, not allocate anew.
	fh.bdPeerDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:02", "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 {
		t.Errorf("re-learn must reuse the surviving bd_peer; peers=%v", fh.bdPeers)
	}
	if got := a.evpn.peers[evpnPeerKey{100, "fd00:2:2:d2::"}]; got == nil || got.index != idx {
		t.Errorf("re-learn must reuse index %d; got %+v", idx, got)
	}
}

// rt3 builds an RT3 Inclusive Multicast route for bd 100 with a given
// End.DT2M flood SID.
func rt3(sid string) *bgp.EVPNRoute {
	return &bgp.EVPNRoute{
		Type:    bgp.EVPNRouteTypeInclusiveMulticast,
		RD:      "65000:100",
		RTs:     []string{"65000:100"},
		SRv6SID: sid,
	}
}

// An RT3 installs a BUM flood bd_peer (End.DT2M) without touching the FDB.
func TestApplier_EVPNRT3Install(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})

	if len(fh.bdPeers) != 1 {
		t.Fatalf("RT3 must install one BUM bd_peer; got %d", len(fh.bdPeers))
	}
	if len(fh.fdb) != 0 {
		t.Errorf("RT3 must not write FDB entries; fdb=%v", fh.fdb)
	}
	for _, p := range fh.bdPeers {
		if p.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2) {
			t.Errorf("RT3 bd_peer mode = %d, want H.Encaps.L2", p.Mode)
		}
		if p.Segments[0] != netip.MustParseAddr("fd00:2:2:24::").As16() {
			t.Errorf("RT3 bd_peer Segments[0] = %v, want End.DT2M SID", p.Segments[0])
		}
	}
}

// Re-advertising the same RT3 is idempotent; a withdraw removes the peer.
func TestApplier_EVPNRT3ReadvertiseAndWithdraw(t *testing.T) {
	a, fh := evpnApplier(t)
	for i := 0; i < 3; i++ {
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
	}
	if len(fh.bdPeers) != 1 {
		t.Fatalf("re-advertise must be idempotent; peers=%d", len(fh.bdPeers))
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(fh.bdPeers) != 0 {
		t.Errorf("withdraw must remove the BUM bd_peer; peers=%v", fh.bdPeers)
	}
}

// RT2 (unicast, End.DT2U) and RT3 (BUM, End.DT2M) for the same BD coexist as
// two distinct bd_peers; the data-plane flood loop sweeps both (Step 3 will
// add a flood-exclude flag to drop the unicast peer from the flood).
func TestApplier_EVPNRT2AndRT3Coexist(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
	if len(fh.bdPeers) != 2 {
		t.Fatalf("RT2 + RT3 must install two distinct bd_peers; got %d", len(fh.bdPeers))
	}
}

// An RT3 with an unusable SID, or whose RTs match no binding, installs nothing.
func TestApplier_EVPNRT3InvalidSIDOrNoBindingSkipped(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("::")})
	if len(fh.bdPeers) != 0 {
		t.Errorf("unspecified SID must be skipped; peers=%v", fh.bdPeers)
	}
	r := rt3("fd00:2:2:24::")
	r.RTs = []string{"65000:999"}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r})
	if len(fh.bdPeers) != 0 {
		t.Errorf("unmatched RT must be dropped; peers=%v", fh.bdPeers)
	}
}

// A DeleteBdPeer failure on RT3 withdraw must keep the reverse index so a retry
// can still remove the flood peer (mirrors the RT2 withdraw error path).
func TestApplier_EVPNRT3WithdrawDeleteErrorKeepsLedger(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})

	fh.bdPeerDelErr = errors.New("boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(a.evpn.mcast) != 1 || len(fh.bdPeers) != 1 {
		t.Fatalf("failed DeleteBdPeer must keep ledger and peer; mcast=%d peers=%v", len(a.evpn.mcast), fh.bdPeers)
	}

	fh.bdPeerDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(a.evpn.mcast) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("retry withdraw must clear all state; mcast=%d peers=%v", len(a.evpn.mcast), fh.bdPeers)
	}
}

// An RT3 whose SID moves (same RD/EthernetTag, new End.DT2M SID) tears the old
// flood peer down and installs the new one, leaving exactly one bd_peer.
func TestApplier_EVPNRT3SidMove(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:3:3:24::")})
	if len(fh.bdPeers) != 1 {
		t.Fatalf("SID move must leave exactly one BUM bd_peer; got %d", len(fh.bdPeers))
	}
	for _, p := range fh.bdPeers {
		if p.Segments[0] != netip.MustParseAddr("fd00:3:3:24::").As16() {
			t.Errorf("BUM bd_peer Segments[0] = %v, want the new End.DT2M SID", p.Segments[0])
		}
	}
}

// When the bridge domain's bd_peer slots are exhausted, an RT3 installs nothing
// and records no mcast ledger entry.
func TestApplier_EVPNRT3BdFull(t *testing.T) {
	a, fh := evpnApplier(t)
	for i := uint16(0); i < bpf.MaxBumNexthops; i++ {
		fh.bdPeers[bdPeerKey{100, i}] = &bpf.HeadendEntry{}
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
	if _, ok := a.evpn.mcast[evpnMcastKey{rd: "65000:100", etag: 0}]; ok {
		t.Error("BD-full must not record an RT3 mcast ledger entry")
	}
}

var testESI = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

// seedLocalEsi marks an ESI as locally attached in the fake esi_map so DF
// election runs for it (the operator-declared `vbctl es create --local-attached`).
func seedLocalEsi(fh *fakeHeadend, esi [10]byte, localPE string) {
	fh.esis[esi] = &bpf.EsiEntry{
		LocalAttached:  1,
		LocalPeSrcAddr: netip.MustParseAddr(localPE).As16(),
	}
}

func rt4(esi [10]byte, pe string) *bgp.EVPNRoute {
	return &bgp.EVPNRoute{
		Type:       bgp.EVPNRouteTypeEthernetSegment,
		RD:         "65000:1",
		ESI:        esi,
		ESImportRT: "aa:bb:cc:dd:ee:ff",
		NextHop:    pe,
	}
}

func dfAddr(fh *fakeHeadend, esi [10]byte) string {
	return netip.AddrFrom16(fh.esis[esi].DfPeSrcAddr).Unmap().String()
}

// DF election picks the numerically lowest PE among {local, RT4 members} for
// ELAN (ETag 0). A higher-addressed remote keeps local as DF; a lower-addressed
// remote wins.
func TestApplier_EVPNRT4DFElection(t *testing.T) {
	a, fh := evpnApplier(t)
	seedLocalEsi(fh, testESI, "fd00:1:1::")

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "fd00:2:2::")})
	if got := dfAddr(fh, testESI); got != "fd00:1:1::" {
		t.Errorf("DF = %s, want local fd00:1:1:: (lowest of {local, fd00:2:2::})", got)
	}

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "fc00::1")})
	if got := dfAddr(fh, testESI); got != "fc00::1" {
		t.Errorf("DF = %s, want fc00::1 (now the lowest)", got)
	}
}

// Withdrawing a member re-elects the DF over the remaining candidates.
func TestApplier_EVPNRT4WithdrawReelects(t *testing.T) {
	a, fh := evpnApplier(t)
	seedLocalEsi(fh, testESI, "fd00:1:1::")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "fc00::1")})
	if got := dfAddr(fh, testESI); got != "fc00::1" {
		t.Fatalf("precondition: DF should be fc00::1, got %s", got)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt4(testESI, "fc00::1")})
	if got := dfAddr(fh, testESI); got != "fd00:1:1::" {
		t.Errorf("after withdraw DF = %s, want local fd00:1:1:: (only candidate left)", got)
	}
}

// An RT4 for an ESI this PE does not locally attach records membership only and
// never writes esi_map -- a crafted RT4 cannot mint a phantom segment.
func TestApplier_EVPNRT4NotLocallyAttachedNoWrite(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "fc00::1")})
	if _, ok := fh.esis[testESI]; ok {
		t.Error("RT4 must not create an esi_map entry for an unattached ESI")
	}
	if _, ok := a.evpn.esMembers[testESI]; !ok {
		t.Error("membership should still be recorded when not locally attached")
	}
}

// A crafted RT4 with an IPv4-mapped next hop must not enter DF election (the
// same guard RT2/RT3 apply to SIDs); the local PE stays DF. Without the guard
// ::ffff:0.0.0.1 sorts before fd00:1:1:: and would steal DF.
func TestApplier_EVPNRT4RejectsMappedMemberAddr(t *testing.T) {
	a, fh := evpnApplier(t)
	seedLocalEsi(fh, testESI, "fd00:1:1::")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "::ffff:0.0.0.1")})
	if got := dfAddr(fh, testESI); got != "fd00:1:1::" {
		t.Errorf("IPv4-mapped member must be rejected; DF = %s, want local fd00:1:1::", got)
	}
}

// A locally-attached ES whose local PE source is unspecified must not elect a
// DF -- electing :: would black-hole the segment.
func TestApplier_EVPNRT4ZeroLocalSkipsElection(t *testing.T) {
	a, fh := evpnApplier(t)
	fh.esis[testESI] = &bpf.EsiEntry{LocalAttached: 1} // LocalPeSrcAddr all-zero
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt4(testESI, "fd00:2:2::")})
	var zero [bpf.IPv6AddrLen]byte
	if fh.esis[testESI].DfPeSrcAddr != zero {
		t.Errorf("zero local source must skip election; DF = %v, want unset",
			netip.AddrFrom16(fh.esis[testESI].DfPeSrcAddr))
	}
}
