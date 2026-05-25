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
