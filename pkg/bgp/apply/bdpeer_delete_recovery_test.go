package apply

import (
	"errors"
	"fmt"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// DeleteBdPeer failure recovery must distinguish "delete failed, entry still
// installed" (existed=true with an error: keep the ledger so a retry works)
// from "the slot is already free" (existed=false: drop the ledger; keeping
// it would collide with the next peer the free-index scan hands the slot
// to).

func TestApplier_EVPNRT2DeleteErrorRepinsIndex(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})

	fh.bdPeerDelErr = fmt.Errorf("map is wedged")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2(mac, "fd00:2:2:d2::")})
	// The bd_peer entry survived the failed delete; the re-pinned index must
	// make a re-learn of the same PE reuse it rather than allocate a second.
	if len(fh.bdPeers) != 1 {
		t.Fatalf("bd_peer count after failed delete = %d, want 1", len(fh.bdPeers))
	}
	fh.bdPeerDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 {
		t.Errorf("re-learn after failed delete allocated a duplicate: %d peers", len(fh.bdPeers))
	}
}

func TestApplier_EVPNRT2DeleteMissingKeyDropsLedger(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})

	// The slot is already free (an external flush, a restart): the withdraw's
	// delete reports existed=false and the ledger must NOT re-pin it.
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt2(mac, "fd00:2:2:d2::")})
	if len(a.evpn.peers) != 0 {
		t.Errorf("ledger re-pinned an already-free slot: %v", a.evpn.peers)
	}
	// A fresh learn must allocate cleanly.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 {
		t.Errorf("fresh learn after free-slot withdraw installed %d peers, want 1", len(fh.bdPeers))
	}
}

func TestApplier_EVPNRT3DeleteMissingKeyDropsLedger(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})

	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(a.evpn.mcast) != 0 {
		t.Errorf("mcast ledger kept for an already-free slot: %v", a.evpn.mcast)
	}
	// Without the existed=false handling the ledger would be wedged: every
	// retry keeps failing, and once the slot is reused the retry deletes an
	// unrelated peer. A fresh RT3 must install cleanly instead.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
	if len(fh.bdPeers) != 1 {
		t.Errorf("fresh RT3 after free-slot withdraw installed %d peers, want 1", len(fh.bdPeers))
	}
}

func TestApplier_EVPNRT3DeleteErrorKeepsLedgerForRetry(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})

	fh.bdPeerDelErr = errors.New("map is wedged")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(a.evpn.mcast) != 1 {
		t.Fatalf("mcast ledger dropped despite a failed delete: %v", a.evpn.mcast)
	}
	fh.bdPeerDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, IsWithdraw: true, EVPN: rt3("fd00:2:2:24::")})
	if len(a.evpn.mcast) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("retry did not finish the withdraw: ledger=%v peers=%v", a.evpn.mcast, fh.bdPeers)
	}
}

// When both the FDB install and its bd_peer rollback fail, the peer entry
// is still installed: the ledger must re-pin the index so a later re-learn
// reuses the surviving entry instead of allocating a duplicate slot.
func TestApplier_EVPNRT2FdbRollbackDeleteErrorRepinsIndex(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	fh.fdbErr = errors.New("fdb boom")
	fh.bdPeerDelErr = errors.New("rollback boom")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 {
		t.Fatalf("bd_peer count after failed rollback = %d, want 1 (still installed)", len(fh.bdPeers))
	}

	fh.fdbErr = nil
	fh.bdPeerDelErr = nil
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})
	if len(fh.bdPeers) != 1 || len(fh.fdb) != 1 {
		t.Errorf("re-learn after failed rollback: peers=%d fdb=%d, want 1/1 (reuse, no duplicate)",
			len(fh.bdPeers), len(fh.fdb))
	}
}
