package apply

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A path whose removal failed stays recorded in its VRF so the removal is
// retried, and the record goes once the tracked pass retires the
// destination: failed withdraws must not leave records behind for routes
// that never come back.
func TestVPNFailedWithdrawRecordDroppedWhenTrackedPassRetires(t *testing.T) {
	fh := &failingVPNRetirement{fakeHeadend: newFakeHeadend()}
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	const prefix = "10.0.1.0/24"
	ev := vpnEvent(prefix, "65000:1", "fd00:1:1:1::", "fd00::1", false)
	placeVPN(a, ev, 7)
	fh.triggerErr = errors.New("trigger delete failed")
	withdraw := vpnEvent(prefix, "65000:1", "", "fd00::1", true)
	withdraw.VPN.NextHop = ""
	a.Apply(withdraw)
	if len(a.vpnGroups.placed) != 1 {
		t.Fatalf("placed = %v, want the failed removal kept for retry", a.vpnGroups.placed)
	}
	fh.triggerErr = nil
	if err := a.ReconcileTracked(); err != nil {
		t.Fatal(err)
	}
	if len(a.vpnGroups.dests) != 0 || len(a.vpnGroups.placed) != 0 || len(a.vpnGroups.stuck) != 0 {
		t.Fatalf("after the retirement: dests %v placed %v stuck %v, want all empty",
			a.vpnGroups.dests, a.vpnGroups.placed, a.vpnGroups.stuck)
	}
	if fh.v4created["vrf 7 "+prefix] != nil {
		t.Fatal("the trigger survived the retirement")
	}
}

// A T1ST entry whose removal failed stays queued for removal even when the
// next install of the same key fails too: only a successful install makes it
// the session's entry again.
func TestMUPT1STStaleKeptUntilReinstallSucceeds(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	const (
		rd = "65100:1"
		ue = "10.1.0.1/32"
	)
	a.Apply(mupT1ST(rd, ue, "172.16.0.1", 256, 9, "fd00:a:0:1::"))
	if fh.v4created[ue] == nil {
		t.Fatal("downlink not installed")
	}
	fh.deleteErr = errors.New("delete failed")
	withdraw := mupT1ST(rd, ue, "172.16.0.1", 256, 9, "")
	withdraw.IsWithdraw = true
	a.Apply(withdraw)
	stale := mupT1STEntry{vrf: 0, prefix: ue, owner: bpf.OwnerBGPMUP(65000, rd)}
	if _, ok := a.mupT1STStale[stale]; !ok {
		t.Fatal("failed removal not queued")
	}
	fh.createErr = errors.New("create failed")
	a.Apply(mupT1ST(rd, ue, "172.16.0.1", 256, 9, "fd00:a:0:1::"))
	a.Apply(withdraw)
	if _, ok := a.mupT1STStale[stale]; !ok {
		t.Fatal("a failed re-install dropped the queued removal")
	}
	fh.deleteErr, fh.createErr = nil, nil
	if err := a.ReconcileTracked(); err != nil {
		t.Fatal(err)
	}
	if fh.v4created[ue] != nil || len(a.mupT1STStale) != 0 {
		t.Fatalf("entry %v stale %v, want the entry removed", fh.v4created[ue], a.mupT1STStale)
	}
}
