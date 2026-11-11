package apply

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A T2ST move that fails when the binding changes is finished by the
// tracked pass once the writes succeed again: the session does not stay in
// the VRF it no longer belongs to.
func TestMUPFailedMoveRetriedByTrackedPass(t *testing.T) {
	const endpoint = "192.0.2.100"
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindMUP(t, vm, "vpn-a", testRTDirect)
	bindMUP(t, vm, "vpn-b", "100:9")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::"))
	idA, _ := vm.VRF().IDForName("vpn-a")
	idB, _ := vm.VRF().IDForName("vpn-b")

	bindMUP(t, vm, "vpn-a", "100:9")
	bindMUP(t, vm, "vpn-b", testRTDirect)
	fh.createErr = errors.New("map full")
	a.ReconcileMUPUplinkInstances()
	if _, ok := fh.mupUplink[mupUplinkKey{idA, endpoint, 0x100, 32}]; !ok {
		t.Fatal("a failed move must leave the session where it was")
	}
	fh.createErr = nil
	if err := a.ReconcileTracked(); err != nil {
		t.Fatal(err)
	}
	if _, ok := fh.mupUplink[mupUplinkKey{idB, endpoint, 0x100, 32}]; !ok {
		t.Error("the tracked pass did not finish the move to vpn-b")
	}
	if fh.v4created[fakeHeadendKey(idA, endpoint+"/32")] != nil || fh.v4created[fakeHeadendKey(idB, endpoint+"/32")] == nil {
		t.Error("the gate did not follow the session to vpn-b")
	}
}
