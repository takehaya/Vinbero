package apply

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A session that can no longer resolve a SID is removed from the VRF it is
// in even when its move to another VRF fails: the move waits for a SID, the
// removal does not.
func TestMUPUnresolvableSessionRemovedWhenMoveFails(t *testing.T) {
	const endpoint = "192.0.2.100"
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	bindMUP(t, vm, "vpn-a", testRTDirect)
	bindMUP(t, vm, "vpn-b", "100:9")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::"))
	idA, _ := vm.VRF().IDForName("vpn-a")
	if _, ok := fh.mupUplink[mupUplinkKey{idA, endpoint, 0x100, 32}]; !ok {
		t.Fatal("uplink not installed in vpn-a")
	}

	fh.createErr = errors.New("map full")
	moved := mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "")
	moved.MUP.RTs = []string{"100:9"}
	a.Apply(moved)
	if len(fh.mupUplink) != 0 {
		t.Errorf("uplinks %v left, want the unresolvable session removed", fh.mupUplink)
	}
	if fh.v4created[fakeHeadendKey(idA, endpoint+"/32")] != nil {
		t.Error("vpn-a's gate left behind")
	}
}
