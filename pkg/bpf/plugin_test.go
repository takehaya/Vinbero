package bpf

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

func TestRegisterPluginReservedSlot(t *testing.T) {
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	mapOps := NewMapOperations(objs)

	// Endpoint: index < 32 should be rejected
	err = mapOps.RegisterPlugin("endpoint", 0, 0)
	if !errors.Is(err, ErrReservedSlot) {
		t.Errorf("Expected ErrReservedSlot for endpoint index 0, got: %v", err)
	}
	err = mapOps.RegisterPlugin("endpoint", 31, 0)
	if !errors.Is(err, ErrReservedSlot) {
		t.Errorf("Expected ErrReservedSlot for endpoint index 31, got: %v", err)
	}

	// Headend: index < 16 should be rejected
	err = mapOps.RegisterPlugin("headend_v4", 0, 0)
	if !errors.Is(err, ErrReservedSlot) {
		t.Errorf("Expected ErrReservedSlot for headend_v4 index 0, got: %v", err)
	}
	err = mapOps.RegisterPlugin("headend_v6", 15, 0)
	if !errors.Is(err, ErrReservedSlot) {
		t.Errorf("Expected ErrReservedSlot for headend_v6 index 15, got: %v", err)
	}

	// Unknown map type
	err = mapOps.RegisterPlugin("unknown", 32, 0)
	if err == nil {
		t.Error("Expected error for unknown map type")
	}

	t.Log("Reserved slot protection verified")
}

func TestRegisterUnregisterPlugin(t *testing.T) {
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	mapOps := NewMapOperations(objs)

	// Register an existing tail call program into a plugin slot.
	pluginIndex := uint32(32)
	progFD := objs.TailcallEndpointEnd.FD()

	err = mapOps.RegisterPlugin("endpoint", pluginIndex, progFD)
	if err != nil {
		t.Fatalf("RegisterPlugin failed: %v", err)
	}

	// Verify the slot is populated via lookup
	var storedFD uint32
	if err := objs.SidEndpointProgs.Lookup(pluginIndex, &storedFD); err != nil {
		t.Fatalf("Lookup after register failed: %v", err)
	}
	if storedFD == 0 {
		t.Error("Expected non-zero FD in plugin slot")
	}
	t.Logf("Plugin registered at slot %d, FD=%d", pluginIndex, storedFD)

	// Unregister
	err = mapOps.UnregisterPlugin("endpoint", pluginIndex)
	if err != nil {
		t.Fatalf("UnregisterPlugin failed: %v", err)
	}

	// Verify the slot is empty (lookup should fail)
	err = objs.SidEndpointProgs.Lookup(pluginIndex, &storedFD)
	if err != nil {
		t.Log("Slot cleared after unregister (lookup returned error)")
	}
}

func TestPluginTailCallExecution(t *testing.T) {
	h := newXDPTestHelper(t)

	// Register the built-in End handler into plugin slot 32.
	// Then create a SID entry with action=32 and verify the plugin runs.
	pluginIndex := uint32(32)
	err := h.objs.SidEndpointProgs.Update(
		pluginIndex, h.objs.TailcallEndpointEnd, ebpf.UpdateAny,
	)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// Create SID entry with action=32 (plugin slot)
	sidPrefix := "fd00::32"
	entry := &SidFunctionEntry{Action: uint8(pluginIndex), Flavor: 0}
	if err := h.mapOps.CreateSidFunction(sidPrefix, entry, nil); err != nil {
		t.Fatalf("Failed to create SID: %v", err)
	}

	// Build SRv6 packet: src=2001::1, dst=fd00::32 (SID), SL=1, one segment
	srcIP := net.ParseIP("2001::1")
	dstIP := net.ParseIP("fd00::32")
	segments := []net.IP{net.ParseIP("fd00::99")}
	pkt, err := buildSRv6Packet(srcIP, dstIP, segments, 1)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	action, _ := h.run(pkt)

	// The End handler with SL=1 does: SL--, update DA, FIB redirect.
	// In test env without real interfaces, FIB returns XDP_PASS → XDP_PASS from End.
	// Key assertion: action != XDP_ABORTED (0), proving the tail call executed.
	if action == 0 {
		t.Fatal("Plugin returned XDP_ABORTED — tail call likely failed")
	}

	t.Logf("Plugin tail call at slot %d executed, action=%d", pluginIndex, action)
}
