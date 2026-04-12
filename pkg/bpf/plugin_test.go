package bpf

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPluginOperations(t *testing.T) {
	h := newXDPTestHelper(t)

	t.Run("ReservedSlot", func(t *testing.T) {
		// Endpoint: index < 32 should be rejected
		err := h.mapOps.RegisterPlugin("endpoint", 0, 0)
		if !errors.Is(err, ErrReservedSlot) {
			t.Errorf("Expected ErrReservedSlot for endpoint index 0, got: %v", err)
		}
		err = h.mapOps.RegisterPlugin("endpoint", 31, 0)
		if !errors.Is(err, ErrReservedSlot) {
			t.Errorf("Expected ErrReservedSlot for endpoint index 31, got: %v", err)
		}

		// Headend: index < 16 should be rejected
		err = h.mapOps.RegisterPlugin("headend_v4", 0, 0)
		if !errors.Is(err, ErrReservedSlot) {
			t.Errorf("Expected ErrReservedSlot for headend_v4 index 0, got: %v", err)
		}
		err = h.mapOps.RegisterPlugin("headend_v6", 15, 0)
		if !errors.Is(err, ErrReservedSlot) {
			t.Errorf("Expected ErrReservedSlot for headend_v6 index 15, got: %v", err)
		}

		// Unknown map type
		err = h.mapOps.RegisterPlugin("unknown", 32, 0)
		if err == nil {
			t.Error("Expected error for unknown map type")
		}
	})

	t.Run("RegisterUnregister", func(t *testing.T) {
		pluginIndex := uint32(32)
		progFD := h.objs.TailcallEndpointEnd.FD()

		err := h.mapOps.RegisterPlugin("endpoint", pluginIndex, progFD)
		if err != nil {
			t.Fatalf("RegisterPlugin failed: %v", err)
		}

		var storedFD uint32
		if err := h.objs.SidEndpointProgs.Lookup(pluginIndex, &storedFD); err != nil {
			t.Fatalf("Lookup after register failed: %v", err)
		}
		if storedFD == 0 {
			t.Error("Expected non-zero FD in plugin slot")
		}

		err = h.mapOps.UnregisterPlugin("endpoint", pluginIndex)
		if err != nil {
			t.Fatalf("UnregisterPlugin failed: %v", err)
		}

		err = h.objs.SidEndpointProgs.Lookup(pluginIndex, &storedFD)
		if err != nil {
			t.Log("Slot cleared after unregister")
		}
	})

	t.Run("TailCallExecution", func(t *testing.T) {
		pluginIndex := uint32(32)
		err := h.objs.SidEndpointProgs.Update(
			pluginIndex, h.objs.TailcallEndpointEnd, ebpf.UpdateAny,
		)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		sidPrefix := "fd00::32"
		entry := &SidFunctionEntry{Action: uint8(pluginIndex), Flavor: 0}
		if err := h.mapOps.CreateSidFunction(sidPrefix, entry, nil); err != nil {
			t.Fatalf("Failed to create SID: %v", err)
		}

		srcIP := net.ParseIP("2001::1")
		dstIP := net.ParseIP("fd00::32")
		segments := []net.IP{net.ParseIP("fd00::99")}
		pkt, err := buildSRv6Packet(srcIP, dstIP, segments, 1)
		if err != nil {
			t.Fatalf("Failed to build packet: %v", err)
		}

		action, _ := h.run(pkt)

		if action == 0 {
			t.Fatal("Plugin returned XDP_ABORTED — tail call likely failed")
		}
		t.Logf("Plugin tail call at slot %d executed, action=%d", pluginIndex, action)
	})
}
