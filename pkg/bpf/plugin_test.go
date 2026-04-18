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
		if err == nil {
			t.Error("Expected lookup to fail after unregister, but it succeeded")
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

// TestSlotStatsRecordsTailCall verifies that tailcall_epilogue actually
// increments slot_stats_endpoint for both a plugin slot and a builtin
// slot. Uses newXDPTestHelperWithStats so enable_stats=1.
func TestSlotStatsRecordsTailCall(t *testing.T) {
	h := newXDPTestHelperWithStats(t)

	cases := []struct {
		name     string
		sidAddr  string
		action   uint8
		progSlot uint32
		prog     *ebpf.Program
		register bool // true: register into plugin slot; false: use existing builtin slot
	}{
		{
			name:     "plugin slot 32",
			sidAddr:  "fd00::32",
			action:   32,
			progSlot: 32,
			prog:     h.objs.TailcallEndpointEnd,
			register: true,
		},
		{
			name:     "builtin End slot 1",
			sidAddr:  "fd00::1",
			action:   1, // SRV6_LOCAL_ACTION_END
			progSlot: 1,
			register: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.register {
				if err := h.objs.SidEndpointProgs.Update(tc.progSlot, tc.prog, ebpf.UpdateAny); err != nil {
					t.Fatalf("register plugin: %v", err)
				}
				t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(tc.progSlot) })
			}

			sidEntry := &SidFunctionEntry{Action: tc.action, Flavor: 0}
			if err := h.mapOps.CreateSidFunction(tc.sidAddr, sidEntry, nil); err != nil {
				t.Fatalf("create SID: %v", err)
			}

			// Snapshot before sending traffic.
			before, err := h.mapOps.ReadSlotStats(MapTypeEndpoint)
			if err != nil {
				t.Fatalf("ReadSlotStats before: %v", err)
			}
			beforePackets := before[tc.progSlot].Packets

			pkt, err := buildSRv6Packet(
				net.ParseIP("2001::1"),
				net.ParseIP(tc.sidAddr),
				[]net.IP{net.ParseIP("fd00::99")},
				1,
			)
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			action, _ := h.run(pkt)
			if action == 0 {
				t.Fatalf("tail call failed (XDP_ABORTED) for slot %d", tc.progSlot)
			}

			after, err := h.mapOps.ReadSlotStats(MapTypeEndpoint)
			if err != nil {
				t.Fatalf("ReadSlotStats after: %v", err)
			}
			got := after[tc.progSlot].Packets - beforePackets
			if got != 1 {
				t.Errorf("slot_stats_endpoint[%d] delta = %d, want 1", tc.progSlot, got)
			}

			// Other slots must be untouched by this packet.
			for i := range after {
				if uint32(i) == tc.progSlot {
					continue
				}
				delta := after[i].Packets - before[i].Packets
				if delta != 0 {
					t.Errorf("slot_stats_endpoint[%d] spuriously changed by %d", i, delta)
				}
			}
		})
	}
}
