package bpf

import "testing"

// TestBpfLoad verifies that BPF objects can be loaded into the kernel.
// This test is used by the multi-kernel CI (vimto) to ensure compatibility
// across different kernel versions.
func TestBpfLoad(t *testing.T) {
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	if objs.VinberoMain == nil {
		t.Fatal("XDP program (VinberoMain) is nil")
	}
	if objs.VinberoTcIngress == nil {
		t.Fatal("TC program (VinberoTcIngress) is nil")
	}

	t.Log("BPF objects loaded successfully")
}

// TestBpfLoadXDPBum loads the collection with xdp BUM mode compiled in, so
// the multi-kernel CI also verifies the xdp-mode branches of vinbero_main
// and the endpoint programs (pruned when bum_xdp_enabled is 0) next to the
// devmap egress program.
func TestBpfLoadXDPBum(t *testing.T) {
	objs, err := ReadCollection(map[string]any{
		"bum_xdp_enabled":  uint8(1),
		"bum_mode_default": BumModeXDP,
	}, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects with xdp BUM mode: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	if NewBumDevmapSync(objs, func(uint16) uint8 { return BumModeXDP }, nil, nil).egress == nil {
		t.Fatal("bum_remote_egress not loaded")
	}
}

// TestBpfLoadXDPBumNative also verifies the native-XDP variant: metadata
// handoff to the egress program and every redirect through uplink_tx_map.
func TestBpfLoadXDPBumNative(t *testing.T) {
	objs, err := ReadCollection(map[string]any{
		"bum_xdp_enabled":  uint8(1),
		"bum_mode_default": BumModeXDP,
		"bum_xdp_native":   uint8(1),
	}, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects with native xdp BUM mode: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
}
