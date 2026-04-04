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
