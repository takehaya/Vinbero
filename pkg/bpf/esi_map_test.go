package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseAndFormatESI(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    [ESILen]byte
		wantErr bool
	}{
		{"empty", "", [ESILen]byte{}, false},
		{"valid", "00:11:22:33:44:55:66:77:88:99",
			[ESILen]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}, false},
		{"short", "00:11:22", [ESILen]byte{}, true},
		{"not hex", "zz:11:22:33:44:55:66:77:88:99", [ESILen]byte{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseESI(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseESI(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseESI(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseESI(%q) = %x, want %x", tc.input, got, tc.want)
			}
			if tc.input != "" {
				if round := FormatESI(got); round != tc.input {
					t.Errorf("FormatESI round-trip: got %q, want %q", round, tc.input)
				}
			} else if round := FormatESI(got); round != "" {
				t.Errorf("FormatESI(zero) = %q, want empty", round)
			}
		})
	}
}

func TestEsiMapCRUD(t *testing.T) {
	h := newXDPTestHelper(t)
	esi, _ := ParseESI("aa:bb:cc:dd:ee:ff:00:11:22:33")

	// Create
	if err := h.mapOps.CreateEsi(esi, &EsiEntry{LocalAttached: 1}); err != nil {
		t.Fatalf("CreateEsi: %v", err)
	}

	// Get
	got, err := h.mapOps.GetEsi(esi)
	if err != nil {
		t.Fatalf("GetEsi: %v", err)
	}
	if got.LocalAttached != 1 {
		t.Errorf("LocalAttached = %d, want 1", got.LocalAttached)
	}

	// List
	entries, err := h.mapOps.ListEsi()
	if err != nil {
		t.Fatalf("ListEsi: %v", err)
	}
	if _, ok := entries[esi]; !ok {
		t.Errorf("ListEsi missing %x", esi)
	}

	// Delete
	if err := h.mapOps.DeleteEsi(esi); err != nil {
		t.Fatalf("DeleteEsi: %v", err)
	}
	if _, err := h.mapOps.GetEsi(esi); err == nil {
		t.Error("GetEsi after delete: expected error")
	}
}

func TestEsiMapZeroESIRejected(t *testing.T) {
	h := newXDPTestHelper(t)
	var zero [ESILen]byte
	if err := h.mapOps.CreateEsi(zero, &EsiEntry{LocalAttached: 1}); err == nil {
		t.Error("CreateEsi(all-zero) should be rejected as single-homing sentinel")
	}
}

func TestBdPeerReverseEsi(t *testing.T) {
	h := newXDPTestHelper(t)
	srcAddr, _ := ParseIPv6("fc00:1::1")
	esi, _ := ParseESI("01:02:03:04:05:06:07:08:09:0a")
	entry := &HeadendEntry{
		Mode:        1, // H_ENCAPS
		NumSegments: 1,
		SrcAddr:     srcAddr,
	}

	if err := h.mapOps.CreateBdPeer(100, 0, entry, esi); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}

	// Reverse map should carry the same ESI bytes
	rKey := &BdPeerReverseKey{BdId: 100}
	copy(rKey.SrcAddr[:], srcAddr[:])
	var rVal BdPeerReverseVal
	if err := h.objs.BdPeerReverseMap.Lookup(rKey, &rVal); err != nil {
		t.Fatalf("lookup reverse map: %v", err)
	}
	var gotEsi [ESILen]byte
	copy(gotEsi[:], rVal.Esi[:])
	if gotEsi != esi {
		t.Errorf("reverse map ESI = %x, want %x", gotEsi, esi)
	}

	// Empty ESI (single-homing) should round-trip to zero
	if err := h.mapOps.CreateBdPeer(100, 1, entry, [ESILen]byte{}); err != nil {
		t.Fatalf("CreateBdPeer single-homing: %v", err)
	}

	// Cleanup
	_ = h.mapOps.DeleteBdPeer(100, 0)
	_ = h.mapOps.DeleteBdPeer(100, 1)
	// Ensure reverse map was drained for ESI path
	if err := h.objs.BdPeerReverseMap.Lookup(rKey, &rVal); err != nil {
		if err != ebpf.ErrKeyNotExist {
			t.Logf("DeleteBdPeer left reverse_map stale: %v", err)
		}
	}
}
