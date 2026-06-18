package bpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestComposeGTP4ArgsSID(t *testing.T) {
	const (
		base   = "fc00:3::"
		offset = uint8(7)
		gnb    = "10.0.0.2"
		teid   = uint32(0xDEADBEEF)
		qfi    = uint8(15)
		rqi    = uint8(1)
	)

	got, err := ComposeGTP4ArgsSID(base, offset, gnb, teid, qfi, rqi)
	if err != nil {
		t.Fatalf("ComposeGTP4ArgsSID: %v", err)
	}
	addr, err := netip.ParseAddr(got)
	if err != nil {
		t.Fatalf("result %q not parseable: %v", got, err)
	}
	sid := addr.As16()

	// RFC 9433 §6.1 layout (matches the BPF data-plane SID layout):
	// [gNB IPv4 (4)] [QFI<<2 | RQI<<1 (1)] [TEID big-endian (4)].
	wantV4 := netip.MustParseAddr(gnb).As4()
	if got := sid[offset : offset+4]; [4]byte(got) != wantV4 {
		t.Errorf("gNB IPv4 = %v, want %v", got, wantV4)
	}
	if got, want := sid[offset+4], ((qfi&0x3F)<<2)|((rqi&0x01)<<1); got != want {
		t.Errorf("QFI/RQI byte = 0x%02X, want 0x%02X", got, want)
	}
	if got := binary.BigEndian.Uint32(sid[offset+5 : offset+9]); got != teid {
		t.Errorf("TEID = 0x%08X, want 0x%08X", got, teid)
	}

	// Bytes outside the 9-byte args window must equal the base SID.
	baseBytes := netip.MustParseAddr(base).As16()
	for i := 0; i < 16; i++ {
		if i >= int(offset) && i < int(offset)+9 {
			continue
		}
		if sid[i] != baseBytes[i] {
			t.Errorf("byte %d = 0x%02X, want base 0x%02X (locator:function must be preserved)", i, sid[i], baseBytes[i])
		}
	}
}

// TestComposeGTP4ArgsSID_RFC9433Wire pins the exact SID the RFC 9433 §6.1 wire
// layout produces for a downlink session (gNB 172.16.0.1, TEID 256, QFI 9 at
// args-offset 7 over the fd00:a:0:1:: interwork locator). A divergence here
// means a peer implementation's End.M.GTP4.E would read a transposed TEID/QFI
// from this SID (and vice versa) -- the RFC 9433 byte order is the contract.
func TestComposeGTP4ArgsSID_RFC9433Wire(t *testing.T) {
	got, err := ComposeGTP4ArgsSID("fd00:a:0:1::", 7, "172.16.0.1", 256, 9, 0)
	if err != nil {
		t.Fatalf("ComposeGTP4ArgsSID: %v", err)
	}
	const want = "fd00:a:0:ac:1000:124:0:100"
	if got != want {
		t.Errorf("composed SID = %s, want %s (RFC 9433 §6.1 layout)", got, want)
	}
}

func TestComposeGTP6ArgsSID(t *testing.T) {
	const (
		base   = "fd00:6::"
		offset = uint8(9)
		teid   = uint32(0xCAFEBABE)
		qfi    = uint8(5)
		rqi    = uint8(1)
	)
	got, err := ComposeGTP6ArgsSID(base, offset, teid, qfi, rqi)
	if err != nil {
		t.Fatalf("ComposeGTP6ArgsSID: %v", err)
	}
	addr, err := netip.ParseAddr(got)
	if err != nil {
		t.Fatalf("result %q not parseable: %v", got, err)
	}
	sid := addr.As16()

	// GTP6 Args.Mob.Session (RFC 9433 §6.1): [QFI<<2 | RQI<<1 (1)] [TEID big-endian (4)].
	if got, want := sid[offset], ((qfi&0x3F)<<2)|((rqi&0x01)<<1); got != want {
		t.Errorf("QFI/RQI byte = 0x%02X, want 0x%02X", got, want)
	}
	if got := binary.BigEndian.Uint32(sid[offset+1 : offset+5]); got != teid {
		t.Errorf("TEID = 0x%08X, want 0x%08X", got, teid)
	}
	// Bytes outside the 5-byte args window must equal the base SID.
	baseBytes := netip.MustParseAddr(base).As16()
	for i := 0; i < 16; i++ {
		if i >= int(offset) && i < int(offset)+5 {
			continue
		}
		if sid[i] != baseBytes[i] {
			t.Errorf("byte %d = 0x%02X, want base 0x%02X", i, sid[i], baseBytes[i])
		}
	}

	// offset > 11 must be rejected (5 bytes must fit 16).
	if _, err := ComposeGTP6ArgsSID(base, 12, teid, qfi, rqi); err == nil {
		t.Error("ComposeGTP6ArgsSID(offset=12) = nil error, want error")
	}
	// non-IPv6 base rejected.
	if _, err := ComposeGTP6ArgsSID("10.0.0.1", 9, teid, qfi, rqi); err == nil {
		t.Error("ComposeGTP6ArgsSID(IPv4 base) = nil error, want error")
	}
}

func TestComposeGTP4ArgsSID_Errors(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		offset uint8
		gnb    string
	}{
		{"offset too large", "fc00:3::", 8, "10.0.0.2"},
		{"base not IPv6", "10.0.0.1", 7, "10.0.0.2"},
		{"endpoint not IPv4", "fc00:3::", 7, "fc00::9"},
		{"base unparseable", "not-an-ip", 7, "10.0.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ComposeGTP4ArgsSID(tt.base, tt.offset, tt.gnb, 1, 0, 0); err == nil {
				t.Errorf("ComposeGTP4ArgsSID(%q, %d, %q) = nil error, want error", tt.base, tt.offset, tt.gnb)
			}
		})
	}
}
