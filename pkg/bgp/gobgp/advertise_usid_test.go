package gobgp

import (
	"net/netip"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// A VPN route carrying a SID Structure must advertise the RFC 9252
// Sub-Sub-TLV and decode back to the same structure -- this is how a peer
// recognizes a NEXT-C-SID (uSID) service SID.
func TestEncodeVPNPath_SIDStructureRoundTrip(t *testing.T) {
	want := bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16, ArgumentLen: 0}
	r := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		RTs: []string{"65000:200"}, SRv6SID: "fd00:aaaa:b002:d004::",
		NextHop: "2001:db8::1", SIDStructure: want,
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		t.Fatalf("encodeVPNPath: %v", err)
	}
	got := decodeSIDStructure(path.Attrs)
	if got != want {
		t.Errorf("decoded structure = %+v, want %+v", got, want)
	}
	if !got.IsUSID() {
		t.Errorf("32/16/16/0 must classify as uSID")
	}
	// The SID itself survives (no transposition is signalled).
	if sid := decodeSRv6SID(path.Attrs, 0, gobgppkt.TLVTypeSRv6L3Service); sid != r.SRv6SID {
		t.Errorf("decoded SID = %q, want %q", sid, r.SRv6SID)
	}
}

// A structure signalling transposition is rejected on advertise: the
// encoder neither zeroes the SID bits nor fills the VPN label, so
// advertising it would desynchronize the peer's fold from the wire.
func TestEncodeVPNPath_RejectsTransposition(t *testing.T) {
	r := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:aaaa:b002:d004::", NextHop: "2001:db8::1",
		SIDStructure: bgp.SIDStructure{
			LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16,
			TranspositionLen: 16, TranspositionOffset: 64,
		},
	}
	if _, err := encodeVPNPath(r); err == nil {
		t.Fatal("encodeVPNPath accepted a transposition it cannot perform")
	}
}

// A semantically invalid structure (off-the-wire values are
// attacker-controlled) makes the whole Information Sub-TLV unusable: no SID,
// no structure -- RFC 9252 Sec.7 treats such a path as ineligible.
func TestDecodeSIDStructure_InvalidStructureSkipsTLV(t *testing.T) {
	sid := netip.MustParseAddr("fd00:aaaa:b002:d004::")
	bad := gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 0, 64) // TO without TL
	info := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT4, bad)
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributePrefixSID(
		gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info))}
	if got := decodeSRv6SID(attrs, 0, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("decoded SID = %q from an invalid structure, want none", got)
	}
	if got := decodeSIDStructure(attrs); !got.IsZero() {
		t.Errorf("decoded structure = %+v, want zero", got)
	}
}

// A transposed advertisement whose SID did not zero the transposed bit
// range is malformed (RFC 9252 §4 requires those bits zeroed on the
// wire): folding the label into it would synthesize a SID the peer never
// owned, so the whole Information Sub-TLV is unusable.
func TestDecodeSRv6SID_NonZeroTransposedRangeSkipsTLV(t *testing.T) {
	// TL=16 at offset 48, but the SID still carries 0xd004 in bits 48..63
	// -- the range RFC 9252 §4 requires to be zeroed on the wire.
	st := gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 16, 48)
	sid := netip.MustParseAddr("fd00:aaaa:b002:d004::")
	info := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT4, st)
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributePrefixSID(
		gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info))}
	if got := decodeSRv6SID(attrs, 0xd004<<4, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("decoded SID = %q from a non-zeroed transposed range, want none", got)
	}
}

// On an L3 Service TLV the transposition carries function bits (RFC 9252
// §4.1), so a TL longer than FL cannot describe a valid L3 service SID
// and the Information Sub-TLV is unusable. (L2 Service TLVs are exempt:
// EVPN transposes argument bits.)
func TestDecodeSRv6SID_L3TranspositionWiderThanFunctionSkipsTLV(t *testing.T) {
	st := gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 8, 16, 48)
	sid := netip.MustParseAddr("fd00:aaaa:b002::")
	info := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT4, st)
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributePrefixSID(
		gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info))}
	if got := decodeSRv6SID(attrs, 0x11110, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("decoded SID = %q from an L3 TLV with TL > FL, want none", got)
	}
}

// RFC 9252 ties the Service TLV type to the route type: an L2 Service
// TLV (EVPN's) on a VPNv4/v6 path must not supply the L3VPN's SID.
func TestDecodeSRv6SID_WrongServiceTLVTypeIgnored(t *testing.T) {
	sid := netip.MustParseAddr("fd00:aaaa:b002:d004::")
	info := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT2U)
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributePrefixSID(
		gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, info))}
	if got := decodeSRv6SID(attrs, 0, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("L3 decode took the SID from an L2 Service TLV: %q", got)
	}
	if got := decodeSRv6SID(attrs, 0, gobgppkt.TLVTypeSRv6L2Service); got == "" {
		t.Error("L2 decode must still find the L2 Service TLV's SID")
	}
}

// An L3 transposition offset inside the locator (TO < LBL+LNL) would let
// the VPN label rewrite the locator itself; such a structure is invalid.
func TestDecodeSRv6SID_L3TranspositionIntoLocatorSkipsTLV(t *testing.T) {
	st := gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 16, 0)
	sid := netip.MustParseAddr("fd00:aaaa:b002::")
	info := gobgppkt.NewSRv6InformationSubTLV(sid, gobgppkt.END_DT4, st)
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributePrefixSID(
		gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info))}
	if got := decodeSRv6SID(attrs, 0xd004<<4, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("decoded SID = %q from a transposition into the locator, want none", got)
	}
}

// A route without a structure keeps the pre-existing wire shape: no
// Sub-Sub-TLV, and the decoder returns the zero value.
func TestEncodeVPNPath_NoSIDStructure(t *testing.T) {
	r := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1",
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		t.Fatalf("encodeVPNPath: %v", err)
	}
	if got := decodeSIDStructure(path.Attrs); !got.IsZero() {
		t.Errorf("decoded structure = %+v, want zero", got)
	}
}

// IsUSID's boundary: an Argument disqualifies, as does an oversized
// block+node+function; a transposition does not (the fold restores the
// full SID before the applier looks at the shape).
func TestSIDStructureIsUSID(t *testing.T) {
	cases := []struct {
		name string
		st   bgp.SIDStructure
		want bool
	}{
		{"F3216", bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16}, true},
		{"zero", bgp.SIDStructure{}, false},
		{"classic with argument", bgp.SIDStructure{LocatorBlockLen: 40, LocatorNodeLen: 24, FunctionLen: 16, ArgumentLen: 48}, false},
		// FRR transposes even with usid-f3216; the fold happens before
		// install, so a transposed 32/16/16/0 is still a micro-SID.
		{"transposed F3216", bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 16, TranspositionLen: 16, TranspositionOffset: 64}, true},
		{"full-length layout", bgp.SIDStructure{LocatorBlockLen: 48, LocatorNodeLen: 16, FunctionLen: 64}, false},
	}
	for _, c := range cases {
		if got := c.st.IsUSID(); got != c.want {
			t.Errorf("%s: IsUSID = %t, want %t", c.name, got, c.want)
		}
	}
}
