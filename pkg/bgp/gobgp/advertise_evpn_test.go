package gobgp

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Encoding an RT2 then decoding it back must round-trip the identity fields
// and the End.DT2U SID, proving advertise and receive agree on the wire form.
func TestEncodeEVPNMacPath_RoundTrip(t *testing.T) {
	in := bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeMACIP,
		RD:          "65000:100",
		RTs:         []string{"65000:100"},
		EthernetTag: 0,
		MAC:         "aa:bb:cc:00:00:01",
		SRv6SID:     "fd00:2:2:d2::",
		NextHop:     "2001:db8::1",
	}
	path, err := encodeEVPNMacPath(in)
	if err != nil {
		t.Fatalf("encodeEVPNMacPath: %v", err)
	}
	got := decodeEVPNRoute(path)
	if got == nil {
		t.Fatal("decodeEVPNRoute returned nil for an encoded RT2")
	}
	if got.MAC != in.MAC {
		t.Errorf("MAC = %q, want %q", got.MAC, in.MAC)
	}
	if got.SRv6SID != in.SRv6SID {
		t.Errorf("SID = %q, want %q", got.SRv6SID, in.SRv6SID)
	}
	if got.RD != in.RD {
		t.Errorf("RD = %q, want %q", got.RD, in.RD)
	}
	if len(got.RTs) != 1 || got.RTs[0] != "65000:100" {
		t.Errorf("RTs = %v, want [65000:100]", got.RTs)
	}
	if got.EthernetTag != in.EthernetTag {
		t.Errorf("EthernetTag = %d, want %d", got.EthernetTag, in.EthernetTag)
	}
}

func TestEncodeEVPNMacPath_RejectsBadInput(t *testing.T) {
	base := bgp.EVPNRoute{
		Type: bgp.EVPNRouteTypeMACIP, RD: "65000:100", RTs: []string{"65000:100"},
		MAC: "aa:bb:cc:00:00:01", SRv6SID: "fd00:2:2:d2::", NextHop: "2001:db8::1",
	}
	cases := map[string]func(*bgp.EVPNRoute){
		"bad MAC":              func(r *bgp.EVPNRoute) { r.MAC = "zz" },
		"IPv4 SID":             func(r *bgp.EVPNRoute) { r.SRv6SID = "10.0.0.1" },
		"unspecified SID":      func(r *bgp.EVPNRoute) { r.SRv6SID = "::" },
		"IPv4 next hop":        func(r *bgp.EVPNRoute) { r.NextHop = "10.0.0.1" },
		"unspecified next hop": func(r *bgp.EVPNRoute) { r.NextHop = "::" },
		"bad RD":               func(r *bgp.EVPNRoute) { r.RD = "not-an-rd" },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		if _, err := encodeEVPNMacPath(r); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// Encoding an RT3 then decoding it back must round-trip the identity fields
// and the End.DT2M SID (carried in the L2 Service TLV alongside the PMSI
// Ingress Replication attribute).
func TestEncodeEVPNMulticastPath_RoundTrip(t *testing.T) {
	in := bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeInclusiveMulticast,
		RD:          "65000:100",
		RTs:         []string{"65000:100"},
		EthernetTag: 5,
		SRv6SID:     "fd00:2:2:24::",
		NextHop:     "2001:db8::1",
	}
	path, err := encodeEVPNMulticastPath(in)
	if err != nil {
		t.Fatalf("encodeEVPNMulticastPath: %v", err)
	}
	got := decodeEVPNRoute(path)
	if got == nil {
		t.Fatal("decodeEVPNRoute returned nil for an encoded RT3")
	}
	if got.Type != bgp.EVPNRouteTypeInclusiveMulticast {
		t.Errorf("Type = %d, want InclusiveMulticast", got.Type)
	}
	if got.SRv6SID != in.SRv6SID {
		t.Errorf("SID = %q, want %q", got.SRv6SID, in.SRv6SID)
	}
	if got.RD != in.RD {
		t.Errorf("RD = %q, want %q", got.RD, in.RD)
	}
	if len(got.RTs) != 1 || got.RTs[0] != "65000:100" {
		t.Errorf("RTs = %v, want [65000:100]", got.RTs)
	}
	if got.EthernetTag != in.EthernetTag {
		t.Errorf("EthernetTag = %d, want %d", got.EthernetTag, in.EthernetTag)
	}
}

func TestEncodeEVPNMulticastPath_RejectsBadInput(t *testing.T) {
	base := bgp.EVPNRoute{
		Type: bgp.EVPNRouteTypeInclusiveMulticast, RD: "65000:100", RTs: []string{"65000:100"},
		SRv6SID: "fd00:2:2:24::", NextHop: "2001:db8::1",
	}
	cases := map[string]func(*bgp.EVPNRoute){
		"IPv4 SID":             func(r *bgp.EVPNRoute) { r.SRv6SID = "10.0.0.1" },
		"unspecified SID":      func(r *bgp.EVPNRoute) { r.SRv6SID = "::" },
		"IPv4 next hop":        func(r *bgp.EVPNRoute) { r.NextHop = "10.0.0.1" },
		"unspecified next hop": func(r *bgp.EVPNRoute) { r.NextHop = "::" },
		"bad RD":               func(r *bgp.EVPNRoute) { r.RD = "not-an-rd" },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		if _, err := encodeEVPNMulticastPath(r); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// Encoding an RT4 then decoding it back must round-trip the ESI, the ES-Import
// route target, and the originating PE next hop. RT4 carries no SID.
func TestEncodeEVPNEthernetSegmentPath_RoundTrip(t *testing.T) {
	in := bgp.EVPNRoute{
		Type:       bgp.EVPNRouteTypeEthernetSegment,
		RD:         "65000:1",
		ESI:        [10]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		ESImportRT: "aa:bb:cc:dd:ee:ff",
		NextHop:    "2001:db8::1",
	}
	path, err := encodeEVPNEthernetSegmentPath(in)
	if err != nil {
		t.Fatalf("encodeEVPNEthernetSegmentPath: %v", err)
	}
	got := decodeEVPNRoute(path)
	if got == nil {
		t.Fatal("decodeEVPNRoute returned nil for an encoded RT4")
	}
	if got.Type != bgp.EVPNRouteTypeEthernetSegment {
		t.Errorf("Type = %d, want EthernetSegment", got.Type)
	}
	if got.ESI != in.ESI {
		t.Errorf("ESI = %v, want %v", got.ESI, in.ESI)
	}
	if got.ESImportRT != in.ESImportRT {
		t.Errorf("ESImportRT = %q, want %q", got.ESImportRT, in.ESImportRT)
	}
	if got.NextHop != in.NextHop {
		t.Errorf("NextHop = %q, want %q", got.NextHop, in.NextHop)
	}
	if got.SRv6SID != "" {
		t.Errorf("RT4 carries no SID; got %q", got.SRv6SID)
	}
}

func TestEncodeEVPNEthernetSegmentPath_RejectsBadInput(t *testing.T) {
	base := bgp.EVPNRoute{
		Type: bgp.EVPNRouteTypeEthernetSegment, RD: "65000:1",
		ESI:        [10]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		ESImportRT: "aa:bb:cc:dd:ee:ff", NextHop: "2001:db8::1",
	}
	cases := map[string]func(*bgp.EVPNRoute){
		"zero ESI":             func(r *bgp.EVPNRoute) { r.ESI = [10]byte{} },
		"IPv4 next hop":        func(r *bgp.EVPNRoute) { r.NextHop = "10.0.0.1" },
		"IPv4-mapped next hop": func(r *bgp.EVPNRoute) { r.NextHop = "::ffff:10.0.0.1" },
		"unspecified next hop": func(r *bgp.EVPNRoute) { r.NextHop = "::" },
		"bad RD":               func(r *bgp.EVPNRoute) { r.RD = "not-an-rd" },
		"empty ES-Import":      func(r *bgp.EVPNRoute) { r.ESImportRT = "" },
		"bad ES-Import":        func(r *bgp.EVPNRoute) { r.ESImportRT = "zz" },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		if _, err := encodeEVPNEthernetSegmentPath(r); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
