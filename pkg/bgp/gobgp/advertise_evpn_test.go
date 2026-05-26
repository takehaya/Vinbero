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
		"bad MAC":         func(r *bgp.EVPNRoute) { r.MAC = "zz" },
		"IPv4 SID":        func(r *bgp.EVPNRoute) { r.SRv6SID = "10.0.0.1" },
		"unspecified SID": func(r *bgp.EVPNRoute) { r.SRv6SID = "::" },
		"IPv4 next hop":   func(r *bgp.EVPNRoute) { r.NextHop = "10.0.0.1" },
		"bad RD":          func(r *bgp.EVPNRoute) { r.RD = "not-an-rd" },
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
		"IPv4 SID":        func(r *bgp.EVPNRoute) { r.SRv6SID = "10.0.0.1" },
		"unspecified SID": func(r *bgp.EVPNRoute) { r.SRv6SID = "::" },
		"IPv4 next hop":   func(r *bgp.EVPNRoute) { r.NextHop = "10.0.0.1" },
		"bad RD":          func(r *bgp.EVPNRoute) { r.RD = "not-an-rd" },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		if _, err := encodeEVPNMulticastPath(r); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
