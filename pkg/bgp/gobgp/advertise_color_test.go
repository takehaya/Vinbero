package gobgp

import (
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Encoding a colored VPN route must attach a Color Extended Community that
// decodeColor reads back after a wire round-trip -- the advertise side is
// the inverse of the receive side.
func TestEncodeVPNPath_ColorRoundTrip(t *testing.T) {
	r := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		RTs: []string{"65000:200"}, SRv6SID: "fd00:1:1:a::",
		NextHop: "2001:db8::1", Color: 100,
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		t.Fatalf("encodeVPNPath: %v", err)
	}

	var raw []byte
	for _, a := range path.Attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		b, serr := ec.Serialize()
		if serr != nil {
			t.Fatalf("serialize ext-comm: %v", serr)
		}
		raw = b
	}
	if raw == nil {
		t.Fatal("encoded path has no Extended Communities attribute")
	}
	ec2 := &gobgppkt.PathAttributeExtendedCommunities{}
	if err := ec2.DecodeFromBytes(raw); err != nil {
		t.Fatalf("decode ext-comm from wire: %v", err)
	}
	if got := decodeColor([]gobgppkt.PathAttributeInterface{ec2}); got != 100 {
		t.Errorf("decoded color = %d, want 100", got)
	}
}

// A route with color 0 and no route targets carries no Extended Communities
// attribute, and decodeColor returns 0.
func TestEncodeVPNPath_NoColorNoExtComm(t *testing.T) {
	r := bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", NextHop: "2001:db8::1", Color: 0,
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		t.Fatalf("encodeVPNPath: %v", err)
	}
	for _, a := range path.Attrs {
		if _, ok := a.(*gobgppkt.PathAttributeExtendedCommunities); ok {
			t.Errorf("unexpected Extended Communities attribute for an un-colored, RT-less route")
		}
	}
	if got := decodeColor(path.Attrs); got != 0 {
		t.Errorf("decoded color = %d, want 0", got)
	}
}
