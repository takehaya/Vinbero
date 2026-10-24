package gobgp

import (
	"net/netip"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestBehaviorMatchesVPNServiceSID(t *testing.T) {
	r := bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100", SRv6SID: "fd00:1::", NextHop: "2001:db8::1", EndpointBehavior: 0xfe01}
	p, err := encodeVPNPath(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range p.Attrs {
		if psid, ok := attr.(*gobgppkt.PathAttributePrefixSID); ok {
			l2 := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:2::"), gobgppkt.END_DT2U))
			psid.TLVs = append([]gobgppkt.PrefixSIDTLVInterface{l2}, psid.TLVs...)
		}
	}
	ev, ok := pathToRouteEvent(p)
	if !ok || ev.VPN == nil || ev.VPN.SRv6SID != r.SRv6SID {
		t.Fatalf("VPN decode = %+v", ev)
	}
	if ev.EndpointBehavior != r.EndpointBehavior {
		t.Fatalf("SID %s uses behavior %#x but event reports unrelated L2 behavior %#x", ev.VPN.SRv6SID, r.EndpointBehavior, ev.EndpointBehavior)
	}
}

func TestBehaviorMatchesEVPNServiceSID(t *testing.T) {
	r := bgp.EVPNRoute{Type: bgp.EVPNRouteTypeMACIP, RD: "65000:1", MAC: "02:00:00:00:00:01", SRv6SID: "fd00:1::", NextHop: "2001:db8::1"}
	p, err := encodeEVPNMacPath(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range p.Attrs {
		if psid, ok := attr.(*gobgppkt.PathAttributePrefixSID); ok {
			l3 := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:2::"), gobgppkt.SRBehavior(0xfe01)))
			psid.TLVs = append([]gobgppkt.PrefixSIDTLVInterface{l3}, psid.TLVs...)
		}
	}
	ev, ok := pathToRouteEvent(p)
	if !ok || ev.EVPN == nil || ev.EVPN.SRv6SID != r.SRv6SID || ev.EndpointBehavior != uint16(gobgppkt.END_DT2U) {
		t.Fatalf("mismatched L2 service: %+v", ev)
	}
}
