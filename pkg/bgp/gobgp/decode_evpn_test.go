package gobgp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// rt2Path builds a received EVPN RT2 (MAC/IP) path with a route target and
// an End.DT2U SID in the SRv6 L2 Service TLV.
func rt2Path(t *testing.T, mac, sid string) *apiutil.Path {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := &gobgppkt.EVPNNLRI{
		RouteType: gobgppkt.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
		RouteTypeData: &gobgppkt.EVPNMacIPAdvertisementRoute{
			RD:               rd,
			ETag:             0,
			MacAddressLength: 48,
			MacAddress:       hw,
		},
	}
	rt, _ := gobgppkt.ParseExtendedCommunity(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{rt}),
		gobgppkt.NewPathAttributePrefixSID(
			gobgppkt.NewSRv6ServiceTLV(
				gobgppkt.TLVTypeSRv6L2Service,
				gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), gobgppkt.END_DT2U),
			),
		),
	}
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}
}

func TestDecodeEVPN_RT2(t *testing.T) {
	r := decodeEVPNRoute(rt2Path(t, "aa:bb:cc:00:00:01", "fd00:2:2:d2::"))
	if r == nil {
		t.Fatal("decodeEVPNRoute returned nil for an RT2 path")
	}
	if r.Type != bgp.EVPNRouteTypeMACIP {
		t.Errorf("Type = %d, want RT2 (MAC/IP)", r.Type)
	}
	if r.MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("MAC = %q, want aa:bb:cc:00:00:01", r.MAC)
	}
	if r.SRv6SID != "fd00:2:2:d2::" {
		t.Errorf("SRv6SID = %q, want fd00:2:2:d2:: (End.DT2U)", r.SRv6SID)
	}
	if len(r.RTs) != 1 || r.RTs[0] != "65000:100" {
		t.Errorf("RTs = %v, want [65000:100]", r.RTs)
	}
}

// A non-RT2 EVPN route (here a bare unknown type) decodes to nil in Phase E1
// so the subscriber skips it until RT3/RT4 land.
func TestDecodeEVPN_NonRT2IsNil(t *testing.T) {
	nlri := &gobgppkt.EVPNNLRI{
		RouteType:     gobgppkt.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		RouteTypeData: &gobgppkt.EVPNEthernetAutoDiscoveryRoute{},
	}
	if r := decodeEVPNRoute(&apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri}); r != nil {
		t.Errorf("non-RT2 EVPN route decoded to %+v, want nil", r)
	}
}
