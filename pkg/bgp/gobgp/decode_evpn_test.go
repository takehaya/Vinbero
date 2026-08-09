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

// A route type Vinbero does not decode must come back nil so the applier is
// never handed a half-populated route. RT5 IP Prefix is the remaining one;
// RT1 used to sit here too and now decodes.
func TestDecodeEVPN_UndecodedTypeIsNil(t *testing.T) {
	nlri := &gobgppkt.EVPNNLRI{
		RouteType:     gobgppkt.EVPN_IP_PREFIX,
		RouteTypeData: &gobgppkt.EVPNIPPrefixRoute{},
	}
	if r := decodeEVPNRoute(&apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri}); r != nil {
		t.Errorf("undecoded EVPN route decoded to %+v, want nil", r)
	}
}

// rt3Path builds a received EVPN RT3 (Inclusive Multicast) path with a route
// target, a PMSI Ingress Replication attribute, and an End.DT2M SID in the
// SRv6 L2 Service TLV.
func rt3Path(t *testing.T, sid string) *apiutil.Path {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := &gobgppkt.EVPNNLRI{
		RouteType: gobgppkt.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG,
		RouteTypeData: &gobgppkt.EVPNMulticastEthernetTagRoute{
			RD:   rd,
			ETag: 0,
		},
	}
	rt, _ := gobgppkt.ParseExtendedCommunity(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	tid, _ := gobgppkt.NewIngressReplTunnelID(netip.MustParseAddr("2001:db8::2"))
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{rt}),
		gobgppkt.NewPathAttributePmsiTunnel(gobgppkt.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, tid),
		gobgppkt.NewPathAttributePrefixSID(
			gobgppkt.NewSRv6ServiceTLV(
				gobgppkt.TLVTypeSRv6L2Service,
				gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), gobgppkt.END_DT2M),
			),
		),
	}
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}
}

func TestDecodeEVPN_RT3(t *testing.T) {
	r := decodeEVPNRoute(rt3Path(t, "fd00:2:2:24::"))
	if r == nil {
		t.Fatal("decodeEVPNRoute returned nil for an RT3 path")
	}
	if r.Type != bgp.EVPNRouteTypeInclusiveMulticast {
		t.Errorf("Type = %d, want RT3 (Inclusive Multicast)", r.Type)
	}
	if r.SRv6SID != "fd00:2:2:24::" {
		t.Errorf("SRv6SID = %q, want fd00:2:2:24:: (End.DT2M)", r.SRv6SID)
	}
	if len(r.RTs) != 1 || r.RTs[0] != "65000:100" {
		t.Errorf("RTs = %v, want [65000:100]", r.RTs)
	}
}

// An RT3 with no PMSI Tunnel attribute still decodes: the End.DT2M SID comes
// from the L2 Service TLV and the transposition label defaults to 0. This is
// untrusted wire input (a peer may omit or vary the PMSI), so it must not panic
// or drop the SID.
func TestDecodeEVPN_RT3NoPmsi(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := &gobgppkt.EVPNNLRI{
		RouteType:     gobgppkt.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG,
		RouteTypeData: &gobgppkt.EVPNMulticastEthernetTagRoute{RD: rd, ETag: 0},
	}
	rt, _ := gobgppkt.ParseExtendedCommunity(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{rt}),
		gobgppkt.NewPathAttributePrefixSID(
			gobgppkt.NewSRv6ServiceTLV(
				gobgppkt.TLVTypeSRv6L2Service,
				gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:2:2:24::"), gobgppkt.END_DT2M),
			),
		),
	}
	r := decodeEVPNRoute(&apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs})
	if r == nil || r.Type != bgp.EVPNRouteTypeInclusiveMulticast {
		t.Fatalf("RT3 without PMSI must still decode as Inclusive Multicast; got %+v", r)
	}
	if r.SRv6SID != "fd00:2:2:24::" {
		t.Errorf("SRv6SID = %q, want fd00:2:2:24:: from the L2 Service TLV", r.SRv6SID)
	}
}

// rt4Path builds a received EVPN RT4 (Ethernet Segment) path: an ESI, an
// ES-Import route target, and the originating router IP as the next hop. RT4
// carries no SRv6 SID.
func rt4Path(t *testing.T, esiValue []byte, nh string) *apiutil.Path {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 1)
	nlri := &gobgppkt.EVPNNLRI{
		RouteType: gobgppkt.EVPN_ETHERNET_SEGMENT_ROUTE,
		RouteTypeData: &gobgppkt.EVPNEthernetSegmentRoute{
			RD:              rd,
			ESI:             gobgppkt.EthernetSegmentIdentifier{Type: gobgppkt.ESI_ARBITRARY, Value: esiValue},
			IPAddressLength: 128,
			IPAddress:       netip.MustParseAddr(nh),
		},
	}
	esImport := gobgppkt.NewESImportRouteTarget("aa:bb:cc:dd:ee:ff")
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nh))
	if err != nil {
		t.Fatalf("build MP_REACH_NLRI: %v", err)
	}
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{esImport}),
		mpReach,
	}
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}
}

func TestDecodeEVPN_RT4(t *testing.T) {
	r := decodeEVPNRoute(rt4Path(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, "2001:db8::1"))
	if r == nil {
		t.Fatal("decodeEVPNRoute returned nil for an RT4 path")
	}
	if r.Type != bgp.EVPNRouteTypeEthernetSegment {
		t.Errorf("Type = %d, want RT4 (Ethernet Segment)", r.Type)
	}
	if r.NextHop != "2001:db8::1" {
		t.Errorf("NextHop = %q, want 2001:db8::1 (originating PE)", r.NextHop)
	}
	if r.ESImportRT != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ESImportRT = %q, want aa:bb:cc:dd:ee:ff", r.ESImportRT)
	}
	if r.SRv6SID != "" {
		t.Errorf("RT4 carries no SID; got %q", r.SRv6SID)
	}
	// esiToArray: Type (0) + 9-byte value.
	want := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if r.ESI != want {
		t.Errorf("ESI = %v, want %v", r.ESI, want)
	}
}

// decodeRemoteSrc derives the advertising PE's encap source by masking the
// received SID to its locator length. rt2Path carries no SID Structure
// sub-sub-TLV, so this exercises the configurable fallback length.
func TestDecodeRemoteSrc_Fallback(t *testing.T) {
	p := rt2Path(t, "aa:bb:cc:00:00:01", "fd00:200:0:2::")
	if got := decodeRemoteSrc(p.Attrs, 0, 48); got != "fd00:200::" {
		t.Errorf("remote src (/48) = %q, want fd00:200::", got)
	}
	// A different fallback length changes the mask.
	if got := decodeRemoteSrc(p.Attrs, 0, 64); got != "fd00:200:0:2::" {
		t.Errorf("remote src (/64) = %q, want fd00:200:0:2::", got)
	}
}

// An RT2 with the decoded RemoteSrc reaches the route via decodeEVPNRoute.
func TestDecodeEVPN_RT2RemoteSrc(t *testing.T) {
	r := decodeEVPNRoute(rt2Path(t, "aa:bb:cc:00:00:01", "fd00:200:0:2::"))
	if r == nil || r.RemoteSrc != "fd00:200::" {
		t.Errorf("RemoteSrc = %q, want fd00:200:: (/48 fallback)", r.RemoteSrc)
	}
}

// rt1Path builds a received EVPN RT1 (Ethernet A-D) path. etag selects the
// per-ES form (MAX-ET) or a per-EVI one; singleActive attaches the ESI Label
// extended community with the Single-Active bit set.
func rt1Path(t *testing.T, etag uint32, sid string, singleActive bool) *apiutil.Path {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	esi := gobgppkt.EthernetSegmentIdentifier{
		Type:  gobgppkt.ESI_ARBITRARY,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	nlri := &gobgppkt.EVPNNLRI{
		RouteType: gobgppkt.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		RouteTypeData: &gobgppkt.EVPNEthernetAutoDiscoveryRoute{
			RD: rd, ESI: esi, ETag: etag,
		},
	}
	rt, _ := gobgppkt.ParseExtendedCommunity(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	ecs := []gobgppkt.ExtendedCommunityInterface{rt}
	if singleActive {
		ecs = append(ecs, gobgppkt.NewESILabelExtended(0, true))
	}
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities(ecs),
	}
	if sid != "" {
		attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(
			gobgppkt.NewSRv6ServiceTLV(
				gobgppkt.TLVTypeSRv6L2Service,
				gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), gobgppkt.END_DT2U),
			),
		))
	}
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}
}

// rt1TransposedPath builds an RT1 whose SID has its Argument bits transposed
// out into a label, so the decoded SID depends on which label the decoder
// reads. nlriLabel goes in the NLRI, esiLabel in the ESI Label extended
// community.
func rt1TransposedPath(t *testing.T, etag, nlriLabel, esiLabel uint32) *apiutil.Path {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	esi := gobgppkt.EthernetSegmentIdentifier{
		Type:  gobgppkt.ESI_ARBITRARY,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	nlri := &gobgppkt.EVPNNLRI{
		RouteType: gobgppkt.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		RouteTypeData: &gobgppkt.EVPNEthernetAutoDiscoveryRoute{
			RD: rd, ESI: esi, ETag: etag, Label: nlriLabel,
		},
	}
	info := gobgppkt.NewSRv6InformationSubTLV(
		netip.MustParseAddr("fd00:1:1::"), gobgppkt.END_DT2M)
	// block 32 / node 16 / function 16, argument transposed out: 16 bits at
	// offset 64.
	info.SubSubTLVs = append(info.SubSubTLVs,
		gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 16, 16, 64))
	rt, _ := gobgppkt.ParseExtendedCommunity(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, "65000:100")
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{
			rt, gobgppkt.NewESILabelExtended(esiLabel, false),
		}),
		gobgppkt.NewPathAttributePrefixSID(
			gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, info)),
	}
	return &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: nlri, Attrs: attrs}
}

// RFC 9252 puts the transposed Argument bits in different places for the two
// RT1 forms: a per-EVI route uses the NLRI's MPLS label, a per-ES route sets
// that label to 0 and uses the 24-bit ESI Label extended community instead.
// Reading the wrong one composes a SID pointing somewhere else entirely, and
// nothing downstream would notice.
func TestDecodeEVPN_RT1TranspositionSource(t *testing.T) {
	t.Run("per-EVI transposes from the NLRI label", func(t *testing.T) {
		// The ESI Label differs between the two paths; only the NLRI label
		// may move the SID.
		a := decodeEVPNRoute(rt1TransposedPath(t, 100, 0x11000, 0))
		b := decodeEVPNRoute(rt1TransposedPath(t, 100, 0x11000, 0x99000))
		if a.SRv6SID != b.SRv6SID {
			t.Errorf("per-EVI SID moved with the ESI Label: %q vs %q", a.SRv6SID, b.SRv6SID)
		}
		c := decodeEVPNRoute(rt1TransposedPath(t, 100, 0x22000, 0))
		if a.SRv6SID == c.SRv6SID {
			t.Errorf("per-EVI SID did not follow the NLRI label: both %q", a.SRv6SID)
		}
	})

	t.Run("per-ES transposes from the ESI Label community", func(t *testing.T) {
		et := bgp.EVPNMaxEthernetTag
		// A per-ES route carries NLRI label 0 on the wire; vary it anyway to
		// prove the decoder is not reading it.
		a := decodeEVPNRoute(rt1TransposedPath(t, et, 0, 0x11000))
		b := decodeEVPNRoute(rt1TransposedPath(t, et, 0x77000, 0x11000))
		if a.SRv6SID != b.SRv6SID {
			t.Errorf("per-ES SID moved with the NLRI label: %q vs %q", a.SRv6SID, b.SRv6SID)
		}
		c := decodeEVPNRoute(rt1TransposedPath(t, et, 0, 0x22000))
		if a.SRv6SID == c.SRv6SID {
			t.Errorf("per-ES SID did not follow the ESI Label: both %q", a.SRv6SID)
		}
	})
}

func TestDecodeEVPN_RT1(t *testing.T) {
	// One NLRI type carries two statements, told apart by the Ethernet Tag.
	// Confusing them would be serious: treating a per-ES withdraw as per-EVI
	// loses the mass-withdraw signal, and treating per-EVI as per-ES would
	// apply one broadcast domain's SID to the whole segment.
	t.Run("per-EVI carries the aliasing SID", func(t *testing.T) {
		r := decodeEVPNRoute(rt1Path(t, 100, "fd00:1:1:2::", false))
		if r == nil {
			t.Fatal("RT1 did not decode")
		}
		if r.Type != bgp.EVPNRouteTypeEthernetAD {
			t.Errorf("type = %d, want RT1", r.Type)
		}
		if r.IsPerES() {
			t.Error("a per-EVI route must not report IsPerES")
		}
		if r.EthernetTag != 100 {
			t.Errorf("ethernet tag = %d, want 100", r.EthernetTag)
		}
		if r.SRv6SID != "fd00:1:1:2::" {
			t.Errorf("SID = %q, want the aliasing SID", r.SRv6SID)
		}
		if r.ESI != [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
			t.Errorf("ESI = %v", r.ESI)
		}
	})

	t.Run("per-ES is identified by MAX-ET", func(t *testing.T) {
		r := decodeEVPNRoute(rt1Path(t, bgp.EVPNMaxEthernetTag, "", false))
		if r == nil {
			t.Fatal("RT1 did not decode")
		}
		if !r.IsPerES() {
			t.Errorf("ethernet tag %#x should mark a per-ES route", r.EthernetTag)
		}
	})

	t.Run("single-active is read from the ESI Label community", func(t *testing.T) {
		// Single-active forbids aliasing: only the DF forwards, so spreading
		// traffic over the PEs advertising the ES would black-hole whatever
		// reached a non-DF.
		r := decodeEVPNRoute(rt1Path(t, bgp.EVPNMaxEthernetTag, "", true))
		if !r.SingleActive {
			t.Error("Single-Active bit was not decoded")
		}
	})

	t.Run("absent community means all-active", func(t *testing.T) {
		r := decodeEVPNRoute(rt1Path(t, bgp.EVPNMaxEthernetTag, "", false))
		if r.SingleActive {
			t.Error("no ESI Label community must read as all-active")
		}
	})
}
