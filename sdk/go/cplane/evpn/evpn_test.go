package evpn

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

func fixture(t *testing.T, flood bool) routes.Entry {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	var n *bgp.EVPNNLRI
	var err error
	behavior := bgp.END_DT2U
	if flood {
		n, err = bgp.NewEVPNMulticastEthernetTagRoute(rd, 0, netip.MustParseAddr("192.0.2.1"))
		behavior = bgp.END_DT2M
	} else {
		n, err = bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, "02:00:00:00:00:01", netip.Addr{}, []uint32{0})
	}
	if err != nil {
		t.Fatal(err)
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	sid := bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L2Service, bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:2::1"), behavior)))
	packet, err := gobgppath.Encode(bgp.RF_EVPN, n, []bgp.PathAttributeInterface{mp, sid})
	if err != nil {
		t.Fatal(err)
	}
	p, err := gobgppath.DecodePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	return routes.Entry{Family: "evpn", Path: p}
}

func TestStaticMACAndFloodBuilders(t *testing.T) {
	source := netip.MustParseAddr("fd00:feed::1")
	entry := fixture(t, false)
	rt2 := RT2Selector().Project(entry)
	if rt2.State != resolve.Present {
		t.Fatal(rt2)
	}
	out, err := BuildStaticMAC(rt2.Value, "l2", source)
	if err != nil || out.MAC != "02:00:00:00:00:01" || out.Flood || out.Context != "l2" || out.RemoteSrc != "2001:db8::1" || out.Segments[0] != "fd00:2::1" {
		t.Fatalf("static: %+v %v", out, err)
	}
	entry.Path.NLRI.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).MacAddress[5] = 2
	if rt2.Value.MAC[5] != 1 {
		t.Fatal("projection borrowed MAC")
	}
	rt3 := RT3Selector().Project(fixture(t, true))
	if rt3.State != resolve.Present {
		t.Fatal(rt3)
	}
	out, err = BuildFlood(rt3.Value, "l2", source)
	if err != nil || !out.Flood || out.MAC != "" || out.SrcAddr != source.String() {
		t.Fatalf("flood: %+v %v", out, err)
	}
	if RT2Selector().Project(fixture(t, true)).State != resolve.Missing || RT3Selector().Project(fixture(t, false)).State != resolve.Missing {
		t.Fatal("unrelated route kinds were invalid")
	}
}

func TestUnsupportedEVPNProfiles(t *testing.T) {
	base := RT2Selector().Project(fixture(t, false)).Value
	source := netip.MustParseAddr("fd00:feed::1")
	for name, mutate := range map[string]func(*RT2){
		"ESI": func(r *RT2) { r.ESI[9] = 1 }, "Ethernet-tag": func(r *RT2) { r.EthernetTag = 1 },
		"multicast-MAC": func(r *RT2) { r.MAC[0] = 1 }, "zero-MAC": func(r *RT2) { r.MAC = [6]byte{} },
		"wrong-behavior":   func(r *RT2) { r.Service.Behavior = uint16(bgp.END_DT2M) },
		"missing-next-hop": func(r *RT2) { r.Remote = netip.Addr{} },
		"transposition":    func(r *RT2) { r.Service.HasStructure = true; r.Service.Structure.TranspositionLength = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if _, err := BuildStaticMAC(r, "l2", source); err == nil {
				t.Fatal("unsupported profile accepted")
			}
		})
	}
	if _, err := BuildStaticMAC(base, "", source); err == nil {
		t.Fatal("missing context accepted")
	}
	entry := fixture(t, false)
	entry.Path.Attributes = entry.Path.Attributes[:1]
	if RT2Selector().Project(entry).State != resolve.Invalid {
		t.Fatal("missing SID accepted")
	}
	entry = fixture(t, false)
	entry.Path.Attributes = append(entry.Path.Attributes, entry.Path.Attributes[0])
	if RT2Selector().Project(entry).State != resolve.Invalid {
		t.Fatal("duplicate next hop accepted")
	}
}
