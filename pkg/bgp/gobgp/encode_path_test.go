package gobgp

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane"
	sdk "github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
)

func pluginBGPFixtures(t *testing.T) map[string]*apiutil.Path {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 7)
	src := netip.MustParseAddr("192.0.2.9")
	sid := gobgppkt.NewPathAttributePrefixSID(gobgppkt.NewSRv6ServiceTLV(
		gobgppkt.TLVTypeSRv6L3Service,
		gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00::1"), gobgppkt.END_DT4,
			gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 0, 0))))
	paths := map[string]*apiutil.Path{
		"isd":        mupPath(gobgppkt.NewMUPInterworkSegmentDiscoveryRoute(rd, netip.MustParsePrefix("192.0.2.0/24"))),
		"dsd":        mupPath(gobgppkt.NewMUPDirectSegmentDiscoveryRoute(rd, src)),
		"st1":        mupPath(gobgppkt.NewMUPType1SessionTransformedRoute(rd, netip.MustParsePrefix("10.0.0.1/32"), teidAddr(0x12345678), 9, src, nil)),
		"st1-source": mupPath(gobgppkt.NewMUPType1SessionTransformedRoute(rd, netip.MustParsePrefix("10.0.0.1/32"), teidAddr(0x12345678), 9, src, &src)),
		"st2":        mupPath(gobgppkt.NewMUPType2SessionTransformedRoute(rd, 40, src, teidAddr(0xab000000))),
		"st2-v6":     {Family: gobgppkt.RF_MUP_IPv6, Nlri: gobgppkt.NewMUPType2SessionTransformedRoute(rd, 136, netip.MustParseAddr("2001:db8::2"), teidAddr(0xab000000))},
		"evpn":       rt2Path(t, "aa:bb:cc:00:00:01", "fd00:2:2:d2::"),
		"sr-policy":  srPolicyPath(t, 1, 2, "2001:db8::1", &gobgppkt.TunnelEncapSubTLVUnknown{TunnelEncapSubTLV: gobgppkt.TunnelEncapSubTLV{Type: 250}, Value: []byte{1, 2, 3}}),
	}
	unicast, err := gobgppkt.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"))
	if err != nil {
		t.Fatal(err)
	}
	paths["unicast"] = &apiutil.Path{Family: gobgppkt.RF_IPv6_UC, Nlri: unicast}
	vpn, err := gobgppkt.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"), *gobgppkt.NewMPLSLabelStack(100), rd)
	if err != nil {
		t.Fatal(err)
	}
	paths["vpn"] = &apiutil.Path{Family: gobgppkt.RF_IPv4_VPN, Nlri: vpn}
	vpn6, err := gobgppkt.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"), *gobgppkt.NewMPLSLabelStack(100), rd)
	if err != nil {
		t.Fatal(err)
	}
	paths["vpn6"] = &apiutil.Path{Family: gobgppkt.RF_IPv6_VPN, Nlri: vpn6}
	rt5, err := gobgppkt.NewEVPNIPPrefixRoute(rd, gobgppkt.EthernetSegmentIdentifier{}, 0, 24,
		netip.MustParseAddr("10.1.0.0"), netip.MustParseAddr("192.0.2.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	paths["evpn-prefix"] = &apiutil.Path{Family: gobgppkt.RF_EVPN, Nlri: rt5}
	evpn, err := gobgppkt.NewEVPNMacIPAdvertisementRoute(rd, gobgppkt.EthernetSegmentIdentifier{}, 0,
		"aa:bb:cc:00:00:01", netip.Addr{}, []uint32{100})
	if err != nil {
		t.Fatal(err)
	}
	paths["evpn"].Nlri = evpn
	tunnel := paths["sr-policy"].Attrs[0].(*gobgppkt.PathAttributeTunnelEncap)
	paths["sr-policy"].Attrs[0] = gobgppkt.NewPathAttributeTunnelEncap(tunnel.Value)
	for _, path := range paths {
		path.PeerAddress = netip.MustParseAddr("2001:db8::7")
		path.PeerID = netip.MustParseAddr("192.0.2.7")
		path.RemoteID, path.LocalID, path.PeerASN, path.Age = 17, 99, 65007, 1700000000
		path.Stale, path.IsFromExternal, path.NoImplicitWithdraw, path.IsNexthopInvalid = true, true, true, true
		reach, err := gobgppkt.NewPathAttributeMpReachNLRI(path.Family, []gobgppkt.PathNLRI{{NLRI: path.Nlri}}, netip.MustParseAddr("2001:db8::7"))
		if err != nil {
			t.Fatal(err)
		}
		path.Attrs = append(path.Attrs, gobgppkt.NewPathAttributeOrigin(0), reach)
		// Keep both a zero segment ID and duplicates; neither is "absent".
		path.Attrs = append(path.Attrs, sid,
			gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{
				gobgppkt.NewMUPExtended(0, 0), gobgppkt.NewMUPExtended(7, 8), gobgppkt.NewMUPExtended(7, 8),
			}), gobgppkt.NewPathAttributeUnknown(0xc0, 253, []byte{1, 2, 3}))
	}
	return paths
}

func decodePluginInput(t *testing.T, evRoute *v1.PluginRoute) sdk.Route {
	t.Helper()
	data, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Route: evRoute}}})
	if err != nil {
		t.Fatal(err)
	}
	events, err := sdk.DecodeEvents(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	return events[0].Route
}

func TestPluginBGPPathRoundTrip(t *testing.T) {
	for name, p := range pluginBGPFixtures(t) {
		t.Run(name, func(t *testing.T) {
			ev, ok := pathToRouteEvent(p)
			if !ok {
				t.Fatal("path not delivered")
			}
			route := decodePluginInput(t, cplane.EncodeRouteEvent(ev))
			decoded, err := gobgppath.Decode(route)
			if err != nil {
				t.Fatal(err)
			}
			nlri, err := decoded.NLRI.Serialize()
			if err != nil || !bytes.Equal(nlri, ev.BGPPath.NLRI) {
				t.Fatalf("NLRI lost: %x, %v", nlri, err)
			}
			if len(decoded.Attributes) != len(p.Attrs) {
				t.Fatalf("attribute count = %d, want %d", len(decoded.Attributes), len(p.Attrs))
			}
			for i, attr := range decoded.Attributes {
				data, err := attr.Serialize()
				if err != nil || !bytes.Equal(data, ev.BGPPath.Attributes[i]) {
					t.Fatalf("attribute %d lost: %x, %v", i, data, err)
				}
			}
			wantMetadata := sdk.BGPPathMetadata{Age: 1700000000, PeerASN: 65007, PeerRouterID: "192.0.2.7", Stale: true,
				IsFromExternal: true, NoImplicitWithdraw: true, IsNexthopInvalid: true, LocalPathID: 99}
			if decoded.Key.PathID != 17 || decoded.Key.Peer != p.PeerAddress.String() || !reflect.DeepEqual(decoded.Metadata, wantMetadata) {
				t.Fatalf("source/metadata lost: %+v", decoded)
			}
			// Metadata and attributes can change without changing the path key.
			before := decoded.Key
			p.Age++
			p.Best = false
			snapshot, _ := pathToRouteEventWithMetadata(p, true)
			updated := decodePluginInput(t, cplane.EncodeRouteEvent(snapshot))
			key, _ := updated.BGPKey()
			if key != before || updated.BGPPath.Metadata.Best == nil || *updated.BGPPath.Metadata.Best {
				t.Fatal("metadata changed identity or absent Best became false")
			}
			// BGP withdraw has only NLRI, but still selects exactly the same path.
			p.Withdrawal, p.Attrs = true, nil
			withdraw, _ := pathToRouteEvent(p)
			removed, err := gobgppath.Decode(decodePluginInput(t, cplane.EncodeRouteEvent(withdraw)))
			if err != nil || removed.Key != before || !removed.Withdraw || len(removed.Attributes) != 0 {
				t.Fatalf("withdraw: %+v, %v", removed, err)
			}
		})
	}
}

type failingPacketAttribute struct{ gobgppkt.PathAttributeUnknown }

func (*failingPacketAttribute) Serialize(...*gobgppkt.MarshallingOption) ([]byte, error) {
	return nil, errors.New("fixture failure")
}

func TestPluginBGPEncodingFailureKeepsIdentityAndLegacyDelivery(t *testing.T) {
	p := pluginBGPFixtures(t)["st1"]
	p.Attrs = append(p.Attrs, &failingPacketAttribute{})
	ev, ok := pathToRouteEvent(p)
	if !ok || ev.MUP == nil || ev.BGPPath.EncodingError == "" || len(ev.BGPPath.Attributes) != 0 {
		t.Fatalf("lost legacy delivery or hid failure: %+v", ev)
	}
	r := decodePluginInput(t, cplane.EncodeRouteEvent(ev))
	if _, ok := r.BGPKey(); !ok {
		t.Fatal("attribute failure erased NLRI identity")
	}
	if _, err := gobgppath.Decode(r); !errors.Is(err, gobgppath.ErrEncoding) {
		t.Fatalf("failure = %v", err)
	}
}

func TestBGPEncodingDoesNotMutateSharedTunnelAttributes(t *testing.T) {
	tlv := &gobgppkt.TunnelEncapSubTLVUnknown{TunnelEncapSubTLV: gobgppkt.TunnelEncapSubTLV{Type: 250, Length: 0}, Value: []byte{1, 2, 3}}
	p := srPolicyPath(t, 1, 2, "2001:db8::1", tlv)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				encodeBGPPath(p, false)
			}
		}()
	}
	wg.Wait()
	if tlv.Length != 0 || !reflect.DeepEqual(tlv.Value, []byte{1, 2, 3}) {
		t.Fatalf("shared RIB TLV mutated: %+v", tlv)
	}
	if raw := encodeBGPPath(p, false); raw.EncodingError != "" {
		t.Fatal(raw.EncodingError)
	}
}

func TestPluginBGPIdentitySeparatesDestinationFromPayload(t *testing.T) {
	for _, name := range []string{"vpn", "vpn6", "evpn", "evpn-prefix", "st1"} {
		t.Run(name, func(t *testing.T) {
			p := pluginBGPFixtures(t)[name]
			route := func() sdk.Route {
				ev, _ := pathToRouteEvent(p)
				return decodePluginInput(t, cplane.EncodeRouteEvent(ev))
			}
			first := route()
			key, ok := first.BGPKey()
			if !ok {
				t.Fatal("missing identity")
			}
			switch n := p.Nlri.(type) {
			case *gobgppkt.LabeledVPNIPAddrPrefix:
				n.Labels = *gobgppkt.NewMPLSLabelStack(200)
			case *gobgppkt.EVPNNLRI:
				switch r := n.RouteTypeData.(type) {
				case *gobgppkt.EVPNMacIPAdvertisementRoute:
					r.Labels[0]++
					r.ESI.Value = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
				case *gobgppkt.EVPNIPPrefixRoute:
					r.Label++
					r.ESI.Value = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
					r.GWIPAddress = netip.MustParseAddr("192.0.2.55")
				}
			case *gobgppkt.MUPNLRI:
				r := n.RouteTypeData.(*gobgppkt.MUPType1SessionTransformedRoute)
				r.QFI++
				r.TEID = teidAddr(0x87654321)
				r.EndpointAddress = netip.MustParseAddr("192.0.2.55")
			}
			updated := route()
			if next, _ := updated.BGPKey(); next != key || bytes.Equal(updated.BGPPath.NLRI, first.BGPPath.NLRI) {
				t.Fatal("non-key update must retain identity and change the full payload")
			}
			p.Withdrawal = true
			if n, ok := p.Nlri.(*gobgppkt.LabeledVPNIPAddrPrefix); ok {
				n.Labels = *gobgppkt.NewMPLSLabelStack(gobgppkt.WITHDRAW_LABEL)
			}
			removed, err := gobgppath.Decode(route())
			if err != nil || removed.Key != key || !removed.Withdraw || len(removed.Attributes) != 0 {
				t.Fatalf("withdraw did not select prior path: %+v, %v", removed, err)
			}
			p.RemoteID++
			other := route()
			if next, _ := other.BGPKey(); next == key {
				t.Fatal("ADD-PATH ID lost")
			}
			previous, _ := other.BGPKey()
			p.PeerAddress = netip.MustParseAddr("2001:db8::8")
			if next, _ := route().BGPKey(); next == previous {
				t.Fatal("peer identity lost")
			}
		})
	}
}

func TestPluginBGPST2EndpointIdentity(t *testing.T) {
	p := pluginBGPFixtures(t)["st2"]
	before := encodeBGPPath(p, false)
	st := p.Nlri.(*gobgppkt.MUPNLRI).RouteTypeData.(*gobgppkt.MUPType2SessionTransformedRoute)
	st.TEID = teidAddr(0xcd000000)
	after := encodeBGPPath(p, false)
	if bytes.Equal(before.RouteKey, after.RouteKey) {
		t.Fatal("ST2 endpoint identifier lost from key")
	}
}

func TestGoBGPAdapterOwnsDecodedData(t *testing.T) {
	p := pluginBGPFixtures(t)["st1"]
	ev, _ := pathToRouteEventWithMetadata(p, true)
	r := decodePluginInput(t, cplane.EncodeRouteEvent(ev))
	decoded, err := gobgppath.Decode(r)
	if err != nil {
		t.Fatal(err)
	}
	nlri := decoded.NLRI.String()
	attrs := make([]string, len(decoded.Attributes))
	for i, a := range decoded.Attributes {
		attrs[i] = a.String()
	}
	clear(r.BGPPath.NLRI)
	for _, a := range r.BGPPath.Attributes {
		clear(a)
	}
	*r.BGPPath.Metadata.Best = true
	if decoded.NLRI.String() != nlri || *decoded.Metadata.Best {
		t.Fatal("adapter borrowed event data")
	}
	for i, a := range decoded.Attributes {
		if a.String() != attrs[i] {
			t.Fatalf("attribute %d borrowed event bytes", i)
		}
	}
}
