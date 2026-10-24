package gobgppath

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func TestEncodeDecodePacketPreservesAttributes(t *testing.T) {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	vpn, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"), *bgp.NewMPLSLabelStack(100), rd)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		family bgp.Family
		nlri   bgp.NLRI
	}{
		"unicast": {bgp.RF_IPv6_UC, packetPrefix(t, "2001:db8::/48")},
		"vpn":     {bgp.RF_IPv4_VPN, vpn},
		"mup":     {bgp.RF_MUP_IPv4, bgp.NewMUPDirectSegmentDiscoveryRoute(rd, netip.MustParseAddr("192.0.2.1"))},
	} {
		t.Run(name, func(t *testing.T) {
			unknown := bgp.NewPathAttributeUnknown(bgp.BGP_ATTR_FLAG_OPTIONAL|bgp.BGP_ATTR_FLAG_TRANSITIVE, 250, []byte{1, 2, 3})
			attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), unknown,
				bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(0, 0), bgp.NewMUPExtended(0, 0)})}
			packet, err := Encode(tt.family, tt.nlri, attrs)
			if err != nil {
				t.Fatal(err)
			}
			if len(packet.RouteKey) != 0 || packet.Metadata.PeerASN != 0 {
				t.Fatal("outgoing path invented received identity")
			}
			decoded, err := DecodePacket(packet)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.NLRI.String() != tt.nlri.String() || len(decoded.Attributes) != len(attrs) {
				t.Fatalf("roundtrip: %+v", decoded)
			}
			again, err := Encode(tt.family, decoded.NLRI, decoded.Attributes)
			if err != nil || !bytes.Equal(again.NLRI, packet.NLRI) || !reflect.DeepEqual(again.Attributes, packet.Attributes) {
				t.Fatalf("wire changed on roundtrip: %v", err)
			}
			// Both directions own buffers, including unknown attribute payloads.
			unknown.Value[0] = 9
			packet.Attributes[1][len(packet.Attributes[1])-1] = 9
			if got := decoded.Attributes[1].(*bgp.PathAttributeUnknown).Value; !bytes.Equal(got, []byte{1, 2, 3}) {
				t.Fatalf("borrowed bytes: %v", got)
			}
		})
	}
}

func TestEncodeDoesNotMutateBorrowedTunnel(t *testing.T) {
	tlv := &bgp.TunnelEncapSubTLVUnknown{TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{Type: 250}, Value: []byte{1, 2, 3}}
	attr := &bgp.PathAttributeTunnelEncap{Value: []*bgp.TunnelEncapTLV{{Type: bgp.TUNNEL_TYPE_SR_POLICY, Value: []bgp.TunnelEncapSubTLVInterface{tlv}}}}
	nlri := packetPrefix(t, "2001:db8::/48")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := Encode(bgp.RF_IPv6_UC, nlri, []bgp.PathAttributeInterface{attr}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if tlv.Length != 0 || attr.Value[0].Length != 0 || !bytes.Equal(tlv.Value, []byte{1, 2, 3}) {
		t.Fatal("serializer mutated borrowed graph")
	}
}

func TestEncodeRejectsNilAndReturnsNoPartialPacket(t *testing.T) {
	nlri := packetPrefix(t, "192.0.2.0/24")
	var typedNil *bgp.IPAddrPrefix
	var nilAttr *bgp.PathAttributeOrigin
	for _, n := range []bgp.NLRI{nil, typedNil} {
		if p, err := Encode(bgp.RF_IPv4_UC, n, nil); p != nil || !errors.Is(err, ErrEncoding) {
			t.Fatalf("nil NLRI accepted: %v %v", p, err)
		}
	}
	for _, a := range []bgp.PathAttributeInterface{nil, nilAttr} {
		if p, err := Encode(bgp.RF_IPv4_UC, nlri, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), a}); p != nil || !errors.Is(err, ErrEncoding) {
			t.Fatalf("partial output: %v %v", p, err)
		}
	}
}

func TestDecodePacketWithoutIdentityAndWithdrawCompatibility(t *testing.T) {
	p := &cplane.BGPPath{Codec: cplane.BGPPathCodec, AFI: 1, SAFI: 1, NLRI: []byte{24, 192, 0, 2}, Attributes: [][]byte{{64, 1, 1, 0}}}
	if _, err := DecodePacket(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(cplane.Route{BGPPath: p}); !errors.Is(err, ErrMalformed) {
		t.Fatal("received identity validation was bypassed")
	}
	p.RouteKey = []byte("host-key")
	p.Attributes = [][]byte{{64, 1}}
	out, err := Decode(cplane.Route{Peer: "192.0.2.1", Withdraw: true, BGPPath: p})
	if err != nil || !out.Withdraw || len(out.Attributes) != 0 {
		t.Fatalf("withdraw semantics changed: %v %v", out, err)
	}
	if _, err := DecodePacket(p); !errors.Is(err, ErrMalformed) {
		t.Fatal("outgoing malformed attributes accepted")
	}
}

func packetPrefix(t *testing.T, prefix string) *bgp.IPAddrPrefix {
	t.Helper()
	p, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
