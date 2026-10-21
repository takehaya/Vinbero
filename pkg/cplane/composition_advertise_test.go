package cplane

import (
	"net/netip"
	"testing"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
)

func rawAdvertisement(t *testing.T, f gp.Family, n gp.NLRI, attrs ...gp.PathAttributeInterface) *v1.PluginBgpAdvertisement {
	t.Helper()
	p, e := gobgppath.Encode(f, n, attrs)
	if e != nil {
		t.Fatal(e)
	}
	return &v1.PluginBgpAdvertisement{Context: "mobile", Path: &v1.PluginBGPPath{Codec: p.Codec, Afi: uint32(p.AFI), Safi: uint32(p.SAFI), Nlri: p.NLRI, Attributes: p.Attributes}}
}
func unicastAdvertisement(t *testing.T) *v1.PluginBgpAdvertisement {
	t.Helper()
	n, e := gp.NewIPAddrPrefix(netip.MustParsePrefix("fd00:1::/64"))
	if e != nil {
		t.Fatal(e)
	}
	mp, e := gp.NewPathAttributeMpReachNLRI(gp.RF_IPv6_UC, []gp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("2001:db8::1"))
	if e != nil {
		t.Fatal(e)
	}
	return rawAdvertisement(t, gp.RF_IPv6_UC, n, gp.NewPathAttributeOrigin(0), mp)
}
func TestRawAdvertisementProfile(t *testing.T) {
	a := unicastAdvertisement(t)
	r, e := decodeRawAdvertisement(a)
	if e != nil || r.Prefix != "fd00:1::/64" || r.NextHop != "2001:db8::1" {
		t.Fatalf("decode %+v %v", r, e)
	}
	a.Path.Attributes = append(a.Path.Attributes, []byte{0xc0, 99, 1, 1})
	if _, e = decodeRawAdvertisement(a); e == nil {
		t.Fatal("unknown attr silently dropped")
	}
	rd := gp.NewRouteDistinguisherTwoOctetAS(0, 0)
	n, e := gp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"), *gp.NewMPLSLabelStack(0), rd)
	if e != nil {
		t.Fatal(e)
	}
	mp, e := gp.NewPathAttributeMpReachNLRI(gp.RF_IPv4_VPN, []gp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("fd00::1"))
	if e != nil {
		t.Fatal(e)
	}
	sid := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:1::100"), gp.END_DT4, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 0, 0))))
	a = rawAdvertisement(t, gp.RF_IPv4_VPN, n, gp.NewPathAttributeOrigin(0), mp, sid)
	r, e = decodeRawAdvertisement(a)
	if e != nil || r.SRv6SID != "fd00:1::100" || r.SIDStructure.FunctionLen != 16 {
		t.Fatalf("VPN profile %+v %v", r, e)
	}
	a.Path.Attributes = append(a.Path.Attributes, a.Path.Attributes[0])
	if _, e = decodeRawAdvertisement(a); e == nil {
		t.Fatal("duplicate attr accepted")
	}
	a = rawAdvertisement(t, gp.RF_IPv4_VPN, n, gp.NewPathAttributeOrigin(0), mp, sid, rtAttribute("65000:1"))
	if _, e = decodeRawAdvertisement(a); e == nil {
		t.Fatal("guest route target accepted")
	}
}
func TestCompositionAdvertisementDependsOnForwarding(t *testing.T) {
	p, f := compositionOps(t)
	p.caps[wasm.CapAdvertise] = struct{}{}
	p.guard = testGuard()
	p.guard.scope.HeadendPrefixes = append(p.guard.scope.HeadendPrefixes, netip.MustParsePrefix("192.0.2.0/24"))
	p.policy.contexts[0].families = append(p.policy.contexts[0].families, "ipv6_unicast")
	adv := &fakeAdvertiser{}
	p.advertise = NewAdvertiseSet(adv, p.leases)
	m := desiredComposition(1)
	m.BgpAdvertisements = []*v1.PluginBgpAdvertisement{unicastAdvertisement(t)}
	f.failOn = "10.0.0.1/32"
	if e := putComposition(p, m); e == nil {
		t.Fatal("expected forwarding failure")
	}
	if len(adv.unicast) != 0 {
		t.Fatal("advertised before forwarding installed")
	}
	f.failOn = ""
	p.RetryPending()
	if len(adv.unicast) != 1 || p.advertise.LiveCount(p.owner) != 1 {
		t.Fatal("retry did not advertise")
	}
	m.DesiredRevision = 2
	if e := putComposition(p, m); e != nil {
		t.Fatal(e)
	}
	if len(adv.unicast) != 1 || len(adv.withdrawn) != 0 {
		t.Fatal("unchanged set flapped advertisement")
	}
	adv.failWithdraw = "fd00:1::/64"
	if e := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 3}); e == nil {
		t.Fatal("withdraw failure ignored")
	}
	if len(f.uplinks) != 1 || len(f.v4) == 0 {
		t.Fatal("removed forwarding behind failed withdrawal")
	}
	adv.failWithdraw = ""
	p.RetryPending()
	if p.advertise.LiveCount(p.owner) != 0 || len(f.uplinks) != 0 {
		t.Fatal("withdraw retry did not converge")
	}
}
