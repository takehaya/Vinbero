package gobgp

import (
	"bytes"
	"context"
	"testing"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestProducerRejectsRDAlias(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	r := bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100", SRv6SID: "fd00:1::", NextHop: "2001:db8::1"}
	alias := r
	alias.RD = "065000:00100"
	a, err := encodeVPNPath(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodeVPNPath(alias)
	if err != nil {
		t.Fatal(err)
	}
	aw, err := a.Nlri.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bw, err := b.Nlri.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aw, bw) {
		t.Fatal("test requires identical NLRI bytes")
	}
	plugin := s.AsProducer("cplane:test")
	operator := s.AsProducer(ProducerOperator)
	if err := plugin.Advertise(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := operator.Advertise(context.Background(), alias); err == nil {
		t.Fatal("operator was allowed to replace plugin NLRI using an equivalent RD spelling")
	}
}

func TestProducerPrefixAliasesAndWithdrawal(t *testing.T) {
	for _, tc := range []struct {
		family        bgp.Family
		prefix, alias string
	}{
		{bgp.FamilyVPNv4, "10.0.0.128/25", "10.0.0.255/25"},
		{bgp.FamilyVPNv6, "2001:db8:1::/64", "2001:0db8:0001::1/64"},
		{bgp.FamilyIPv6Unicast, "2001:db8:1::/64", "2001:0db8:0001::1/64"},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			s := newTestSession(t)
			startTestSession(t, s)
			owner, other := s.AsProducer("cplane:owner"), s.AsProducer(ProducerOperator)
			advertise := func(p *ProducerSession, prefix string) error {
				if tc.family == bgp.FamilyIPv6Unicast {
					return p.AdvertiseUnicast(context.Background(), bgp.UnicastRoute{Prefix: prefix, NextHop: "2001:db8::1"})
				}
				return p.Advertise(context.Background(), bgp.VPNRoute{Family: tc.family, Prefix: prefix, RD: "65000:100", NextHop: "2001:db8::1", SRv6SID: "fd00:1::"})
			}
			if err := advertise(owner, tc.prefix); err != nil {
				t.Fatal(err)
			}
			if err := advertise(other, tc.alias); err == nil {
				t.Fatal("another producer replaced the same wire prefix")
			}
			alias := bgp.RouteKey{Family: tc.family, Prefix: tc.alias, RD: "065000:00100"}
			if err := other.Withdraw(context.Background(), alias); err != nil {
				t.Fatal(err)
			}
			count := func() int {
				n := 0
				rf, err := vinberoFamilyToAPI(tc.family)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.bgpServer().ListPath(apiutil.ListPathRequest{TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL, Family: rf}, func(_ gobgppkt.NLRI, paths []*apiutil.Path) { n += len(paths) }); err != nil {
					t.Fatal(err)
				}
				return n
			}
			if n := count(); n != 1 {
				t.Fatalf("foreign withdrawal changed RIB: %d paths", n)
			}
			if err := owner.Withdraw(context.Background(), alias); err != nil {
				t.Fatal(err)
			}
			if n := count(); n != 0 {
				t.Fatalf("alias withdrawal left %d paths", n)
			}
		})
	}
}
