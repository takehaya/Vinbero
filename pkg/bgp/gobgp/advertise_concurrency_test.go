package gobgp

import (
	"context"
	"fmt"
	"sync"
	"testing"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Each caller advertises and then withdraws the same NLRI. The GoBGP RIB,
// UUID ledger and producer claim must finish empty together, even when another
// caller's AddPath supersedes the UUID a withdrawal was about to use.
func TestAdvertisementConcurrentWithdrawAndReadvertise(t *testing.T) {
	ctx := context.Background()
	r := bgp.EVPNRoute{
		RD: "65000:100", RTs: []string{"65000:100"}, EthernetTag: 5,
		MAC: "aa:bb:cc:00:00:01", NextHop: "2001:db8::1", SRv6SID: "fd00:2:2:d2::",
		ESI: [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, ESImportRT: "aa:bb:cc:dd:ee:ff",
	}
	policy := advSRPolicy(100, 1, 200, "2001:db8::2", "2001:db8::1", "fd00:200:0:1::")
	unicastKey := bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: "2001:db8:dead::/64"}
	cases := []struct {
		name     string
		encode   func() (*apiutil.Path, error)
		key      bgp.RouteKey
		producer string
		withdraw func(*Session) error
	}{
		{
			name: "vinbero", key: unicastKey,
			encode: func() (*apiutil.Path, error) {
				return encodeUnicastPath(bgp.UnicastRoute{Prefix: unicastKey.Prefix, NextHop: "2001:db8::1"})
			},
			withdraw: func(s *Session) error { return s.Withdraw(ctx, unicastKey) },
		},
		{
			name: "plugin", key: unicastKey, producer: "plugin:test",
			encode: func() (*apiutil.Path, error) {
				return encodeUnicastPath(bgp.UnicastRoute{Prefix: unicastKey.Prefix, NextHop: "2001:db8::1"})
			},
			withdraw: func(s *Session) error { return s.withdrawAs(ctx, unicastKey, "plugin:test") },
		},
		{
			name: "EVPN_RT2", key: evpnAdvKey(r.RD, r.EthernetTag, r.MAC),
			encode: func() (*apiutil.Path, error) { return encodeEVPNMacPath(r) },
			withdraw: func(s *Session) error {
				return s.WithdrawEVPNMac(ctx, bgp.EVPNMACKey{RD: r.RD, EthernetTag: r.EthernetTag, MAC: r.MAC})
			},
		},
		{
			name: "EVPN_RT3", key: evpnImetKey(r.RD, r.EthernetTag),
			encode: func() (*apiutil.Path, error) { return encodeEVPNMulticastPath(r) },
			withdraw: func(s *Session) error {
				return s.WithdrawEVPNInclusiveMulticast(ctx, bgp.EVPNMcastKey{RD: r.RD, EthernetTag: r.EthernetTag})
			},
		},
		{
			name: "EVPN_RT4", key: evpnEsKey(r.RD, r.ESI),
			encode: func() (*apiutil.Path, error) { return encodeEVPNEthernetSegmentPath(r) },
			withdraw: func(s *Session) error {
				return s.WithdrawEVPNEthernetSegment(ctx, bgp.EVPNESKey{RD: r.RD, ESI: r.ESI})
			},
		},
		{
			name: "EVPN_RT1", key: evpnAdKey(r.RD, r.ESI, r.EthernetTag),
			encode: func() (*apiutil.Path, error) { return encodeEVPNEthernetADPath(r) },
			withdraw: func(s *Session) error {
				return s.WithdrawEVPNEthernetAD(ctx, bgp.EVPNADKey{RD: r.RD, ESI: r.ESI, EthernetTag: r.EthernetTag})
			},
		},
		{
			name: "SRPolicy", key: srPolicyAdvKey(policy.Color, policy.Endpoint, 1),
			encode: func() (*apiutil.Path, error) { return encodeSRPolicyPath(policy) },
			withdraw: func(s *Session) error {
				return s.WithdrawPolicy(ctx, bgp.SRPolicyKey{Color: policy.Color, Endpoint: policy.Endpoint, Distinguisher: 1})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSession(t)
			startTestSession(t, s)
			path, err := tc.encode()
			if err != nil {
				t.Fatal(err)
			}
			const callers, iterations = 8, 16
			start := make(chan struct{})
			errs := make(chan error, callers)
			var wg sync.WaitGroup
			for range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for i := range iterations {
						if err := s.addAndTrackAs(s.bgpServer(), path, tc.key, tc.producer); err != nil {
							errs <- fmt.Errorf("advertise iteration %d: %w", i, err)
							return
						}
						if err := tc.withdraw(s); err != nil {
							errs <- fmt.Errorf("withdraw iteration %d: %w", i, err)
							return
						}
					}
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			s.advMu.Lock()
			tracked, claimed := len(s.advertised), len(s.producers)
			s.advMu.Unlock()
			if tracked != 0 || claimed != 0 {
				t.Errorf("ledger after withdrawals: %d UUIDs, %d owners; want both empty", tracked, claimed)
			}
			var paths int
			err = s.bgpServer().ListPath(apiutil.ListPathRequest{
				TableType: gobgpapi.TableType_TABLE_TYPE_GLOBAL, Family: path.Family,
			}, func(_ gobgppkt.NLRI, p []*apiutil.Path) { paths += len(p) })
			if err != nil {
				t.Fatal(err)
			}
			if paths != 0 {
				t.Errorf("GoBGP still holds %d paths after all withdrawals", paths)
			}
		})
	}
}

func TestAdvertisementFailurePreservesOwnership(t *testing.T) {
	s := newTestSession(t)
	startTestSession(t, s)
	srv := s.bgpServer()
	key := bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: "2001:db8:dead::/64"}
	// A failed first AddPath must release its provisional claim.
	if err := s.addAndTrackAs(srv, nil, key, "failed"); err == nil {
		t.Fatal("nil path unexpectedly advertised")
	}
	path, err := encodeUnicastPath(bgp.UnicastRoute{Prefix: key.Prefix, NextHop: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addAndTrackAs(srv, path, key, "owner"); err != nil {
		t.Fatalf("failed claim blocked another producer: %v", err)
	}
	s.advMu.Lock()
	id := s.advertised[key]
	s.advMu.Unlock()
	assertOwned := func() {
		t.Helper()
		s.advMu.Lock()
		defer s.advMu.Unlock()
		if s.advertised[key] != id || s.producers[key] != "owner" {
			t.Fatalf("failed operation changed the live UUID or owner")
		}
	}
	if err := s.addAndTrackAs(srv, nil, key, "owner"); err == nil {
		t.Fatal("nil replacement path unexpectedly advertised")
	}
	assertOwned()
	// Remove the actual path behind the ledger to force a GoBGP delete error.
	if err := srv.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{path}}); err != nil {
		t.Fatal(err)
	}
	if err := s.withdrawAs(context.Background(), key, "owner"); err == nil {
		t.Fatal("withdrawal of a missing UUID unexpectedly succeeded")
	}
	assertOwned()
}
