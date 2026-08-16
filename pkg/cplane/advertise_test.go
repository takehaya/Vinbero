package cplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// fakeAdvertiser records what was originated and withdrawn.
type fakeAdvertiser struct {
	mu        sync.Mutex
	advertise []bgp.VPNRoute
	unicast   []bgp.UnicastRoute
	withdrawn []bgp.RouteKey
	failOn    string // prefix whose advertise fails
}

func (f *fakeAdvertiser) Advertise(_ context.Context, r bgp.VPNRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Prefix == f.failOn {
		return errors.New("simulated advertise failure")
	}
	f.advertise = append(f.advertise, r)
	return nil
}

func (f *fakeAdvertiser) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unicast = append(f.unicast, r)
	return nil
}

func (f *fakeAdvertiser) Withdraw(_ context.Context, key bgp.RouteKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn = append(f.withdrawn, key)
	return nil
}

func (f *fakeAdvertiser) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.advertise), len(f.withdrawn)
}

// unlimited turns the quota off for tests that are about something else.
const unlimited = -1

func vpnRoute(prefix, sid string) AdvertisedRoute {
	return AdvertisedRoute{
		Family:       bgp.FamilyVPNv4,
		RD:           "65000:1",
		Prefix:       prefix,
		SRv6SID:      sid,
		NextHop:      "2001:db8::1",
		RouteTargets: nil,
	}
}

func TestAdvertiseSetOriginates(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	res, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("10.0.2.0/24", "fd00:2::2"),
	}, unlimited)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Created != 2 {
		t.Fatalf("result = %+v, want 2 originated", res)
	}
	if got, _ := adv.counts(); got != 2 {
		t.Fatalf("advertiser saw %d routes, want 2", got)
	}
}

// A route the plugin stops declaring is withdrawn. There is no withdraw
// call precisely so a plugin does not have to remember what it advertised
// in order to retract it -- which is what it cannot do after a restart.
func TestAdvertiseSetWithdrawsWhatIsNoLongerDeclared(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	ctx := context.Background()
	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("10.0.2.0/24", "fd00:2::2"),
	}, unlimited); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	res, err := set.Apply(ctx, ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if res.Pruned != 1 {
		t.Fatalf("result = %+v, want one withdrawal", res)
	}
	_, withdrawn := adv.counts()
	if withdrawn != 1 {
		t.Fatalf("advertiser saw %d withdrawals, want 1", withdrawn)
	}
	if set.LiveCount(ownerA) != 1 {
		t.Fatalf("owner still originates %d routes, want 1", set.LiveCount(ownerA))
	}
}

// gobgp's AddPath silently supersedes, so two owners originating the same
// NLRI would have the second replace the first with no error anywhere. The
// lease is the only thing that catches it.
func TestAdvertiseSetRefusesAnotherOwnersNLRI(t *testing.T) {
	adv := &fakeAdvertiser{}
	leases := NewLeases()
	set := NewAdvertiseSet(adv, leases)
	ctx := context.Background()
	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited); err != nil {
		t.Fatalf("first owner: %v", err)
	}
	_, err := set.Apply(ctx, ownerB, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::9")}, unlimited)
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second owner got %v, want ErrLeaseHeld", err)
	}
	if got, _ := adv.counts(); got != 1 {
		t.Fatalf("the refused declaration still advertised: %d routes", got)
	}
}

// Withdrawals run before advertisements so a route moving between RDs is
// never briefly present twice.
func TestAdvertiseSetWithdrawsBeforeAdvertising(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	ctx := context.Background()
	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	moved := vpnRoute("10.0.1.0/24", "fd00:2::1")
	moved.RD = "65000:2"
	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{moved}, unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.withdrawn) != 1 || adv.withdrawn[0].RD != "65000:1" {
		t.Fatalf("withdrawals = %+v, want the old RD", adv.withdrawn)
	}
	if len(adv.advertise) != 2 || adv.advertise[1].RD != "65000:2" {
		t.Fatalf("advertisements = %+v, want the new RD last", adv.advertise)
	}
}

func TestAdvertiseSetWithdrawOwnerRetractsEverything(t *testing.T) {
	adv := &fakeAdvertiser{}
	leases := NewLeases()
	set := NewAdvertiseSet(adv, leases)
	ctx := context.Background()
	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("10.0.2.0/24", "fd00:2::2"),
	}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := set.WithdrawOwner(ctx, ownerA); err != nil {
		t.Fatalf("withdraw owner: %v", err)
	}
	if _, withdrawn := adv.counts(); withdrawn != 2 {
		t.Fatalf("withdrew %d routes, want 2", withdrawn)
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("the owner still originates routes")
	}
	// The NLRIs are free for another owner.
	if err := leases.Acquire(LeaseAdvertise, vpnRoute("10.0.1.0/24", "").key(), ownerB); err != nil {
		t.Errorf("withdrawn NLRI is still leased: %v", err)
	}
}

// A daemon with no BGP session cannot originate, and says so rather than
// accepting a declaration it will never send.
func TestAdvertiseSetWithoutASession(t *testing.T) {
	set := NewAdvertiseSet(nil, NewLeases())
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited); err == nil {
		t.Fatal("a declaration was accepted with no advertiser")
	}
	// Declaring nothing is still fine: it is how a plugin says it wants
	// nothing originated.
	if _, err := set.Apply(context.Background(), ownerA, nil, unlimited); err != nil {
		t.Fatalf("empty declaration: %v", err)
	}
}

func TestAdvertiseSetRejectsMalformed(t *testing.T) {
	set := NewAdvertiseSet(&fakeAdvertiser{}, NewLeases())
	ctx := context.Background()
	tests := []struct {
		name  string
		route AdvertisedRoute
	}{
		{name: "unknown family", route: AdvertisedRoute{Family: "nonsense", Prefix: "10.0.0.0/24"}},
		{name: "no prefix", route: AdvertisedRoute{Family: bgp.FamilyVPNv4, RD: "65000:1"}},
		{name: "vpn without rd", route: AdvertisedRoute{Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", NextHop: "2001:db8::1"}},
		// The daemon has no defensible guess at a next hop: the encap
		// source is a locator address, not necessarily the node's BGP
		// transport address, and picking one silently would advertise a
		// route peers cannot follow.
		{name: "no next hop", route: AdvertisedRoute{Family: bgp.FamilyVPNv4, RD: "65000:1", Prefix: "10.0.0.0/24"}},
		{name: "family a plugin cannot originate", route: AdvertisedRoute{Family: bgp.FamilyEVPN, Prefix: "10.0.0.0/24"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{tt.route}, unlimited); err == nil {
				t.Fatal("a malformed declaration was accepted")
			}
		})
	}
}

func TestAdvertiseSetRejectsDuplicateNLRI(t *testing.T) {
	set := NewAdvertiseSet(&fakeAdvertiser{}, NewLeases())
	_, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("10.0.1.0/24", "fd00:2::2"),
	}, unlimited)
	if err == nil {
		t.Fatal("the same NLRI declared twice was accepted")
	}
}

// The behavior codepoint rides through to the advertiser: that one field
// is what lets a plugin originate a behavior it implements itself.
func TestAdvertiseSetCarriesTheBehaviorCodepoint(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	route := vpnRoute("10.0.1.0/24", "fd00:2::1")
	route.EndpointBehavior = 0xFE01
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{route}, unlimited); err != nil {
		t.Fatalf("apply: %v", err)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.advertise) != 1 || adv.advertise[0].EndpointBehavior != 0xFE01 {
		t.Fatalf("advertised %+v, want the plugin's codepoint", adv.advertise)
	}
}

func TestDecodeAdvertisedRoute(t *testing.T) {
	got, err := DecodeAdvertisedRoute(&v1.PluginAdvertisedRoute{
		Family:           "vpnv4",
		Rd:               "65000:1",
		Prefix:           "10.0.0.0/24",
		Srv6Sid:          "fd00:2::100",
		EndpointBehavior: 0xFE01,
		RouteTargets:     []string{"65000:1"},
		NextHop:          "2001:db8::1",
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Family != bgp.FamilyVPNv4 || got.RD != "65000:1" || got.Prefix != "10.0.0.0/24" {
		t.Fatalf("decoded %+v", got)
	}
	if got.EndpointBehavior != 0xFE01 {
		t.Errorf("behavior = %#x, want 0xFE01", got.EndpointBehavior)
	}
	if len(got.RouteTargets) != 1 {
		t.Errorf("route targets = %v", got.RouteTargets)
	}
}

func TestDecodeAdvertisedRouteRejectsBadInput(t *testing.T) {
	if _, err := DecodeAdvertisedRoute(nil); err == nil {
		t.Error("nil was accepted")
	}
	if _, err := DecodeAdvertisedRoute(&v1.PluginAdvertisedRoute{
		Family: "nonsense", Prefix: "10.0.0.0/24", NextHop: "2001:db8::1",
	}); err == nil {
		t.Error("an unknown family was accepted")
	}
	if _, err := DecodeAdvertisedRoute(&v1.PluginAdvertisedRoute{
		Family: "vpnv4", Rd: "65000:1", Prefix: "10.0.0.0/24",
		NextHop: "2001:db8::1", EndpointBehavior: 0x10000,
	}); err == nil {
		t.Error("a behavior codepoint wider than 16 bits was accepted")
	}
}

// One malformed route must not cost the plugin the routes it already has.
// Apply withdraws before it advertises, so a declaration validated only at
// send time retracts the live set and then fails.
func TestOneBadRouteLeavesTheLiveSetAlone(t *testing.T) {
	ctx := context.Background()
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())

	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	advertised, withdrawn := adv.counts()
	if advertised != 1 {
		t.Fatalf("advertised %d routes, want 1", advertised)
	}

	// The second route is nonsense. The first is unchanged and must stay.
	_, err := set.Apply(ctx, ownerA, []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("not-a-prefix", "fd00:2::2"),
	}, unlimited)
	if err == nil {
		t.Fatal("a declaration containing a malformed prefix was accepted")
	}
	if _, nowWithdrawn := adv.counts(); nowWithdrawn != withdrawn {
		t.Errorf("the failed declaration withdrew %d routes; it must withdraw none",
			nowWithdrawn-withdrawn)
	}
}

// The lease key has to be the NLRI as it goes on the wire. Two spellings
// of one prefix leasing separately would let a second plugin originate a
// route the first already holds, and gobgp's AddPath supersedes silently.
func TestPrefixIsNormalizedBeforeLeasing(t *testing.T) {
	ctx := context.Background()
	adv := &fakeAdvertiser{}
	leases := NewLeases()
	set := NewAdvertiseSet(adv, leases)

	if _, err := set.Apply(ctx, ownerA, []AdvertisedRoute{vpnRoute("10.0.1.0/24", "fd00:2::1")}, unlimited); err != nil {
		t.Fatalf("owner A: %v", err)
	}
	// Same route, spelled with a host bit set.
	_, err := set.Apply(ctx, ownerB, []AdvertisedRoute{vpnRoute("10.0.1.7/24", "fd00:2::9")}, unlimited)
	if err == nil {
		t.Fatal("a second owner took the same NLRI spelled differently")
	}
	var le *LeaseError
	if !errors.As(err, &le) {
		t.Fatalf("error = %v, want a lease conflict", err)
	}
}

// An endpoint behavior travels in the SID TLV, and the encoder builds that
// TLV only when there is a SID. Accepting the pair silently drops the
// codepoint the plugin asked for.
func TestBehaviorWithoutSIDIsRefused(t *testing.T) {
	r := vpnRoute("10.0.1.0/24", "")
	r.EndpointBehavior = 0xFE01
	_, err := normalizeAdvertised(r)
	if err == nil {
		t.Fatal("a behavior with no SID to carry it was accepted")
	}
	if !strings.Contains(err.Error(), "no SRv6 SID") {
		t.Errorf("error does not explain the missing SID: %v", err)
	}
}
