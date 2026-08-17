package cplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Advertiser is the send side a plugin is granted. *gobgp.Session
// satisfies it; narrowing it keeps the plugin path testable without a BGP
// session, and keeps the rest of the session's surface out of reach.
type Advertiser interface {
	Advertise(ctx context.Context, r bgp.VPNRoute) error
	AdvertiseUnicast(ctx context.Context, r bgp.UnicastRoute) error
	Withdraw(ctx context.Context, key bgp.RouteKey) error
}

// RouteValidator is an Advertiser that can tell whether it could encode a
// route without sending it.
//
// Apply withdraws before it advertises, so a route that only fails inside
// the encoder has already cost the plugin its other routes by the time
// anyone finds out. Asking the encoder up front is what makes a bad
// declaration refuse the whole set instead of applying half of it, and
// asking the encoder rather than reimplementing its rules is what keeps
// the answer the same as the one the send path will give.
//
// It is optional: an Advertiser without it is used as before, and the
// checks in normalizeAdvertised still apply.
type RouteValidator interface {
	ValidateVPNRoute(r bgp.VPNRoute) error
	ValidateUnicastRoute(r bgp.UnicastRoute) error
	// CanonicalRD renders a route distinguisher the one way the wire has
	// it. The lease key contains the RD, so two spellings of one RD --
	// 65000:1 and 065000:0001 are the same on the wire -- would lease
	// separately and let a second plugin originate an NLRI the first
	// already holds, which AddPath then supersedes with no error anywhere.
	CanonicalRD(rd string) (string, error)
}

// maxRouteTargets bounds the route targets on one route.
//
// They travel in a single extended communities attribute, whose length
// field is 16 bits and whose members are 8 bytes each; a peer will refuse
// an update that overruns it, and refusing an update is how a session ends.
// Real VPN routes carry a handful.
const maxRouteTargets = 128

// AdvertisedRoute is one route an owner wants originated.
type AdvertisedRoute struct {
	Family  bgp.Family
	RD      string
	Prefix  string
	SRv6SID string
	// EndpointBehavior is the codepoint to advertise in the SID TLV. Zero
	// leaves the family's default.
	EndpointBehavior uint16
	RouteTargets     []string
	NextHop          string
}

// key identifies the route for leasing and for diffing one declaration
// against the last. It is the NLRI, not the attributes: two declarations
// of the same NLRI with different SIDs are an update, not two routes.
func (r AdvertisedRoute) key() string {
	return strings.Join([]string{string(r.Family), r.RD, r.Prefix}, "\x1f")
}

// routeKey renders the withdrawal key for this route.
func (r AdvertisedRoute) routeKey() bgp.RouteKey {
	return bgp.RouteKey{Family: r.Family, Prefix: r.Prefix, RD: r.RD}
}

// AdvertiseSet reconciles what one owner has originated.
//
// Advertising is a desired set for the same reason the data-plane writes
// are: a plugin that has to remember which routes it previously advertised
// in order to retract them is a plugin that gets it wrong after a restart.
// Declaring the set it wants is a statement that survives having no
// memory, and what it stops declaring is withdrawn.
//
// The set is tracked here rather than read back from BGP because the rib
// holds this node's own advertisements without saying which of them came
// from which plugin. Ownership lives with the owner tag, as everywhere
// else.
type AdvertiseSet struct {
	adv    Advertiser
	leases *Leases

	mu sync.Mutex
	// live maps owner -> key -> route, the routes each owner has
	// originated and not withdrawn.
	live map[bpf.OwnerTag]map[string]AdvertisedRoute

	// producerMu guards the per-owner advertiser views, which are built on
	// first use and kept because the session tracks paths by the name they
	// were advertised under.
	producerMu sync.Mutex
	namer      func(producer string) Advertiser
	producers  map[bpf.OwnerTag]Advertiser
}

// NewAdvertiseSet builds the tracker. adv may be nil, in which case
// declaring any route reports that the daemon cannot advertise -- which is
// the honest answer on a daemon with BGP disabled.
func NewAdvertiseSet(adv Advertiser, leases *Leases) *AdvertiseSet {
	return &AdvertiseSet{
		adv:    adv,
		leases: leases,
		live:   make(map[bpf.OwnerTag]map[string]AdvertisedRoute),
	}
}

// Apply makes owner's advertised routes match desired exactly.
//
// Withdrawals run before advertisements, so a route moving between RDs is
// never briefly present twice, and both phases run in a stable order so a
// retry repeats the same sequence.
func (a *AdvertiseSet) Apply(ctx context.Context, owner bpf.OwnerTag, desired []AdvertisedRoute, quota int) (ApplyResult, error) {
	var res ApplyResult
	if owner == "" {
		return res, bpf.ErrEmptyOwner
	}
	if len(desired) > 0 && a.adv == nil {
		return res, errors.New("advertise: this daemon has no BGP session to originate through")
	}

	// Every route is validated and normalized before anything is
	// withdrawn. The withdraw phase runs first, so a single malformed
	// route found later would take the live routes with it and leave the
	// plugin advertising nothing -- a typo in one declaration is not a
	// reason to retract the rest.
	adv := a.advertiserFor(owner)
	byKey := make(map[string]AdvertisedRoute, len(desired))
	keys := make([]string, 0, len(desired))
	for _, r := range desired {
		r, err := normalizeAdvertised(r)
		if err != nil {
			return res, err
		}
		// Canonicalized and checked by the encoder before the key is
		// built, so the key is the NLRI as it goes on the wire and a route
		// the encoder would refuse is refused here, before the withdraw
		// phase has touched anything.
		if r, err = a.canonicalize(r); err != nil {
			return res, err
		}
		k := r.key()
		if _, dup := byKey[k]; dup {
			return res, fmt.Errorf("advertise: %s %s declared twice", r.Family, r.Prefix)
		}
		byKey[k] = r
		keys = append(keys, k)
	}

	if cap, bounded := limitOf(quota); bounded && len(keys) > cap {
		return res, &QuotaError{What: "advertised routes", Declared: len(keys), Quota: cap}
	}

	// The lease is the only thing standing between two owners originating
	// the same NLRI: gobgp's AddPath silently supersedes, so the second
	// advertisement would replace the first with no error anywhere.
	if a.leases != nil {
		if _, err := a.leases.AcquireAll(LeaseAdvertise, keys, owner); err != nil {
			return res, err
		}
	}

	a.mu.Lock()
	current := a.live[owner]
	if current == nil {
		current = make(map[string]AdvertisedRoute)
		a.live[owner] = current
	}
	stale := make([]string, 0, len(current))
	for k := range current {
		if _, keep := byKey[k]; !keep {
			stale = append(stale, k)
		}
	}
	a.mu.Unlock()
	sort.Strings(stale)

	for _, k := range stale {
		a.mu.Lock()
		route := current[k]
		a.mu.Unlock()
		if err := adv.Withdraw(ctx, route.routeKey()); err != nil {
			// Nothing declared was originated yet, so those leases
			// describe NLRIs this owner does not advertise. Holding them
			// would deny another plugin a route this one never took.
			a.releaseUnoriginated(keys, current, owner)
			return res, fmt.Errorf("advertise: withdraw %s %s: %w", route.Family, route.Prefix, err)
		}
		a.mu.Lock()
		delete(current, k)
		a.mu.Unlock()
		if a.leases != nil {
			a.leases.Release(LeaseAdvertise, k, owner)
		}
		res.Pruned++
	}

	sort.Strings(keys)
	for _, k := range keys {
		route := byKey[k]
		if err := a.originate(ctx, adv, route); err != nil {
			// Release the leases of what was not advertised, so a key this
			// owner does not hold cannot deny another one.
			a.releaseUnoriginated(keys[indexOf(keys, k):], current, owner)
			return res, fmt.Errorf("advertise: %s %s: %w", route.Family, route.Prefix, err)
		}
		a.mu.Lock()
		_, existed := current[k]
		current[k] = route
		a.mu.Unlock()
		if existed {
			res.Updated++
		} else {
			res.Created++
		}
	}
	return res, nil
}

// releaseUnoriginated frees the leases on declared keys this owner does
// not actually advertise, leaving alone the ones it already originates.
func (a *AdvertiseSet) releaseUnoriginated(keys []string, current map[string]AdvertisedRoute, owner bpf.OwnerTag) {
	if a.leases == nil {
		return
	}
	a.mu.Lock()
	live := make(map[string]struct{}, len(current))
	for k := range current {
		live[k] = struct{}{}
	}
	a.mu.Unlock()
	for _, k := range keys {
		if _, ok := live[k]; ok {
			continue
		}
		a.leases.Release(LeaseAdvertise, k, owner)
	}
}

// WithdrawOwner retracts everything an owner has originated. It is what
// unregistering runs.
func (a *AdvertiseSet) WithdrawOwner(ctx context.Context, owner bpf.OwnerTag) error {
	a.mu.Lock()
	current := a.live[owner]
	keys := make([]string, 0, len(current))
	for k := range current {
		keys = append(keys, k)
	}
	a.mu.Unlock()
	sort.Strings(keys)

	var firstErr error
	for _, k := range keys {
		a.mu.Lock()
		route, ok := current[k]
		a.mu.Unlock()
		if !ok {
			continue
		}
		if adv := a.advertiserFor(owner); adv != nil {
			if err := adv.Withdraw(ctx, route.routeKey()); err != nil {
				// Still advertised, so it is still this owner's. Forgetting
				// it here would leave a route on the wire that nothing
				// tracks, with the state behind it about to be removed --
				// a blackhole -- and would free the lease for another
				// plugin to originate the same NLRI over the top of it.
				if firstErr == nil {
					firstErr = fmt.Errorf("advertise: withdraw %s %s: %w", route.Family, route.Prefix, err)
				}
				continue
			}
		}
		a.mu.Lock()
		delete(current, k)
		a.mu.Unlock()
		if a.leases != nil {
			a.leases.Release(LeaseAdvertise, k, owner)
		}
	}
	a.mu.Lock()
	if len(current) == 0 {
		delete(a.live, owner)
	}
	a.mu.Unlock()
	return firstErr
}

// LiveCount is how many routes an owner currently originates.
func (a *AdvertiseSet) LiveCount(owner bpf.OwnerTag) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.live[owner])
}

// advertiserFor returns the send side this owner originates through.
//
// Each owner gets a view naming itself when the advertiser can provide
// one. The session keeps one local path per NLRI and refuses a takeover
// between different producers, so naming them apart is what stops one
// plugin's withdraw from deleting a route another plugin still wants --
// the barrier under the lease, which matters exactly when the lease has
// been given up by mistake.
func (a *AdvertiseSet) advertiserFor(owner bpf.OwnerTag) Advertiser {
	if a.namer == nil {
		return a.adv
	}
	a.producerMu.Lock()
	defer a.producerMu.Unlock()
	if named, held := a.producers[owner]; held {
		return named
	}
	if a.producers == nil {
		a.producers = make(map[bpf.OwnerTag]Advertiser)
	}
	named := a.namer(string(owner))
	if named == nil {
		named = a.adv
	}
	a.producers[owner] = named
	return named
}

// NameProducers makes each owner originate through a view of its own.
//
// The daemon supplies it because only the daemon knows what its BGP
// session can do. Without it every owner shares one identity and the
// session cannot tell their routes apart.
func (a *AdvertiseSet) NameProducers(namer func(producer string) Advertiser) {
	a.producerMu.Lock()
	defer a.producerMu.Unlock()
	a.namer = namer
	a.producers = nil
}

// canonicalize puts a route in the form the wire has it and asks the
// advertiser whether it could encode it, when it is able to answer.
func (a *AdvertiseSet) canonicalize(r AdvertisedRoute) (AdvertisedRoute, error) {
	v, ok := a.adv.(RouteValidator)
	if !ok {
		return r, nil
	}
	if r.RD != "" {
		rd, err := v.CanonicalRD(r.RD)
		if err != nil {
			return r, fmt.Errorf("advertise: %s %s route distinguisher %q: %w", r.Family, r.Prefix, r.RD, err)
		}
		r.RD = rd
	}
	var err error
	switch r.Family {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		err = v.ValidateVPNRoute(bgp.VPNRoute{
			Family:           r.Family,
			RD:               r.RD,
			Prefix:           r.Prefix,
			SRv6SID:          r.SRv6SID,
			RTs:              r.RouteTargets,
			NextHop:          r.NextHop,
			EndpointBehavior: r.EndpointBehavior,
		})
	case bgp.FamilyIPv6Unicast:
		err = v.ValidateUnicastRoute(bgp.UnicastRoute{Prefix: r.Prefix, NextHop: r.NextHop})
	}
	if err != nil {
		return r, fmt.Errorf("advertise: %s %s cannot be originated: %w", r.Family, r.Prefix, err)
	}
	return r, nil
}

// originate pushes one route out, choosing the call that matches its
// family.
func (a *AdvertiseSet) originate(ctx context.Context, adv Advertiser, r AdvertisedRoute) error {
	switch r.Family {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		return adv.Advertise(ctx, bgp.VPNRoute{
			Family:           r.Family,
			RD:               r.RD,
			Prefix:           r.Prefix,
			SRv6SID:          r.SRv6SID,
			RTs:              r.RouteTargets,
			NextHop:          r.NextHop,
			EndpointBehavior: r.EndpointBehavior,
		})
	case bgp.FamilyIPv6Unicast:
		return adv.AdvertiseUnicast(ctx, bgp.UnicastRoute{
			Prefix:  r.Prefix,
			NextHop: r.NextHop,
		})
	default:
		return fmt.Errorf("family %s cannot be originated by a plugin", r.Family)
	}
}

// normalizeAdvertised rejects a declaration the advertiser could not send,
// and returns it in the canonical form the lease and the diff use.
//
// Everything the encoder will parse is parsed here instead, because the
// encoder runs after the withdraw phase: a value that only fails there
// turns one bad route into a partial apply.
func normalizeAdvertised(r AdvertisedRoute) (AdvertisedRoute, error) {
	if !r.Family.Valid() {
		return r, fmt.Errorf("advertise: unknown family %q", r.Family)
	}
	if r.Prefix == "" {
		return r, fmt.Errorf("advertise: %s route has no prefix", r.Family)
	}
	// The lease key is the NLRI, so it has to be the NLRI as it goes on
	// the wire. 10.0.0.1/24 and 10.0.0.0/24 are the same route to BGP but
	// different strings, and leasing the string would let a second plugin
	// take a lease on a route the first is already originating and
	// supersede it with no error anywhere.
	pfx, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return r, fmt.Errorf("advertise: %s prefix %q: %w", r.Family, r.Prefix, err)
	}
	r.Prefix = pfx.Masked().String()
	switch r.Family {
	case bgp.FamilyVPNv4:
		if !pfx.Addr().Is4() {
			return r, fmt.Errorf("advertise: %s prefix %s is not IPv4", r.Family, r.Prefix)
		}
	case bgp.FamilyVPNv6, bgp.FamilyIPv6Unicast:
		if pfx.Addr().Is4() {
			return r, fmt.Errorf("advertise: %s prefix %s is not IPv6", r.Family, r.Prefix)
		}
	}
	switch r.Family {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		if r.RD == "" {
			return r, fmt.Errorf("advertise: %s %s has no route distinguisher", r.Family, r.Prefix)
		}
		// Route targets go out as one extended communities attribute, and
		// a BGP attribute is not unbounded: enough of them and the update
		// this node sends is one its peers refuse, which costs the session
		// rather than the route. The limit is far above any real VPN.
		if len(r.RouteTargets) > maxRouteTargets {
			return r, fmt.Errorf("advertise: %s %s declares %d route targets, limit %d",
				r.Family, r.Prefix, len(r.RouteTargets), maxRouteTargets)
		}
		if r.SRv6SID != "" {
			sid, err := netip.ParseAddr(r.SRv6SID)
			if err != nil || !sid.Is6() {
				return r, fmt.Errorf("advertise: %s %s SRv6 SID %q is not an IPv6 address", r.Family, r.Prefix, r.SRv6SID)
			}
			r.SRv6SID = sid.String()
		}
		// A behavior with no SID has nowhere to go: the encoder builds the
		// SID TLV only when there is a SID, so the codepoint the plugin
		// asked for would be dropped and the commit would still succeed.
		if r.EndpointBehavior != 0 && r.SRv6SID == "" {
			return r, fmt.Errorf("advertise: %s %s declares endpoint behavior %d but no SRv6 SID to carry it",
				r.Family, r.Prefix, r.EndpointBehavior)
		}
	case bgp.FamilyIPv6Unicast:
		// An IPv6 unicast advertisement carries neither, so accepting them
		// would drop what the plugin asked for while reporting success.
		if r.SRv6SID != "" {
			return r, fmt.Errorf("advertise: %s %s carries no SRv6 SID; %s cannot be advertised with it",
				r.Family, r.Prefix, r.SRv6SID)
		}
		if r.EndpointBehavior != 0 {
			return r, fmt.Errorf("advertise: %s %s carries no SID TLV, so endpoint behavior %d cannot be advertised with it",
				r.Family, r.Prefix, r.EndpointBehavior)
		}
		if r.RD != "" {
			return r, fmt.Errorf("advertise: %s %s is not a VPN route, so it cannot carry route distinguisher %q",
				r.Family, r.Prefix, r.RD)
		}
		if len(r.RouteTargets) > 0 {
			return r, fmt.Errorf("advertise: %s %s is not a VPN route, so it cannot carry route targets",
				r.Family, r.Prefix)
		}
	default:
		return r, fmt.Errorf("advertise: family %s cannot be originated by a plugin", r.Family)
	}
	// The next hop is where a peer is told to send the traffic, and the
	// daemon has no defensible guess at it: the encap source is a locator
	// address, not necessarily the BGP transport address, and picking one
	// silently would advertise a route peers cannot follow. Say so here
	// rather than letting it surface as a parse error deep in the encoder.
	if r.NextHop == "" {
		return r, fmt.Errorf("advertise: %s %s has no next hop", r.Family, r.Prefix)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return r, fmt.Errorf("advertise: %s %s next hop %q: %w", r.Family, r.Prefix, r.NextHop, err)
	}
	r.NextHop = nh.String()
	return r, nil
}

// indexOf finds a key's position in a sorted slice.
func indexOf(keys []string, want string) int {
	for i, k := range keys {
		if k == want {
			return i
		}
	}
	return len(keys)
}

// DecodeAdvertisedRoute converts a plugin's declaration into the internal
// form.
func DecodeAdvertisedRoute(in *v1.PluginAdvertisedRoute) (AdvertisedRoute, error) {
	if in == nil {
		return AdvertisedRoute{}, errors.New("advertise: nil route")
	}
	fam, err := bgp.ParseFamily(in.GetFamily())
	if err != nil {
		return AdvertisedRoute{}, fmt.Errorf("advertise: %w", err)
	}
	if in.GetEndpointBehavior() > 0xFFFF {
		return AdvertisedRoute{}, fmt.Errorf("advertise: endpoint behavior %d does not fit 16 bits",
			in.GetEndpointBehavior())
	}
	out := AdvertisedRoute{
		Family:           fam,
		RD:               in.GetRd(),
		Prefix:           in.GetPrefix(),
		SRv6SID:          in.GetSrv6Sid(),
		EndpointBehavior: uint16(in.GetEndpointBehavior()),
		RouteTargets:     append([]string(nil), in.GetRouteTargets()...),
		NextHop:          in.GetNextHop(),
	}
	return normalizeAdvertised(out)
}
