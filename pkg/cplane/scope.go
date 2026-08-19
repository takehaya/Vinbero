package cplane

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Scope is the region of each key space a plugin may name.
//
// A capability says what kind of thing a plugin may declare. It does not
// say which ones, and on every surface here a new key can outrank an
// existing one without ever touching it: the headend maps are LPM tries,
// so a longer trigger prefix wins the lookup, and a more specific VPN
// route wins at the receiving PE. Owner tags and leases are per object and
// cannot express that, so the region is stated separately.
//
// The zero value permits nothing. A plugin granted every capability and no
// scope can observe and log, which is a real way to run one and the only
// safe default for a plugin whose operator said nothing about where it may
// write.
type Scope struct {
	// Locators are the locators local SIDs may be allocated from. They
	// also bound the IPv6 unicast prefixes the plugin may advertise: what
	// it legitimately originates there is its own SID space.
	Locators []string
	// VRFs are the VRFs VPN routes may be originated into.
	VRFs []string
	// HeadendPrefixes bound the trigger prefixes headend entries may be
	// installed for. A declared prefix must be contained in one of them.
	HeadendPrefixes []netip.Prefix
	// HeadendSlots and EndpointSlots are the plugin PROG_ARRAY slots this
	// plugin's own data-plane half occupies.
	HeadendSlots  []uint32
	EndpointSlots []uint32
}

// LocatorSource resolves a locator name to what it covers.
// *locator.Manager satisfies it.
type LocatorSource interface {
	Get(name string) (locator.Locator, bool)
}

// VRFBindingSource resolves a VRF name to its BGP binding.
// *vrfbgp.Manager satisfies it.
type VRFBindingSource interface {
	Get(vrfName string) (vrfbgp.Binding, bool)
}

// ParseScope turns the operator-facing form into a Scope, in the canonical
// shape the checks compare against.
func ParseScope(locators, vrfs, headendPrefixes []string, headendSlots, endpointSlots []uint32) (Scope, error) {
	s := Scope{
		Locators:      dedupeStrings(locators),
		VRFs:          dedupeStrings(vrfs),
		HeadendSlots:  dedupeUint32(headendSlots),
		EndpointSlots: dedupeUint32(endpointSlots),
	}
	for _, raw := range headendPrefixes {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return Scope{}, fmt.Errorf("cplane scope: headend prefix %q: %w", raw, err)
		}
		// A 4-in-6 spelling of an IPv4 prefix compares false against every
		// IPv4 trigger prefix, so a scope written that way would silently
		// permit nothing. Refuse the spelling rather than the traffic.
		if pfx.Addr().Is4In6() {
			return Scope{}, fmt.Errorf("cplane scope: headend prefix %q is an IPv4 prefix written in IPv6 form; write it as IPv4", raw)
		}
		s.HeadendPrefixes = append(s.HeadendPrefixes, pfx.Masked())
	}
	sort.Slice(s.HeadendPrefixes, func(i, j int) bool {
		return s.HeadendPrefixes[i].String() < s.HeadendPrefixes[j].String()
	})
	for _, slot := range s.HeadendSlots {
		if err := bpf.ValidatePluginSlot(bpf.MapTypeHeadendV4, slot); err != nil {
			return Scope{}, fmt.Errorf("cplane scope: headend slot: %w", err)
		}
	}
	for _, slot := range s.EndpointSlots {
		if err := bpf.ValidatePluginSlot("endpoint", slot); err != nil {
			return Scope{}, fmt.Errorf("cplane scope: endpoint slot: %w", err)
		}
	}
	return s, nil
}

// HeadendPrefixStrings renders the prefixes the way they were given, for
// persistence and for reporting.
func (s Scope) HeadendPrefixStrings() []string {
	out := make([]string, 0, len(s.HeadendPrefixes))
	for _, p := range s.HeadendPrefixes {
		out = append(out, p.String())
	}
	return out
}

// Empty reports a scope that permits nothing.
func (s Scope) Empty() bool {
	return len(s.Locators) == 0 && len(s.VRFs) == 0 && len(s.HeadendPrefixes) == 0 &&
		len(s.HeadendSlots) == 0 && len(s.EndpointSlots) == 0
}

// allowsLocator reports whether the plugin may name this locator.
func (s Scope) allowsLocator(name string) bool { return containsString(s.Locators, name) }

// allowsVRF reports whether the plugin may originate into this VRF.
func (s Scope) allowsVRF(name string) bool { return containsString(s.VRFs, name) }

// allowsTrigger reports whether a headend trigger prefix falls inside the
// scope.
func (s Scope) allowsTrigger(pfx netip.Prefix) bool {
	for _, allowed := range s.HeadendPrefixes {
		if prefixWithin(allowed, pfx) {
			return true
		}
	}
	return false
}

// prefixWithin reports whether inner is contained in outer. A prefix is
// contained in itself; a shorter one never is, because it covers addresses
// outer does not.
func prefixWithin(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	if inner.Bits() < outer.Bits() {
		return false
	}
	return outer.Contains(inner.Addr())
}

// Guard answers what a plugin's declarations are allowed to name.
//
// It holds the scope together with the two things a scope is stated in
// terms of. Locators and VRF bindings are both registered over RPC after
// the daemon starts, so they are resolved at declaration time rather than
// captured: a plugin restored before its locator exists declares, fails,
// and is retried by the machinery that already exists for exactly that.
type Guard struct {
	scope    Scope
	locators LocatorSource
	bindings VRFBindingSource
}

// NewGuard builds the guard for one plugin. Either source may be nil, in
// which case declarations that would need it are refused rather than
// waved through.
func NewGuard(scope Scope, locators LocatorSource, bindings VRFBindingSource) *Guard {
	return &Guard{scope: scope, locators: locators, bindings: bindings}
}

// Scope is what this guard enforces.
func (g *Guard) Scope() Scope {
	if g == nil {
		return Scope{}
	}
	return g.scope
}

// CheckHeadend refuses a trigger prefix outside the scope, and a mode
// pointing at a headend slot the plugin does not own.
//
// trigger is the masked form the map is keyed on, so what is checked is
// what is written.
func (s Scope) CheckHeadend(trigger string, mode uint8) error {
	pfx, err := netip.ParsePrefix(trigger)
	if err != nil {
		return fmt.Errorf("headend entry for %q: %w", trigger, err)
	}
	if !s.allowsTrigger(pfx) {
		return fmt.Errorf("headend entry for %q is outside this plugin's scope (%s)",
			trigger, describe(s.HeadendPrefixStrings(), "no headend prefixes"))
	}
	// Only a plugin slot is checked. A mode naming one of vinbero's own
	// behaviors is ordinary encapsulation, which is what a control-plane
	// plugin computing a segment list uses and is not another plugin's to
	// own.
	if isPluginHeadendSlot(mode) && !containsUint32(s.HeadendSlots, uint32(mode)) {
		return fmt.Errorf("headend entry for %q names headend slot %d, which this plugin does not own (%s)",
			trigger, mode, describeSlots(s.HeadendSlots))
	}
	return nil
}

// checkHeadend is CheckHeadend with the no-scope case spelled out.
func (g *Guard) checkHeadend(trigger string, mode uint8) error {
	if g == nil {
		return fmt.Errorf("headend entry for %q: this plugin has no scope, so it may not install headend entries", trigger)
	}
	return g.scope.CheckHeadend(trigger, mode)
}

// isPluginHeadendSlot reports whether a mode falls in the range reserved
// for plugin data-plane halves rather than vinbero's own behaviors.
func isPluginHeadendSlot(mode uint8) bool {
	return bpf.ValidatePluginSlot(bpf.MapTypeHeadendV4, uint32(mode)) == nil
}

// CheckLocalSID refuses a SID allocated from a locator the plugin was not
// given, or pointed at a slot it does not own.
func (s Scope) CheckLocalSID(sid LocalSID) error {
	if !s.allowsLocator(sid.Locator) {
		return fmt.Errorf("local sid %q: locator %q is outside this plugin's scope (%s)",
			sid.Name, sid.Locator, describe(s.Locators, "no locators"))
	}
	if !containsUint32(s.EndpointSlots, sid.Slot) {
		return fmt.Errorf("local sid %q: endpoint slot %d is not one this plugin owns (%s)",
			sid.Name, sid.Slot, describeSlots(s.EndpointSlots))
	}
	return nil
}

// checkLocalSID is CheckLocalSID with the no-scope case spelled out.
func (g *Guard) checkLocalSID(s LocalSID) error {
	if g == nil {
		return fmt.Errorf("local sid %q: this plugin has no scope, so it may not allocate SIDs", s.Name)
	}
	return g.scope.CheckLocalSID(s)
}

// resolveAdvertised fills in what the plugin is not allowed to say and
// refuses what it may not name.
//
// A VPN route takes its route distinguisher and its route targets from the
// binding of the VRF it names. The route targets are what decide which VRF
// a peer imports the route into, so a plugin able to spell them could put
// a route into a VPN it was never given -- checking them against the
// binding would work, but deriving them removes the question along with
// the canonicalization it would need.
func (g *Guard) resolveAdvertised(r AdvertisedRoute) (AdvertisedRoute, error) {
	if g == nil {
		return r, fmt.Errorf("advertise: this plugin has no scope, so it may not originate routes")
	}
	switch r.Family {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		return g.resolveVPN(r)
	case bgp.FamilyIPv6Unicast:
		return g.resolveUnicast(r)
	default:
		return r, fmt.Errorf("advertise: family %s cannot be originated by a plugin", r.Family)
	}
}

// CheckAdvertised is the part of an advertisement a scope can answer on
// its own, without the daemon's locators and VRF bindings.
//
// It is what the conformance harness runs. Containment in a locator and
// the existence of a VRF binding are not decidable outside a daemon, so
// they are the daemon's alone; naming a VRF the plugin was not given is
// decidable here, and it is the one that matters most.
func (s Scope) CheckAdvertised(r AdvertisedRoute) error {
	switch r.Family {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		if !s.allowsVRF(r.VRF) {
			return fmt.Errorf("advertise: %s %s names VRF %q, which is outside this plugin's scope (%s)",
				r.Family, r.Prefix, r.VRF, describe(s.VRFs, "no VRFs"))
		}
	case bgp.FamilyIPv6Unicast:
		if len(s.Locators) == 0 {
			return fmt.Errorf("advertise: %s %s is outside this plugin's scope, which names no locators",
				r.Family, r.Prefix)
		}
	default:
		return fmt.Errorf("advertise: family %s cannot be originated by a plugin", r.Family)
	}
	return nil
}

// resolveVPN derives the RD and the route targets from the named VRF.
func (g *Guard) resolveVPN(r AdvertisedRoute) (AdvertisedRoute, error) {
	if r.VRF == "" {
		return r, fmt.Errorf("advertise: %s %s names no VRF, and a VPN route takes its route distinguisher from one",
			r.Family, r.Prefix)
	}
	if err := g.scope.CheckAdvertised(r); err != nil {
		return r, err
	}
	if g.bindings == nil {
		return r, fmt.Errorf("advertise: %s %s names VRF %q, but this daemon has no VRF bindings to take a route distinguisher from",
			r.Family, r.Prefix, r.VRF)
	}
	b, ok := g.bindings.Get(r.VRF)
	if !ok {
		return r, fmt.Errorf("advertise: %s %s names VRF %q, which has no BGP binding",
			r.Family, r.Prefix, r.VRF)
	}
	// A binding with no RD is receive-only: it imports routes and
	// originates none. Originating into it would put routes on the wire
	// under an RD the operator never chose.
	if b.RD == "" {
		return r, fmt.Errorf("advertise: %s %s names VRF %q, whose binding is receive-only and has no route distinguisher",
			r.Family, r.Prefix, r.VRF)
	}
	r.RD = b.RD
	r.RouteTargets = append([]string(nil), b.ExportRTsForFamily(r.Family)...)
	return r, nil
}

// resolveUnicast holds an IPv6 unicast advertisement inside the locators
// the plugin was given.
func (g *Guard) resolveUnicast(r AdvertisedRoute) (AdvertisedRoute, error) {
	if r.VRF != "" {
		return r, fmt.Errorf("advertise: %s %s is not a VPN route, so it belongs to no VRF and cannot name %q",
			r.Family, r.Prefix, r.VRF)
	}
	pfx, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return r, fmt.Errorf("advertise: %s prefix %q: %w", r.Family, r.Prefix, err)
	}
	if err := g.scope.CheckAdvertised(r); err != nil {
		return r, err
	}
	if g.locators == nil {
		return r, fmt.Errorf("advertise: %s %s cannot be checked against this plugin's locators, because this daemon has none",
			r.Family, r.Prefix)
	}
	var missing []string
	for _, name := range g.scope.Locators {
		loc, ok := g.locators.Get(name)
		if !ok {
			// Retried rather than refused for good: locators are
			// registered over RPC, and a plugin restored before its own
			// locator exists is the ordinary case.
			missing = append(missing, name)
			continue
		}
		if prefixWithin(loc.Prefix, pfx) {
			return r, nil
		}
	}
	if len(missing) > 0 {
		return r, fmt.Errorf("advertise: %s %s is not inside any locator this plugin holds, and %s not registered yet",
			r.Family, r.Prefix, describeMissing(missing))
	}
	return r, fmt.Errorf("advertise: %s %s is not inside any locator this plugin holds (%s)",
		r.Family, r.Prefix, describe(g.scope.Locators, "no locators"))
}

// checkAdvertiseSet applies the per-VRF prefix cap the binding carries.
//
// The cap is the operator's statement about how much of a VPN one writer
// may fill, and it already governs the auto-advertise path. A plugin
// originating into the same VRF is measured against it too, so granting a
// plugin a VRF does not quietly hand it an unbounded one.
//
// The two are counted separately today: the exporter's own routes live in
// pkg/bgp/export and are not visible here, so a VRF with both can hold up
// to the cap from each.
func (g *Guard) checkAdvertiseSet(routes []AdvertisedRoute) error {
	if g == nil || g.bindings == nil {
		return nil
	}
	counts := make(map[string]int)
	for _, r := range routes {
		if r.VRF == "" {
			continue
		}
		counts[r.VRF]++
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, ok := g.bindings.Get(name)
		if !ok || b.MaxPrefixes == 0 {
			continue
		}
		if counts[name] > int(b.MaxPrefixes) {
			return fmt.Errorf("advertise: %d routes declared in VRF %q, which caps one writer at %d",
				counts[name], name, b.MaxPrefixes)
		}
	}
	return nil
}

// describe renders a list for an error message, or says it is empty.
func describe(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	return strings.Join(items, ", ")
}

// describeSlots renders a slot list for an error message.
func describeSlots(slots []uint32) string {
	if len(slots) == 0 {
		return "it owns no slots"
	}
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		parts = append(parts, fmt.Sprint(s))
	}
	return "it owns " + strings.Join(parts, ", ")
}

// describeMissing names the locators a check could not resolve.
func describeMissing(names []string) string {
	if len(names) == 1 {
		return fmt.Sprintf("locator %q is", names[0])
	}
	return fmt.Sprintf("locators %s are", strings.Join(names, ", "))
}

// dedupeStrings sorts and removes repeats, so two spellings of one scope
// compare equal and the reported form is stable.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// dedupeUint32 is dedupeStrings for slot numbers.
func dedupeUint32(in []uint32) []uint32 {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[uint32]struct{}, len(in))
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsUint32(list []uint32, want uint32) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
