// Package vrfbgp holds VRF <-> BGP route-target bindings. The RPC handler
// (pkg/server) and the BGP route applier (pkg/bgp/apply) share one
// Manager so a received route's route targets can be resolved to a VRF
// consistently.
package vrfbgp

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// ErrEmptyVRFName is returned by Bind when the binding has no VRF name.
var ErrEmptyVRFName = errors.New("vrfbgp: vrf_name must be non-empty")

// ErrBindingNotFound is returned by Unbind for an unknown VRF.
var ErrBindingNotFound = errors.New("vrfbgp: binding not found")

// Direction is the bitmask used to express the direction(s) a route target
// applies in. "both" is expressed by OR'ing import and export so a single
// helper can check either direction.
type Direction uint8

const (
	DirectionImport Direction = 1 << iota
	DirectionExport
)

// DirectionBoth is the bitmask for the "both" direction shorthand.
const DirectionBoth = DirectionImport | DirectionExport

// Has reports whether d covers want (i.e. the want bit is set).
func (d Direction) Has(want Direction) bool { return d&want == want }

// String renders d as the canonical operator-facing string ("import" /
// "export" / "both"). A zero bitmask renders as "invalid" so a stray
// Direction(0) -- which today should never appear in storage -- cannot
// silently round-trip through ParseDirection("") (= DirectionBoth) and
// masquerade as a both-direction RT. Any other non-canonical bitmask also
// renders as "invalid" for the same reason.
func (d Direction) String() string {
	switch d {
	case DirectionImport:
		return "import"
	case DirectionExport:
		return "export"
	case DirectionBoth:
		return "both"
	default:
		return "invalid"
	}
}

// ParseDirection maps a wire/YAML direction string to the bitmask. Empty and
// "both" both yield DirectionBoth (RFC 4364 §4.3 ergonomic). Unknown strings
// return an error so callers can surface InvalidArgument at the boundary.
func ParseDirection(s string) (Direction, error) {
	switch strings.ToLower(s) {
	case "", "both":
		return DirectionBoth, nil
	case "import":
		return DirectionImport, nil
	case "export":
		return DirectionExport, nil
	default:
		return 0, fmt.Errorf("invalid direction %q (want import/export/both)", s)
	}
}

// rtBindableFamilies are the families a VRF binding may declare. It excludes
// FamilyIPv6Unicast (underlay, not RT-bound) and FamilySRPolicyIPv6 (SAFI 73).
var rtBindableFamilies = []bgp.Family{
	bgp.FamilyVPNv4, bgp.FamilyVPNv6, bgp.FamilyEVPN,
	bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6,
}

// ValidateRouteTarget rejects RT strings the BGP layer cannot encode. Three
// RFC 4360 / 5668 forms are accepted: "ASN:value" (2-octet AS, 4-octet value
// or 4-octet AS, 2-octet value) and "IPv4:value". The split is on the LAST
// colon so an IPv4-form RT round-trips unambiguously. Numeric tokens must be
// in their canonical decimal form (no leading zeros) so two operator inputs
// that name the same RT do not survive as two distinct entries downstream
// (mergeLegacyRTs and the Families maps key on the raw string). This is a
// syntax check; the gobgp adapter does the full extended-community encoding
// at advertise time.
func ValidateRouteTarget(rt string) error {
	if rt == "" {
		return fmt.Errorf("route_target is required")
	}
	i := strings.LastIndex(rt, ":")
	if i <= 0 || i == len(rt)-1 {
		return fmt.Errorf("route_target %q: want ASN:value or IPv4:value", rt)
	}
	left, right := rt[:i], rt[i+1:]
	rightVal, err := strconv.ParseUint(right, 10, 32)
	if err != nil {
		return fmt.Errorf("route_target %q: value %q must be a non-negative integer", rt, right)
	}
	if strconv.FormatUint(rightVal, 10) != right {
		return fmt.Errorf("route_target %q: value %q must be canonical decimal (no leading zeros)", rt, right)
	}
	if leftVal, err := strconv.ParseUint(left, 10, 32); err == nil {
		if strconv.FormatUint(leftVal, 10) != left {
			return fmt.Errorf("route_target %q: ASN %q must be canonical decimal (no leading zeros)", rt, left)
		}
		return nil
	}
	if ip, err := netip.ParseAddr(left); err == nil && ip.Is4() {
		return nil
	}
	return fmt.Errorf("route_target %q: %q must be an integer ASN or IPv4 address", rt, left)
}

// ValidateFamily reports whether fam may appear in a binding's Families map.
// Returns an error naming the typo so callers can surface InvalidArgument.
func ValidateFamily(fam string) error {
	if slices.Contains(rtBindableFamilies, bgp.Family(fam)) {
		return nil
	}
	return fmt.Errorf("unknown family %q (want vpnv4/vpnv6/evpn/mup_ipv4/mup_ipv6)", fam)
}

// ParseMUPGTP4SourcePrefix parses and validates a binding's GTP4 downlink
// source prefix (RFC 9433 §6.6). The prefix must be IPv6-native and /96 or
// shorter so the 32-bit IPv4 anchor fits right after the prefix bits, and it
// requires the binding's rd to be set: a received MUP route resolves its
// binding (and so this prefix) by RD, so a prefix on an RD-less binding
// could never take effect. Empty input returns the zero Prefix (embedding
// off). The result is Masked() so two spellings of the same prefix compare
// equal downstream (the applier and the change-detection predicate compare
// Prefix values directly). Shared by the YAML config loader and the RPC
// boundary so the constraints cannot drift.
func ParseMUPGTP4SourcePrefix(s, rd string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("mup_gtp4_source_prefix %q: %w", s, err)
	}
	if !pfx.Addr().Is6() || pfx.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("mup_gtp4_source_prefix %q: must be an IPv6 prefix", s)
	}
	if pfx.Bits() > 96 {
		return netip.Prefix{}, fmt.Errorf("mup_gtp4_source_prefix %q: prefix length %d leaves no room for the 32-bit IPv4 anchor (max /96)", s, pfx.Bits())
	}
	if rd == "" {
		return netip.Prefix{}, fmt.Errorf("mup_gtp4_source_prefix requires rd (MUP routes resolve the binding by RD)")
	}
	return pfx.Masked(), nil
}

// RouteTarget is one route-target entry under one address family.
type RouteTarget struct {
	RT        string
	Direction Direction
}

// FamilyPolicy is one address family's route-target policy under a binding.
// RouteTargets retains the order entries were registered in (matching the
// config input order) so tests can pin a deterministic listing.
type FamilyPolicy struct {
	RouteTargets []RouteTarget
}

// Binding is one VRF's BGP route-target policy.
type Binding struct {
	VRFName string
	// RD is the route distinguisher this VRF advertises its local prefixes
	// under (RFC 4364). It is empty for receive-only bindings; the auto
	// advertise path (pkg/bgp/export) requires it to be non-empty before it
	// will export a prefix, so a binding without an RD simply never exports.
	RD string
	// ImportRTs / ExportRTs are the legacy flat route-target lists, kept for
	// backward compatibility with the L3VPN-only callers in pkg/bgp/export
	// and existing YAML configs. Normalize keeps them in sync with Families:
	// new callers should set Families and read via *ForFamily helpers, but
	// these fields stay populated so the exporter and the legacy MatchImport
	// helpers keep working through the migration.
	ImportRTs []string
	ExportRTs []string
	// Redistribute lists the route protocols ("connected" / "static") whose
	// VRF-local prefixes the auto-advertise path (pkg/bgp/export) exports.
	// Empty means the binding is receive-only.
	Redistribute []string
	// MaxPrefixes caps how many prefixes the auto-advertise path originates for
	// this VRF (0 = unlimited). It bounds the blast radius of a misbehaving or
	// hostile VRF-route writer flooding the VPN.
	MaxPrefixes    uint32
	DefaultLocator string
	// Families is the primary AF -> per-family RT policy map. Normalize
	// derives it from the legacy ImportRTs / ExportRTs when callers do not
	// set it explicitly (L3VPN families only; EVPN and MUP policies must be
	// declared family-scoped).
	Families map[bgp.Family]FamilyPolicy
	// MupGTP4SourcePrefix turns on RFC 9433 §6.6 source-address embedding
	// for GTP4 downlink (T1ST) installs received under this binding's RD:
	// the downlink outer IPv6 source becomes this prefix with the session's
	// UPF IPv4 anchor embedded right after the prefix bits. The zero Prefix
	// means off. Always IPv6-native, /96 or shorter, and Masked(); parse
	// operator input through ParseMUPGTP4SourcePrefix before storing. It is
	// a comparable value so binding snapshots copy and compare it as-is.
	MupGTP4SourcePrefix netip.Prefix
}

// Normalize returns a copy of b with Families and the legacy ImportRTs /
// ExportRTs reconciled. When Families is nil the legacy lists are expanded
// into the L3VPN families. Otherwise — including a non-nil empty map, which
// is how RemoveFamily / RemoveRouteTarget signal "the caller has emptied
// this binding" — Families is the source of truth and the legacy lists are
// synthesized from it. The nil-vs-empty distinction keeps RemoveFamily from
// being silently undone by a stale legacy list.
//
// Families is deep-copied before synthesis so Manager.Bind never stores a
// map that aliases the caller's input.
func (b Binding) Normalize() Binding {
	out := b
	if out.Families == nil {
		out.Families = legacyToFamilies(out.ImportRTs, out.ExportRTs)
		return out
	}
	out.Families = cloneFamilies(out.Families)
	out.ImportRTs, out.ExportRTs = familiesToLegacy(out.Families)
	return out
}

// cloneFamilies returns a deep copy of fams so the result shares no map or
// slice backing array with the input.
func cloneFamilies(fams map[bgp.Family]FamilyPolicy) map[bgp.Family]FamilyPolicy {
	out := make(map[bgp.Family]FamilyPolicy, len(fams))
	for fam, fp := range fams {
		out[fam] = FamilyPolicy{RouteTargets: append([]RouteTarget(nil), fp.RouteTargets...)}
	}
	return out
}

// legacyToFamilies expands the flat ImportRTs / ExportRTs into a Families
// map covering the L3VPN families (vpnv4 + vpnv6). EVPN has no legacy form:
// it needs a bridge domain, which only the VRF's bridge facet provides, so
// an EVPN policy must be declared family-scoped (Families / "evpn:"-prefixed
// RTs). MUP likewise has no representation in the legacy form, so legacy
// bindings never carry a mup_ipv* family (default-allow stays in effect for
// MUP).
func legacyToFamilies(importRTs, exportRTs []string) map[bgp.Family]FamilyPolicy {
	if len(importRTs) == 0 && len(exportRTs) == 0 {
		return nil
	}
	families := []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6}
	out := make(map[bgp.Family]FamilyPolicy, len(families))
	for _, fam := range families {
		out[fam] = FamilyPolicy{RouteTargets: mergeLegacyRTs(importRTs, exportRTs)}
	}
	return out
}

// mergeLegacyRTs merges importRTs and exportRTs into a single RouteTarget list
// with the direction bitmask reflecting which list the RT appeared in. An RT
// in both becomes DirectionBoth so a single Has check answers either direction.
func mergeLegacyRTs(importRTs, exportRTs []string) []RouteTarget {
	idx := make(map[string]int) // rt -> position in out
	out := make([]RouteTarget, 0, len(importRTs)+len(exportRTs))
	add := func(rt string, d Direction) {
		if i, ok := idx[rt]; ok {
			out[i].Direction |= d
			return
		}
		idx[rt] = len(out)
		out = append(out, RouteTarget{RT: rt, Direction: d})
	}
	for _, rt := range importRTs {
		add(rt, DirectionImport)
	}
	for _, rt := range exportRTs {
		add(rt, DirectionExport)
	}
	return out
}

// DedupeRouteTargets collapses entries that share the same RT string into one,
// OR-ing their Direction bitmasks. First-seen order is preserved so a caller
// that fed an operator-supplied list keeps the deterministic ordering
// consumers (ListRouteTargets, exporter origination) rely on. AddRouteTarget
// is the runtime-mutation entry point for idempotent OR-direction adds; this
// helper applies the same invariant at the wire / config boundary so two RT
// "65000:1" entries with directions "import" and "export" do not survive as
// separate items only to mislead `sameRouteTargets` len comparison or to
// double-emit the same extended community on the wire.
func DedupeRouteTargets(in []RouteTarget) []RouteTarget {
	if len(in) <= 1 {
		return in
	}
	idx := make(map[string]int, len(in))
	out := make([]RouteTarget, 0, len(in))
	for _, rt := range in {
		if i, ok := idx[rt.RT]; ok {
			out[i].Direction |= rt.Direction
			continue
		}
		idx[rt.RT] = len(out)
		out = append(out, rt)
	}
	return out
}

// familiesToLegacy synthesizes the flat ImportRTs / ExportRTs lists from
// Families. An RT that appears in any family with the given direction is
// included once. Order is canonical family order then per-RT insertion
// order inside the family so the resulting lists are deterministic.
func familiesToLegacy(families map[bgp.Family]FamilyPolicy) ([]string, []string) {
	var importRTs, exportRTs []string
	appendUnique := func(list *[]string, rt string) {
		if !slices.Contains(*list, rt) {
			*list = append(*list, rt)
		}
	}
	for _, fam := range CanonicalFamilyOrder(families) {
		for _, rt := range families[fam].RouteTargets {
			if rt.Direction.Has(DirectionImport) {
				appendUnique(&importRTs, rt.RT)
			}
			if rt.Direction.Has(DirectionExport) {
				appendUnique(&exportRTs, rt.RT)
			}
		}
	}
	return importRTs, exportRTs
}

// CanonicalFamilyOrder returns the families in a fixed canonical order
// (rtBindableFamilies first, then unknown families lexicographically) so
// map iteration order does not leak into derived legacy lists or
// VrfBgpList responses.
func CanonicalFamilyOrder(families map[bgp.Family]FamilyPolicy) []bgp.Family {
	out := make([]bgp.Family, 0, len(families))
	for _, fam := range rtBindableFamilies {
		if _, ok := families[fam]; ok {
			out = append(out, fam)
		}
	}
	var extras []bgp.Family
	for fam := range families {
		if !slices.Contains(rtBindableFamilies, fam) {
			extras = append(extras, fam)
		}
	}
	slices.SortFunc(extras, func(a, b bgp.Family) int { return cmp.Compare(a, b) })
	return append(out, extras...)
}

// Manager holds VRF<->RT bindings (the BGP-policy facet of a VRF). It owns a
// vrf.Manager (the first-class VRF object: identity, vrf_id, ingress
// membership) and Ensures a VRF exists for every bound VRF name so the BGP
// facet always references a VRF with a stable id. Safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	bindings map[string]Binding
	vrf      *vrf.Manager
}

// NewManager returns an empty Manager with a fresh vrf.Manager.
func NewManager() *Manager {
	return &Manager{
		bindings: make(map[string]Binding),
		vrf:      vrf.NewManager(),
	}
}

// VRF returns the first-class VRF manager this binding manager attaches to.
// The VRF object owns the data-plane vrf_id and ingress membership; the BGP
// binding is a facet referencing a VRF by name.
func (m *Manager) VRF() *vrf.Manager { return m.vrf }

// Bind registers (or replaces) the binding for b.VRFName and Ensures the VRF
// object exists (allocating its vrf_id). The binding is normalized so the new
// (Families) and legacy (ImportRTs / ExportRTs) surfaces stay consistent.
//
// Ensure runs BEFORE the binding is published: a concurrent route apply that
// resolves an RT to this VRF (MatchImportForFamily -> IDForName) must never see
// the binding without its vrf_id, or a T2ST would briefly install under the
// global VRF (id 0). The two locks are independent (Ensure takes vrf.Manager's,
// not held here), so ordering them this way is free of deadlock.
func (m *Manager) Bind(b Binding) error {
	if b.VRFName == "" {
		return ErrEmptyVRFName
	}
	m.vrf.Ensure(b.VRFName) // VRF identity is independent of the binding's lifetime
	m.mu.Lock()
	m.bindings[b.VRFName] = b.Normalize()
	m.mu.Unlock()
	return nil
}

// Unbind removes the binding for vrfName. The VRF object itself is left intact
// (it may still hold ingress ACs or be referenced elsewhere); deleting a VRF
// is an explicit VrfService / config operation.
func (m *Manager) Unbind(vrfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.bindings[vrfName]; !ok {
		return fmt.Errorf("%w: %q", ErrBindingNotFound, vrfName)
	}
	delete(m.bindings, vrfName)
	return nil
}

// Get returns the binding for vrfName and ok=false if none is registered.
func (m *Manager) Get(vrfName string) (Binding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bindings[vrfName]
	return b, ok
}

// BindingByRD returns the binding whose RD matches rd, used by the MUP
// advertise path and EVPN auto-advertise to resolve a route's RD back to
// its binding. An ambiguous RD returns ok=false: refusing to guess is safer
// than originating with a map-iteration-order-dependent VRF/RD/RT.
func (m *Manager) BindingByRD(rd string) (Binding, bool) {
	if rd == "" {
		return Binding{}, false
	}
	return m.findUnique(func(b Binding) bool { return b.RD == rd })
}

// findUnique returns the single binding satisfying pred, or ok=false when
// none or more than one match.
func (m *Manager) findUnique(pred func(Binding) bool) (Binding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var found Binding
	n := 0
	for _, b := range m.bindings {
		if pred(b) {
			found = b
			n++
		}
	}
	if n != 1 {
		return Binding{}, false
	}
	return found, true
}

// List returns a snapshot of every binding.
func (m *Manager) List() []Binding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Binding, 0, len(m.bindings))
	for _, b := range m.bindings {
		out = append(out, b)
	}
	return out
}

// MatchImportForFamily returns the binding whose Families[fam] contains an
// import-direction route target that overlaps rts. For FamilyEVPN it also
// resolves the matched VRF's bridge facet and returns its bd_id -- the facet
// is the bridge domain's single source; L3VPN / MUP callers ignore bdID.
// ok=false means no binding accepts this route under fam.
//
// EVPN install always needs a bridge domain, so a binding whose VRF has no
// bridge facet is skipped for FamilyEVPN (fail-closed) -- otherwise it could
// win the deterministic-name selection ahead of a facet-backed one and
// silently drop a valid RT2/RT3.
//
// When several bindings import the same RT the lowest VRF name wins: the
// match must be deterministic, not map-iteration order, because the MUP
// uplink instance a T2ST installs under follows the matched binding and a
// flapping match would re-key the session's F-TEID entry on every
// reconcile. The minimum is selected in a single allocation-free pass; this
// sits on the per-route apply path. The per-binding facet lookup takes
// vrf.Manager's read lock nested inside m.mu; vrf.Manager never calls back
// into this package, so the order cannot invert.
func (m *Manager) MatchImportForFamily(rts []string, fam bgp.Family) (vrfName string, bdID uint16, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.bindings {
		var facetBD uint16
		if fam == bgp.FamilyEVPN {
			v, exists := m.vrf.Get(b.VRFName)
			if !exists || v.Bridge == nil {
				continue
			}
			facetBD = v.Bridge.BdID
		}
		if ok && b.VRFName >= vrfName {
			continue
		}
		fp, has := b.Families[fam]
		if !has {
			continue
		}
		for _, rt := range fp.RouteTargets {
			if rt.Direction.Has(DirectionImport) && slices.Contains(rts, rt.RT) {
				vrfName, bdID, ok = b.VRFName, facetBD, true
				break
			}
		}
	}
	return vrfName, bdID, ok
}

// ExportRTsForFamily returns the export-direction route targets declared
// under fam, in registration order. Per-AF lookup keeps cross-family RTs
// (a vpnv4 RT) off another family's advertisement (an EVPN RT2/RT3), which
// the legacy ImportRTs / ExportRTs flat union would mix. Returns nil when
// the binding has no entry for fam or no RT has the export bit set.
func (b Binding) ExportRTsForFamily(fam bgp.Family) []string {
	fp, has := b.Families[fam]
	if !has {
		return nil
	}
	out := make([]string, 0, len(fp.RouteTargets))
	for _, rt := range fp.RouteTargets {
		if rt.Direction.Has(DirectionExport) {
			out = append(out, rt.RT)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ExportRTsForFamily returns the export-direction route targets of vrfName
// under fam. An unknown VRF, or one with no entry for fam, returns nil.
func (m *Manager) ExportRTsForFamily(vrfName string, fam bgp.Family) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bindings[vrfName]
	if !ok {
		return nil
	}
	return b.ExportRTsForFamily(fam)
}

// EmptyForFamily reports whether no binding declares fam with at least one
// RT. Receive paths use it to keep default-allow until an operator opts in
// for that family: L3VPN until the first vpnv4 / vpnv6 binding, MUP until
// the first mup_ipv* binding. A family entry with no RTs is treated as
// undeclared so `vbctl vrf-bgp family add` with no --rt does not flip the
// global default-allow off and silently drop traffic on every other binding.
//
// EVPN is intentionally not routed through EmptyForFamily -- the applier
// always requires an explicit BD-bound binding, so a default-allow path
// would have nothing to install into.
func (m *Manager) EmptyForFamily(fam bgp.Family) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.bindings {
		if fp, has := b.Families[fam]; has && len(fp.RouteTargets) > 0 {
			return false
		}
	}
	return true
}

// MatchImport is the legacy L3VPN helper, retained as a thin wrapper over
// MatchImportForFamily. It checks VPNv4 then VPNv6 so a binding declared on
// only one of the two L3VPN families (e.g. via `vbctl vrf-bgp family add
// --family vpnv6`) still resolves, instead of silently failing because the
// legacy-expansion assumption (both families share the same RT set) no
// longer holds for unified-binding callers.
//
// Deprecated: use MatchImportForFamily; this wrapper exists for callers
// that have not migrated yet.
func (m *Manager) MatchImport(rts []string) (string, bool) {
	if vrf, _, ok := m.MatchImportForFamily(rts, bgp.FamilyVPNv4); ok {
		return vrf, true
	}
	vrf, _, ok := m.MatchImportForFamily(rts, bgp.FamilyVPNv6)
	return vrf, ok
}

// Empty reports whether no bindings are registered. L3VPN-receive callers
// historically used this for default-allow before any VrfBgpBind; new
// callers should use EmptyForFamily instead.
//
// Deprecated: use EmptyForFamily(FamilyVPNv4) for the same default-allow
// guard a L3VPN receive path needs.
func (m *Manager) Empty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.bindings) == 0
}
