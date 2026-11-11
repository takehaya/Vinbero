package apply

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/prober"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// moveSourceLocator deletes the source locator and registers it again under
// prefix, the way `vbctl locator delete` and `vbctl locator create` do, and
// runs what the registration hook runs on the applier.
func moveSourceLocator(t *testing.T, a *Applier, locs *locator.Manager, prefix string) {
	t.Helper()
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	addTestLocator(t, locs, prefix)
	reconcileTracked(t, a)
}

// dpSnapshot is the identity of every entry the fake data plane holds. The
// fake keeps the entry each write passes it and every write builds a new
// one, so an identity that did not change is an entry nobody wrote.
type dpSnapshot map[string]any

func snapshotDP(fh *fakeHeadend) dpSnapshot {
	s := dpSnapshot{}
	for k, e := range fh.bdPeers {
		s[fmt.Sprintf("bd_peer %v", k)] = e
	}
	for k, e := range fh.fdb {
		s[fmt.Sprintf("fdb %v", k)] = e
	}
	for id, ps := range fh.ecmpGroups {
		if len(ps) > 0 {
			s[fmt.Sprintf("ecmp %d", id)] = &ps[0]
		}
	}
	for k, e := range fh.v4created {
		s["headend_v4 "+k] = e
	}
	for k, e := range fh.v6created {
		s["headend_v6 "+k] = e
	}
	for k, e := range fh.mupUplink {
		s[fmt.Sprintf("mup_uplink %v", k)] = e
	}
	return s
}

// rewritten lists the entries of s that later no longer holds as they
// were: written again, removed, or added.
func (s dpSnapshot) rewritten(later dpSnapshot) []string {
	var out []string
	for k, v := range s {
		if later[k] != v {
			out = append(out, k)
		}
	}
	for k := range later {
		if _, ok := s[k]; !ok {
			out = append(out, k+" (new)")
		}
	}
	return out
}

// countingProber counts registrations. A group rewrite re-registers its
// probe targets (the write resets the group's liveness bitmap); an
// unchanged group must not.
type countingProber struct {
	*fakeProber
	registers int
}

func (c *countingProber) Register(groupID uint32, targets []prober.Target) {
	c.registers++
	c.fakeProber.Register(groupID, targets)
}

var aliasESI = [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

// evpnSourceLab programs every kind of EVPN entry that carries the encap
// source, with the source locator under fd00:1:1::/48: a single-homed PE's
// unicast peer (RT2, two MACs sharing it), its BUM flood peer (RT3), and a
// two-PE all-active segment (aliasing group, ES peer, and a MAC on the
// segment). routes is what the EVPN loc-rib holds, for the replay the
// registration hook runs after ReconcileTracked.
func evpnSourceLab(t *testing.T) (*Applier, *fakeHeadend, *locator.Manager, *countingProber, []bgp.RouteEvent) {
	t.Helper()
	locs := locator.NewManager()
	addTestLocator(t, locs, "fd00:1:1::/48")
	a, fh := evpnApplierOn(t, locs)
	fp := &countingProber{fakeProber: newFakeProber()}
	a.SetProber(fp)

	single := rt2From("65000:100:4", "aa:bb:cc:00:00:01", "fd00:4:4:d2::", "fd00::4", [10]byte{})
	single.RemoteSrc = "fd00:4:4::"
	other := *single
	other.MAC = "aa:bb:cc:00:00:02"
	flood := rt3("fd00:4:4:24::")
	flood.RD, flood.NextHop = "65000:100:4", "fd00::4"
	routes := []bgp.RouteEvent{
		{Family: bgp.FamilyEVPN, EVPN: single},
		{Family: bgp.FamilyEVPN, EVPN: &other},
		{Family: bgp.FamilyEVPN, EVPN: flood},
		perESAD("fd00::2", aliasESI, false),
		perESAD("fd00::3", aliasESI, false),
		perEVIAD("65000:100:2", "fd00::2", "fd00:2:2:ad::", aliasESI),
		perEVIAD("65000:100:3", "fd00::3", "fd00:3:3:ad::", aliasESI),
		{Family: bgp.FamilyEVPN, EVPN: rt2From("65000:100:2", "aa:bb:cc:00:00:03", "fd00:2:2:d2::", "fd00::2", aliasESI)},
	}
	for _, ev := range routes {
		a.Apply(ev)
	}
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:1:1::"))
	// The single-homed PE's unicast and flood peers, the segment PE's own
	// unicast peer, and the ES peer.
	if len(fh.bdPeers) != 4 || len(fh.ecmpGroups) != 1 || len(fh.fdb) != 3 {
		t.Fatalf("setup: %d bd_peers, %d groups, %d FDB entries; want 4, 1, 3",
			len(fh.bdPeers), len(fh.ecmpGroups), len(fh.fdb))
	}
	return a, fh, locs, fp, routes
}

func replayRoutes(t *testing.T, a *Applier, routes []bgp.RouteEvent) {
	t.Helper()
	if err := a.ReplayEVPN(func(h bgp.RouteHandler) error {
		for _, ev := range routes {
			h(ev)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// checkEVPNSource fails unless every bd_peer and every aliasing member
// carries want.
func checkEVPNSource(t *testing.T, fh *fakeHeadend, want netip.Addr) {
	t.Helper()
	for k, e := range fh.bdPeers {
		if got := netip.AddrFrom16(e.SrcAddr); got != want {
			t.Errorf("bd_peer %v source = %s, want %s", k, got, want)
		}
	}
	for id, ps := range fh.ecmpGroups {
		for i, p := range ps {
			if got := netip.AddrFrom16(p.Entry.SrcAddr); got != want {
				t.Errorf("group %d member %d source = %s, want %s", id, i, got, want)
			}
		}
	}
}

// EVPN entries follow the source locator to a new prefix without any route
// being sent again: the unicast and flood peers are rewritten in place, and
// the aliasing group and its ES peer are rewritten. Nothing else moves: the
// FDB entries, the peer indices (flood slots included), the reverse keys,
// the ESIs and the group id stay as they were.
func TestReconcileTrackedEVPNMoved(t *testing.T) {
	a, fh, locs, fp, routes := evpnSourceLab(t)
	before := snapshotDP(fh)
	reverse := maps.Clone(fh.reverse)
	reverseWrites := fh.reverseWrites
	esis := maps.Clone(fh.bdPeerESI)
	registers := fp.registers

	moveSourceLocator(t, a, locs, "fd00:9:9::/48")
	replayRoutes(t, a, routes)

	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:9:9::"))
	after := snapshotDP(fh)
	for k := range before {
		if _, ok := after[k]; !ok {
			t.Errorf("%s is gone after the source moved", k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s appeared after the source moved", k)
		}
	}
	for k := range fh.fdb {
		key := fmt.Sprintf("fdb %v", k)
		if before[key] != after[key] {
			t.Errorf("%s was written again; a source change must not touch the FDB", key)
		}
	}
	if !maps.Equal(reverse, fh.reverse) {
		t.Errorf("reverse map changed: %v, want %v", fh.reverse, reverse)
	}
	if n := fh.reverseWrites - reverseWrites; n != 0 {
		t.Errorf("source move wrote the reverse map %d times; nothing in it depends on the local source", n)
	}
	if !maps.Equal(esis, fh.bdPeerESI) {
		t.Errorf("peer ESIs changed: %v, want %v", fh.bdPeerESI, esis)
	}
	if got := fp.registers - registers; got != 1 {
		t.Errorf("probe registrations after the move = %d, want 1 (the aliasing group)", got)
	}
}

// Registering the source locator again under the same prefix writes
// nothing: not the peers, not the FDB, not the aliasing group, and the
// group's probe registration stays as it is.
func TestReconcileTrackedEVPNUnchanged(t *testing.T) {
	a, fh, locs, fp, routes := evpnSourceLab(t)
	before := snapshotDP(fh)
	registers := fp.registers

	moveSourceLocator(t, a, locs, "fd00:1:1::/48")
	replayRoutes(t, a, routes)

	if w := before.rewritten(snapshotDP(fh)); len(w) > 0 {
		t.Errorf("an unchanged source locator rewrote %v", w)
	}
	if fp.registers != registers {
		t.Errorf("an unchanged source locator re-registered probes %d times", fp.registers-registers)
	}
}

// groupMembers lists the member SIDs of a group.
func groupMembers(fh *fakeHeadend, group uint32) []string {
	var out []string
	for _, p := range fh.ecmpGroups[group] {
		out = append(out, netip.AddrFrom16(p.Entry.Segments[0]).String())
	}
	slices.Sort(out)
	return out
}

// While the source locator is gone, a membership change on an aliased
// segment is still written, with the source the group already carries, and
// without an error. Once the locator is back the group takes its source.
func TestEVPNAliasingMemberAddedWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	core, logs := observer.New(zapcore.WarnLevel)
	a.logger = zap.New(core)
	_, es := esPeerOf(t, fh)
	group := es.GroupId

	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	a.Apply(perESAD("fd00::5", aliasESI, false))
	a.Apply(perEVIAD("65000:100:5", "fd00::5", "fd00:5:5:ad::", aliasESI))
	if got := groupMembers(fh, group); len(got) != 3 {
		t.Errorf("group members while the locator is gone = %v, want 3", got)
	}
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:1:1::"))
	if _, es := esPeerOf(t, fh); es.GroupId != group {
		t.Errorf("ES peer points at group %d, want %d", es.GroupId, group)
	}
	if fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:03"}]; fdb == nil || fdb.PeerIndex < bpf.EsPeerIndexBase {
		t.Errorf("MAC on the segment moved off the ES peer: %+v", fdb)
	}
	if n := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); n != 0 {
		t.Errorf("%d errors logged while the locator is gone: %v", n, logs.All())
	}

	addTestLocator(t, locs, "fd00:9:9::/48")
	reconcileTracked(t, a)
	if got := groupMembers(fh, group); len(got) != 3 {
		t.Errorf("group members after the locator is back = %v, want 3", got)
	}
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:9:9::"))
}

// A PE that leaves the segment while the source locator is gone is out of
// the group at once: its share of the flows must not be sent to it until
// the locator is registered again.
func TestEVPNAliasingMemberRemovedWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	_, es := esPeerOf(t, fh)
	group := es.GroupId
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	a.Apply(withdrawn(perESAD("fd00::3", aliasESI, false)))
	if got, want := groupMembers(fh, group), []string{"fd00:2:2:ad::"}; !slices.Equal(got, want) {
		t.Errorf("group members after fd00::3 left with the locator gone = %v, want %v", got, want)
	}
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:1:1::"))
}

const (
	labGateEndpoint = "192.0.2.100"
	labGatePrefix   = labGateEndpoint + "/32"
	labUEPrefix     = "10.0.0.1/32"
)

// mupSourceLab programs a downlink (T1ST) and an uplink (T2ST, with its
// gate) with the source locator under fd00:1:1::/48.
func mupSourceLab(t *testing.T) (*Applier, *fakeHeadend, *locator.Manager, mupUplinkKey) {
	t.Helper()
	fh := newFakeHeadend()
	locs := locator.NewManager()
	addTestLocator(t, locs, "fd00:1:1::/48")
	a := NewApplier(fh, locs, vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: "65000:100",
		Prefix: labUEPrefix, Endpoint: "203.0.113.5", TEID: 0x12345678, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: labGateEndpoint, TEID: 0xAB000000, TEIDLen: 8, SRv6SID: "fd00:3:3:c::",
	}})
	uplink := mupUplinkKey{0, labGateEndpoint, 0xAB000000, 8}
	if _, ok := fh.mupUplink[uplink]; !ok {
		t.Fatal("setup: T2ST not written")
	}
	if _, ok := fh.v4created[labUEPrefix]; !ok {
		t.Fatal("setup: T1ST not written")
	}
	return a, fh, locs, uplink
}

// An uplink follows the source locator to a new prefix. Only its source
// changes, and its gate, which carries no source, is not written again.
func TestReconcileTrackedMUPT2STMoved(t *testing.T) {
	a, fh, locs, uplink := mupSourceLab(t)
	gate := fh.v4created[labGatePrefix]

	moveSourceLocator(t, a, locs, "fd00:9:9::/48")
	e := fh.mupUplink[uplink]
	if e == nil {
		t.Fatal("T2ST uplink entry gone after the source moved")
	}
	if got := netip.AddrFrom16(e.SrcAddr); got != netip.MustParseAddr("fd00:9:9::") {
		t.Errorf("T2ST source after the locator moved = %s, want fd00:9:9::", got)
	}
	if e.Segments[0] != netip.MustParseAddr("fd00:3:3:c::").As16() || e.ArgsOffset != bpf.MupArgsOffsetNone {
		t.Errorf("T2ST entry changed beyond its source: %+v", e)
	}
	if fh.v4created[labGatePrefix] != gate {
		t.Error("T2ST gate was written again")
	}
	if n := a.mupGateRefs[mupGateKey{prefix: labGatePrefix}]; n != 1 {
		t.Errorf("gate references = %d, want 1", n)
	}
}

// Registering the source locator again under the same prefix writes no MUP
// entry.
func TestReconcileTrackedMUPUnchanged(t *testing.T) {
	a, fh, locs, _ := mupSourceLab(t)
	before := snapshotDP(fh)
	moveSourceLocator(t, a, locs, "fd00:1:1::/48")
	if w := before.rewritten(snapshotDP(fh)); len(w) > 0 {
		t.Errorf("an unchanged source locator rewrote %v", w)
	}
}

// While the source locator is gone, every discovery route still
// re-reconciles the sessions. Installed ones stay as they are without an
// error per session, and a session that arrives in that window is logged
// once, however many reconciles pass over it.
func TestMUPSessionsKeptWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs, _ := mupSourceLab(t)
	core, logs := observer.New(zapcore.WarnLevel)
	a.logger = zap.New(core)
	before := snapshotDP(fh)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: "192.0.2.101", TEID: 0xCD000000, TEIDLen: 8, SRv6SID: "fd00:3:3:c::",
	}})
	for i := range 3 {
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
			Type: bgp.MUPRouteTypeDSD, RD: "65000:200", Address: fmt.Sprintf("192.0.2.%d", 200+i),
			RTs: []string{"65000:200"}, SRv6SID: "fd00:7:7:c::",
		}})
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
			Type: bgp.MUPRouteTypeISD, RD: "65000:200", Prefix: fmt.Sprintf("198.51.%d.0/24", 100+i),
			RTs: []string{"65000:200"}, SRv6SID: "fd00:7:7:b::",
		}})
	}
	if w := before.rewritten(snapshotDP(fh)); len(w) > 0 {
		t.Errorf("entries changed while the locator is gone: %v", w)
	}
	if n := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); n != 0 {
		t.Errorf("%d errors logged while the locator is gone: %v", n, logs.All())
	}
	if n := logs.FilterMessageSnippet("until the source locator is registered").Len(); n != 1 {
		t.Errorf("waiting-session warnings = %d, want 1: %v", n, logs.All())
	}
}

// An EVPN entry that cannot be rewritten for the new source is reported and
// rewritten by the next pass. A peer keeps the source it has meanwhile; the
// aliasing group unwinds to per-PE forwarding and is formed again.
func TestReconcileTrackedRetriesEVPN(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	addTestLocator(t, locs, "fd00:9:9::/48")
	fh.bdPeerErr = errors.New("map full")
	if err := a.ReconcileTracked(); err == nil {
		t.Fatal("ReconcileTracked reported success with every bd_peer write failing")
	}
	fh.bdPeerErr = nil
	reconcileTracked(t, a)
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:9:9::"))
	idx, _ := esPeerOf(t, fh)
	if fdb := fh.fdb[fdbKey{100, "aa:bb:cc:00:00:03"}]; fdb == nil || fdb.PeerIndex != idx {
		t.Errorf("MAC on the segment = %+v, want it on the ES peer %d again", fdb, idx)
	}
	if len(fh.ecmpGroups) != 1 {
		t.Errorf("%d aliasing groups after the retry, want 1", len(fh.ecmpGroups))
	}
}

// An uplink whose direct SID stops resolving is removed. When the removal
// fails, the session counts as a failed write, so the pass that follows
// removes it.
func TestReconcileTrackedRetriesT2STRemoval(t *testing.T) {
	a, fh, _, uplink := mupSourceLab(t)
	fh.mupUplinkDelErr = errors.New("busy")
	// The same session re-advertised without a SID, and no discovery route
	// resolves one.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: labGateEndpoint, TEID: 0xAB000000, TEIDLen: 8,
	}})
	if _, ok := fh.mupUplink[uplink]; !ok {
		t.Fatal("setup: uplink entry removed although its delete failed")
	}
	if err := a.ReconcileTracked(); err == nil {
		t.Fatal("ReconcileTracked reported success with the stale uplink entry still installed")
	}
	fh.mupUplinkDelErr = nil
	reconcileTracked(t, a)
	if _, ok := fh.mupUplink[uplink]; ok {
		t.Error("stale uplink entry still installed after the retry")
	}
	if _, ok := fh.v4created[labGatePrefix]; ok {
		t.Error("gate still installed after the last uplink on it was removed")
	}
}
