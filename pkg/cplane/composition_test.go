package cplane

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/pkg/headend"
	"google.golang.org/protobuf/proto"
)

type serviceFake struct {
	uplinks6        map[bpf.MupUplinkV6Key]bpf.OwnerTag
	failV6Inventory bool
	*fakeHeadendOps
	uplinks                     map[bpf.MupUplinkV4Key]bpf.OwnerTag
	entries                     map[bpf.MupUplinkV4Key]bpf.HeadendEntry
	fdb                         map[bpf.FdbKey]bpf.OwnerTag
	peers                       map[bpf.BdPeerKey]bpf.OwnerTag
	peerEntries                 map[bpf.BdPeerKey]*bpf.HeadendEntry
	failFTDelete, failFDBDelete bool
}

func newServiceFake() *serviceFake {
	return &serviceFake{fakeHeadendOps: newFakeHeadendOps(), uplinks: map[bpf.MupUplinkV4Key]bpf.OwnerTag{}, entries: map[bpf.MupUplinkV4Key]bpf.HeadendEntry{}, fdb: map[bpf.FdbKey]bpf.OwnerTag{}, peers: map[bpf.BdPeerKey]bpf.OwnerTag{}, peerEntries: map[bpf.BdPeerKey]*bpf.HeadendEntry{}}
}
func serviceKey(id uint32, ep string, teid uint32, bits uint8) bpf.MupUplinkV4Key {
	k := bpf.MupUplinkV4Key{Prefixlen: 64 + uint32(bits), Endpoint: netip.MustParseAddr(ep).As4()}
	binary.BigEndian.PutUint32(k.Instance[:], id)
	binary.BigEndian.PutUint32(k.Teid[:], teid)
	return k
}
func (f *serviceFake) CreateMupUplinkV4Owned(id uint32, ep string, teid uint32, bits uint8, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	k := serviceKey(id, ep, teid, bits)
	if old := f.uplinks[k]; old != "" && old != o {
		return bpf.ErrEntryOwnerMismatch
	}
	f.uplinks[k] = o
	f.entries[k] = *e
	return nil
}
func (f *serviceFake) DeleteMupUplinkV4Owned(id uint32, ep string, teid uint32, bits uint8, o bpf.OwnerTag) error {
	if f.failFTDelete {
		return errors.New("FT delete failed")
	}
	k := serviceKey(id, ep, teid, bits)
	if old := f.uplinks[k]; old != "" && old != o {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(f.uplinks, k)
	delete(f.entries, k)
	return nil
}
func (f *serviceFake) DeleteMupUplinkV6Owned(id uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	k := bpf.MupUplinkV6Key{Prefixlen: 160 + uint32(bits), Endpoint: netip.MustParseAddr(ep).As16()}
	binary.BigEndian.PutUint32(k.Instance[:], id)
	binary.BigEndian.PutUint32(k.Teid[:], teid)
	if old := f.uplinks6[k]; old != "" && old != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(f.uplinks6, k)
	return nil
}
func (f *serviceFake) ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error) {
	return cloneMap(f.uplinks), nil
}
func (f *serviceFake) ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error) {
	if f.failV6Inventory {
		return nil, errors.New("inventory failed")
	}
	return cloneMap(f.uplinks6), nil
}
func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	o := map[K]V{}
	for k, v := range m {
		o[k] = v
	}
	return o
}
func (f *serviceFake) ListFdbOwners() (map[bpf.FdbKey]bpf.OwnerTag, error) {
	return cloneMap(f.fdb), nil
}
func (f *serviceFake) ListBdPeerOwners() (map[bpf.BdPeerKey]bpf.OwnerTag, error) {
	return cloneMap(f.peers), nil
}
func (f *serviceFake) ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error) {
	return cloneMap(f.peerEntries), nil
}
func fk(bd uint16, mac net.HardwareAddr) bpf.FdbKey {
	k := bpf.FdbKey{BdId: bd}
	copy(k.Mac[:], mac)
	return k
}
func (f *serviceFake) CreateFdbOwned(bd uint16, mac net.HardwareAddr, e *bpf.FdbEntry, o bpf.OwnerTag) error {
	k := fk(bd, mac)
	if old := f.fdb[k]; old != "" && old != o {
		return bpf.ErrEntryOwnerMismatch
	}
	f.fdb[k] = o
	return nil
}
func (f *serviceFake) DeleteFdbOwned(bd uint16, mac net.HardwareAddr, o bpf.OwnerTag) error {
	if f.failFDBDelete {
		return errors.New("FDB delete failed")
	}
	k := fk(bd, mac)
	if old := f.fdb[k]; old != "" && old != o {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(f.fdb, k)
	return nil
}
func (f *serviceFake) CreateBdPeerOwned(bd, idx uint16, e *bpf.HeadendEntry, _ [bpf.ESILen]byte, _ [16]byte, _ bool, o bpf.OwnerTag) error {
	k := bpf.BdPeerKey{BdId: bd, Index: idx}
	if old := f.peers[k]; old != "" && old != o {
		return bpf.ErrEntryOwnerMismatch
	}
	f.peers[k] = o
	c := *e
	f.peerEntries[k] = &c
	return nil
}
func (f *serviceFake) CreateBdPeerAtFreeIndexOwned(bd uint16, e *bpf.HeadendEntry, esi [bpf.ESILen]byte, remote [16]byte, rev bool, o bpf.OwnerTag) (uint16, error) {
	for i := uint16(0); i < 64; i++ {
		if f.peers[bpf.BdPeerKey{BdId: bd, Index: i}] == "" {
			return i, f.CreateBdPeerOwned(bd, i, e, esi, remote, rev, o)
		}
	}
	return 0, errors.New("peer limit")
}
func (f *serviceFake) DeleteBdPeerOwned(bd, idx uint16, o bpf.OwnerTag) (bool, error) {
	k := bpf.BdPeerKey{BdId: bd, Index: idx}
	if old := f.peers[k]; old != "" && old != o {
		return true, bpf.ErrEntryOwnerMismatch
	}
	delete(f.peers, k)
	delete(f.peerEntries, k)
	return true, nil
}
func compositionPolicy() *v1.CplaneInputPolicy {
	return &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "mobile", Grants: []*v1.CplaneInputGrant{{Families: []string{"mup_ipv4", "mup_ipv6", "evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateMupTypes: []uint32{3, 4}, EndpointPrefixes: []string{"192.0.2.0/24"}, TeidPrefixes: []string{"0/0"}, DelegateEvpn: true, BridgeDomain: 100}}}
}
func compositionOps(t *testing.T) (*PluginOps, *serviceFake) {
	t.Helper()
	f := newServiceFake()
	r, err := headend.NewReconciler(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newCompositionMaps(f, r)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := parseInputPolicy(compositionPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	caps, _ := wasm.ParseCapabilities([]string{"headend", "mup", "evpn"})
	p, err := NewPluginOps(PluginOpsConfig{Owner: bpf.OwnerPluginBundle("compose"), HeadendReconciler: r, Services: s, Policy: policy, StrictInputs: true, Capabilities: caps, Guard: NewGuard(scope, nil, nil), ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.finishInputReplay(); err != nil {
		t.Fatal(err)
	}
	if err = p.Publish(); err != nil {
		t.Fatal(err)
	}
	return p, f
}
func putComposition(p *PluginOps, m *v1.PluginApplyChunk) error {
	g, e := p.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_COMPOSITION))
	if e != nil {
		return e
	}
	b, e := proto.Marshal(m)
	if e != nil {
		return e
	}
	if e = p.ApplyPut(g, b); e != nil {
		p.ApplyAbort(g)
		return e
	}
	return p.ApplyCommit(g)
}
func desiredComposition(rev uint64) *v1.PluginApplyChunk {
	return &v1.PluginApplyChunk{DesiredRevision: rev, ForwardingHeadends: []*v1.PluginForwardingHeadend{{Context: "mobile", Entry: &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.1/32", Segments: []string{"fd00:a::1"}, SrcAddr: "fd00:feed::1"}}}, MupUplinks: []*v1.PluginMupUplink{{Context: "mobile", Endpoint: "192.0.2.1", Teid: 256, TeidBits: 32, Segments: []string{"fd00:b::1"}, SrcAddr: "fd00:feed::1"}}, EvpnForwards: []*v1.PluginEvpnForward{{Context: "mobile", Mac: "02:00:00:00:00:01", Segments: []string{"fd00:c::1"}, SrcAddr: "fd00:feed::1", RemoteSrc: "fd00:c::2", Flood: true}}}
}
func TestCompositionPermissionAndCleanup(t *testing.T) {
	p, f := compositionOps(t)
	m := desiredComposition(1)
	if err := putComposition(p, m); err != nil {
		t.Fatal(err)
	}
	if len(f.v4) != 2 || len(f.uplinks) != 1 || len(f.fdb) != 1 || len(f.peers) != 1 {
		t.Fatalf("incomplete outputs: %+v", f)
	}
	for _, e := range f.entries {
		if e.ArgsOffset != bpf.MupArgsOffsetNone {
			t.Fatal("uplink SID unexpectedly patched")
		}
	}
	bad := desiredComposition(2)
	bad.MupUplinks[0].Endpoint = "198.51.100.1"
	if err := putComposition(p, bad); err == nil {
		t.Fatal("out of scope accepted")
	}
	if len(f.uplinks) != 1 || len(f.fdb) != 1 {
		t.Fatal("invalid desired partially applied")
	}
	f.failFTDelete = true
	if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 3}); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if len(f.uplinks) != 1 || f.owner4["192.0.2.1/32"] != headend.MUPGateOwner {
		t.Fatal("released FT dependency")
	}
	f.failFTDelete = false
	p.RetryPending()
	if len(f.v4) != 0 || len(f.uplinks) != 0 || len(f.peers) != 0 || len(f.fdb) != 0 {
		t.Fatal("cleanup retry did not converge")
	}
	desired, applied, failure := p.OutputState()
	if desired != 3 || applied != 3 || failure != "" {
		t.Fatalf("output stats %d %d %q", desired, applied, failure)
	}
}
func TestCompositionLatestFailureSuppressesOldRetry(t *testing.T) {
	p, f := compositionOps(t)
	old := desiredComposition(1)
	f.failOn = "10.0.0.1/32"
	if err := putComposition(p, old); err == nil {
		t.Fatal("missing failure")
	}
	newer := desiredComposition(2)
	newer.ForwardingHeadends[0].Context = "ungranted"
	if err := putComposition(p, newer); err == nil {
		t.Fatal("missing context refusal")
	}
	f.failOn = ""
	p.RetryPending()
	if len(f.uplinks) != 0 || len(f.v4) != 0 {
		t.Fatal("old retry resurrected")
	}
	if err := putComposition(p, old); err == nil {
		t.Fatal("backwards revision accepted")
	}
}
func TestCompositionInputLossAndReplay(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	f.failFDBDelete = true
	if err := p.failInput("lost input"); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	ready, _, pending := p.InputState()
	if ready || !pending || len(f.peers) == 0 {
		t.Fatal("failed cleanup not reserved")
	}
	if _, err := p.ApplyBegin(5); err == nil {
		t.Fatal("write allowed on incomplete input")
	}
	f.failFDBDelete = false
	p.RetryPending()
	if len(f.fdb) != 0 || len(f.peers) != 0 {
		t.Fatal("cleanup did not retry")
	}
	p.beginInputReplay()
	if err := putComposition(p, desiredComposition(2)); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 0 {
		t.Fatal("wrote before replay barrier")
	}
	if err := p.finishInputReplay(); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 1 {
		t.Fatal("replay desired not published")
	}
}
func TestSharedMUPGateRetainsOtherOwner(t *testing.T) {
	p, f := compositionOps(t)
	builtin := bpf.OwnerBGPMUPGate(65000)
	mode := uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)
	if err := p.headend.SetGateReferences(AFv4, "192.0.2.1/32", mode, builtin, 1); err != nil {
		t.Fatal(err)
	}
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.owner4["192.0.2.1/32"] != headend.MUPGateOwner {
		t.Fatal("deleted sibling gate")
	}
	f.failDel = "192.0.2.1/32"
	if err := p.headend.SetGateReferences(AFv4, "192.0.2.1/32", mode, builtin, 0); err == nil {
		t.Fatal("delete failure ignored")
	}
	f.failDel = ""
	if err := p.headend.SetGateReferences(AFv4, "192.0.2.1/32", mode, builtin, 0); err != nil {
		t.Fatal(err)
	}
	if len(f.v4) != 0 {
		t.Fatal("gate leaked")
	}
}
func TestCompositionChunkAtomicity(t *testing.T) {
	p, _ := compositionOps(t)
	g, err := p.ApplyBegin(5)
	if err != nil {
		t.Fatal(err)
	}
	m := desiredComposition(1)
	m.HeadendEntries = []*v1.PluginHeadendEntry{{TriggerPrefix: "10.0.0.1/32"}}
	b, _ := proto.Marshal(m)
	if err := p.ApplyPut(g, b); err == nil {
		t.Fatal("mixed legacy output accepted")
	}
	if err := p.ApplyCommit(g); err == nil {
		t.Fatal("missing revision accepted")
	}
}

func TestCompositionGateCanBecomeHeadend(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	m := desiredComposition(2)
	m.MupUplinks = nil
	m.ForwardingHeadends[0].Entry.TriggerPrefix = "192.0.2.1/32"
	if err := putComposition(p, m); err != nil {
		t.Fatal(err)
	}
	if f.owner4["192.0.2.1/32"] != p.owner || len(f.uplinks) != 0 {
		t.Fatal("old gate blocked replacement")
	}
}
func TestCompositionEVPNReverseIsUnicastOnly(t *testing.T) {
	p, _ := compositionOps(t)
	m := desiredComposition(1)
	flood := proto.Clone(m.EvpnForwards[0]).(*v1.PluginEvpnForward)
	flood.Mac = ""
	flood.Segments = []string{"fd00:c::3"}
	m.EvpnForwards[0].Flood = false
	m.EvpnForwards = append(m.EvpnForwards, flood)
	if _, err := p.normalizeComposition(m); err != nil {
		t.Fatal(err)
	}
	conflict := proto.Clone(m.EvpnForwards[0]).(*v1.PluginEvpnForward)
	conflict.Mac = "02:00:00:00:00:02"
	conflict.Segments = []string{"fd00:c::4"}
	m.EvpnForwards = append(m.EvpnForwards, conflict)
	if _, err := p.normalizeComposition(m); err == nil {
		t.Fatal("multiple reverse unicast peers accepted")
	}
}
func TestCompositionForwardingInventorySurvivesRestart(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	r, err := headend.NewReconciler(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newCompositionMaps(f, r)
	if err != nil {
		t.Fatal(err)
	}
	if f.owner4["192.0.2.1/32"] != headend.MUPGateOwner {
		t.Fatal("recovery removed gate")
	}
	f.failFTDelete = true
	if err = s.flush(p.owner); err == nil {
		t.Fatal("hidden failure")
	}
	owners, err := s.inventoryOwners()
	if err != nil || !owners[p.owner] {
		t.Fatal("failed cleanup lost inventory")
	}
	f.failFTDelete = false
	if err = s.flush(p.owner); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 0 || len(f.fdb) != 0 || len(f.peers) != 0 {
		t.Fatal("cold cleanup leaked")
	}
}

func TestCompositionRevisionRestartsWithGuest(t *testing.T) {
	p, _ := compositionOps(t)
	if err := putComposition(p, desiredComposition(100)); err != nil {
		t.Fatal(err)
	}
	if err := p.failInput("trap"); err != nil {
		t.Fatal(err)
	}
	p.BeginInstance()
	p.beginInputReplay()
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	if err := p.finishInputReplay(); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(); err != nil {
		t.Fatal(err)
	}
	desired, applied, failure := p.OutputState()
	if desired != 1 || applied != 1 || failure != "" {
		t.Fatalf("new guest blocked by previous revision: %d %d %q", desired, applied, failure)
	}
}

func TestCompositionInventoryFailureRetainsGate(t *testing.T) {
	f := newServiceFake()
	owner := bpf.OwnerPluginBundle("v6-remnant")
	k := bpf.MupUplinkV6Key{Prefixlen: 192, Endpoint: netip.MustParseAddr("fd00::1").As16()}
	f.uplinks6 = map[bpf.MupUplinkV6Key]bpf.OwnerTag{k: owner}
	r, err := headend.NewReconciler(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newCompositionMaps(f, r)
	if err != nil {
		t.Fatal(err)
	}
	f.failV6Inventory = true
	if err = s.flush(owner); err == nil {
		t.Fatal("inventory failure ignored")
	}
	if f.owner6["fd00::1/128"] != headend.MUPGateOwner {
		t.Fatal("unknown live dependency released")
	}
	f.failV6Inventory = false
	if err = s.flush(owner); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks6) != 0 || len(f.v6) != 0 {
		t.Fatal("recovery cleanup failed")
	}
}

func TestCompositionQueueRecoveryNeedsFreshReplayAfterCleanup(t *testing.T) {
	p, f := compositionOps(t)
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	f.failFTDelete = true
	p.noteInputLoss()
	p.beginInputReplay()
	p.RetryPending()
	if p.takeInputRecoveryReplay() {
		t.Fatal("replay before cleanup completed")
	}
	if err := p.finishInputReplay(); err == nil {
		t.Fatal("incomplete replay authorized output")
	}
	f.failFTDelete = false
	p.RetryPending()
	if !p.takeInputRecoveryReplay() {
		t.Fatal("cleanup did not request fresh replay")
	}
	if p.takeInputRecoveryReplay() {
		t.Fatal("replay request not consumed")
	}
	p.beginInputReplay()
	if err := p.finishInputReplay(); err != nil {
		t.Fatal(err)
	}
	if err := putComposition(p, desiredComposition(2)); err != nil {
		t.Fatal(err)
	}
}

func TestCompositionReconcilesHostInstanceChange(t *testing.T) {
	p, f := compositionOps(t)
	id := uint32(7)
	p.resolveMUPInstance = func(string) (uint32, error) { return id, nil }
	if err := putComposition(p, desiredComposition(1)); err != nil {
		t.Fatal(err)
	}
	id = 8
	if _, err := p.ReconcileAdvertised(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.uplinks) != 1 {
		t.Fatal("old instance leaked")
	}
	for k := range f.uplinks {
		if binary.BigEndian.Uint32(k.Instance[:]) != 8 {
			t.Fatal("host-derived instance change ignored")
		}
	}
}
