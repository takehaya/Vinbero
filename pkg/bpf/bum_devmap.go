package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// BUM replication modes, matching BUM_MODE_* in src/l2vpn/bum_xdp.h.
const (
	BumModeInherit uint8 = 0
	BumModeTC      uint8 = 1
	BumModeXDP     uint8 = 2
	// BumModeTCFallback: an xdp-mode BD on a host that cannot run xdp
	// mode. It takes the tc path and counts BUM_XDP_FALLBACK.
	BumModeTCFallback uint8 = 4
)

// BumSlotKeyBase marks a devmap key as remote flood slot (key = base | slot).
// Local ACs are keyed by ifindex. Matches BUM_SLOT_KEY_BASE.
const BumSlotKeyBase uint32 = 0x80000000

// bumDevmapMaxEntries matches BUM_DEVMAP_MAX_ENTRIES (inner devmap size).
const bumDevmapMaxEntries = 32

// BumUplink is where a remote PE's copies leave: the device, and the next
// hop on it (the gateway, or the PE itself when it is on link).
type BumUplink struct {
	Ifindex uint32
	Nexthop net.IP
}

// UplinkQuery is one uplink lookup: the arguments the data plane's FIB
// lookup uses for a copy to this peer (bum_egress.c).
type UplinkQuery struct {
	AC  uint32 // the BD's source AC: the device the lookup runs on
	Src [IPv6AddrLen]byte
	Dst [IPv6AddrLen]byte
}

// UplinkResolver returns the uplink a remote PE's copies are routed out of.
// The devmap entry of a flood slot transmits on that device.
type UplinkResolver func(q UplinkQuery) (BumUplink, error)

// KeepNeighResolved makes the neighbour entry of ip on ifindex a managed
// one (NTF_EXT_MANAGED): the kernel resolves it and keeps it resolved
// whether or not traffic uses it. It is marked extern_learn too, because
// neighbour GC spares only those: a managed entry alone that is FAILED
// while its next hop is down would be deleted and never probed again. The devmap egress program cannot hand an
// unresolved next hop to the kernel the way the main program's XDP_PASS
// does, so without this a peer that only gets BUM would wait for other
// traffic to resolve its uplink's next hop. Static entries (permanent,
// noarp) and managed ones are left as they are.
func KeepNeighResolved(ifindex uint32, ip net.IP) error {
	// The encapsulation next-hop keeper never gives back a BUM next hop.
	bumNeighClaims.Store(neighKey(ifindex, ip), struct{}{})
	family := netlink.FAMILY_V6
	if ip.To4() != nil {
		family = netlink.FAMILY_V4
	}
	neighs, err := netlink.NeighList(int(ifindex), family)
	if err != nil {
		return fmt.Errorf("list neighbours of %d: %w", ifindex, err)
	}
	for _, n := range neighs {
		if !n.IP.Equal(ip) {
			continue
		}
		if n.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0 || n.FlagsExt&netlink.NTF_EXT_MANAGED != 0 {
			return nil
		}
		break
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: int(ifindex), Family: family, IP: ip,
		State: netlink.NUD_NONE, Flags: netlink.NTF_EXT_LEARNED, FlagsExt: netlink.NTF_EXT_MANAGED,
	}); err != nil {
		return fmt.Errorf("make neighbour %s on %d managed: %w", ip, ifindex, err)
	}
	return nil
}

// BumDevmapSync keeps the xdp-mode devmaps (bum_flood_map, bum_local_map) in
// step with the maps they derive from. Every rebuild reads bd_config_map's
// mode, headend_l2_map (local ACs) and bd_peer_map (remote flood slots) and
// swaps a freshly built inner map into the outer one, so the devmap reflects
// whatever those maps hold after a mutation -- including a partially rolled
// back one -- and a restart only needs SyncAll.
type BumDevmapSync struct {
	mu        sync.Mutex // serializes rebuilds: a stale read must not overwrite a newer one
	objs      *BpfObjects
	egress    *ebpf.Program // bum_remote_egress, shared by every remote slot entry
	innerSpec *ebpf.MapSpec
	modeOf    func(bdID uint16) uint8
	uplink    UplinkResolver
	native    bool // native XDP: keep bum_tx_map in step too
	live      bool // XDP programs may be running (SetLive)
	logger    *zap.Logger
	// keepNeigh, when set, keeps each flood slot's next hop resolved
	// (KeepNeighResolved): the next hop the probe chose, so per ECMP member.
	keepNeigh func(ifindex uint32, nexthop net.IP) error
	// unserved holds the xdp-mode BDs the sync leaves on the tc path,
	// with the reason (unservable), so the change is logged once.
	unserved map[uint16]string
	// excluded holds the flood slots a failed lookup left out, with the
	// error, so each is logged once and the watch knows to retry them.
	excluded map[bdSlot]string
	// built holds what each BD's installed devmaps were built from: a
	// rebuild that would produce the same ones leaves them alone.
	built map[uint16]builtDevmaps
	// resync and resyncPoll: see uplinkResyncRose.
	resync     uint64
	resyncPoll time.Duration
	retryPoll  time.Duration // see bumExcludedRetry
	// routeSt follows the watch's subscription (WatchRoutes).
	routeSt *netlinksub.State
}

// NewBumDevmapSync binds the sync to a loaded collection. modeOf returns the
// effective BUM_MODE_* of a BD (config default or override). A nil uplink
// resolver uses the collection's probe program (ProbeUplinkResolver).
func NewBumDevmapSync(objs *BpfObjects, modeOf func(uint16) uint8, uplink UplinkResolver, logger *zap.Logger) *BumDevmapSync {
	if uplink == nil {
		uplink = ProbeUplinkResolver(objs.BumUplinkProbe)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BumDevmapSync{
		objs:   objs,
		egress: objs.BumRemoteEgress,
		innerSpec: &ebpf.MapSpec{
			Name:       "bum_devmap",
			Type:       ebpf.DevMapHash,
			KeySize:    4,
			ValueSize:  8, // struct bpf_devmap_val {ifindex, prog fd}
			MaxEntries: bumDevmapMaxEntries,
		},
		modeOf:   modeOf,
		uplink:   uplink,
		logger:   logger,
		unserved: map[uint16]string{},
		excluded: map[bdSlot]string{},
		built:    map[uint16]builtDevmaps{},

		resyncPoll: bumUplinkResyncPoll,
		retryPoll:  bumExcludedRetry,
		routeSt:    netlinksub.New(logger, "xdp BUM: routes"),
	}
}

// SetNativeXDP tells the sync that the data plane runs in native XDP
// (bum_xdp_native). Native XDP queues redirected frames per CPU and output
// device until the end of the NAPI poll, and runs the devmap program of the
// first frame queued on the whole queue (src/core/xdp_redirect.h). So every
// frame sent to a device the BUM devmaps send to must carry the same
// program, bum_remote_egress:
//
//   - every entry of both BD devmaps carries it, local ACs included; it
//     sends the copies without BUM metadata (post-decap flood) unchanged,
//     and tells local copies from remote ones with the plan;
//   - every such device, AC or uplink, has a bum_tx_map entry carrying it,
//     added before the first devmap that sends to the device is installed,
//     and every other redirect of the main program goes through that map.
//
// A device keeps its bum_tx_map entry when no BD uses it any more; that
// only costs its frames one pass through the program.
func (s *BumDevmapSync) SetNativeXDP(native bool) {
	s.mu.Lock()
	s.native = native
	s.mu.Unlock()
}

// SetLive tells the sync that the XDP programs are (about to be) attached,
// so a device that joins bum_tx_map must first wait out the NAPI polls in
// flight. Before that, nothing can be in flight and no rebuild waits.
func (s *BumDevmapSync) SetLive() {
	s.mu.Lock()
	s.live = true
	s.mu.Unlock()
}

// SetNeighKeeper installs the hook that keeps the flood slots' next hops
// resolved (KeepNeighResolved); nil disables it.
func (s *BumDevmapSync) SetNeighKeeper(keep func(ifindex uint32, nexthop net.IP) error) {
	s.mu.Lock()
	s.keepNeigh = keep
	s.mu.Unlock()
}

// devmapVal is struct bpf_devmap_val as written from userspace.
type devmapVal struct {
	Ifindex uint32
	ProgFD  uint32
}

// SyncBD rebuilds the devmaps of one bridge domain.
func (s *BumDevmapSync) SyncBD(bdID uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bdID == 0 {
		return nil
	}
	acs, err := s.scanACs()
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	b, err := s.buildBDLocked(bdID, acs[bdID], seen)
	if err != nil || b == nil {
		return err
	}
	return s.installLocked([]*bdBuild{b}, seen)
}

// bumAC is one headend_l2 entry of a BD: a local AC.
type bumAC struct {
	ifindex uint32
	vlanID  uint16
}

// splitACsReason is why a BD whose ACs resolve a peer differently runs in
// tc mode (resolveUplink, unservable).
const splitACsReason = "its ACs resolve a peer differently (an iif ip rule, a VRF, or an AC with no usable route), " +
	"and its devmap holds one uplink per peer"

// unservable returns why xdp mode cannot serve a BD with these ACs
// and this many flood slots, or "". Such a BD gets no devmap, so its BUM
// takes the tc path and the bridge (BUM_XDP_FALLBACK).
func unservable(acs []bumAC, ifindexes []uint32, slots int) string {
	// xdp mode forwards a frame with its VLAN tag unchanged, local copies
	// and known unicast alike. That is what the bridge does too as long as
	// every AC of the BD uses the same VLAN ID, whether its members are the
	// ports themselves or VLAN devices on them. With different VLAN IDs
	// only the bridge setup can say what a frame should look like on the
	// other ACs, and two ACs on one port must reach each other through it.
	for _, ac := range acs[1:] {
		if ac.vlanID != acs[0].vlanID {
			return fmt.Sprintf("its ACs use different VLAN IDs (%d and %d), and xdp mode forwards frames with their VLAN tag unchanged",
				acs[0].vlanID, ac.vlanID)
		}
	}
	if n := len(ifindexes) + slots; n > bumDevmapMaxEntries {
		return fmt.Sprintf("its %d AC devices and %d flood slots exceed the %d entries of a BD devmap",
			len(ifindexes), slots, bumDevmapMaxEntries)
	}
	return ""
}

// resolveUplink returns a peer's uplink. A BD has one devmap, so one uplink
// per peer, but the FIB lookup runs on the frame's own AC: the ACs of a BD
// agree unless an iif ip rule or a VRF sends one of them to another table.
// disagree reports such a split, an AC that has no usable route included;
// one devmap cannot serve that, so the BD takes the tc path, where every
// frame's copies are looked up on its own AC (splitACsReason). others are
// the answers of the other ACs that differ from up: their next hops need
// resolving too. An AC whose device is gone is passed over, the same as it
// is in the devmap.
func (s *BumDevmapSync) resolveUplink(acs []uint32, peer *HeadendEntry) (up BumUplink, others []BumUplink, disagree bool, err error) {
	found := false
	for _, ac := range acs {
		got, e := s.uplink(UplinkQuery{AC: ac, Src: peer.SrcAddr, Dst: peer.Segments[0]})
		switch {
		case errors.Is(e, unix.ENODEV):
			err = e
		case e != nil:
			err, disagree = e, true
		case !found:
			up, found = got, true
		case got.Ifindex != up.Ifindex:
			disagree = true
			others = append(others, got)
		case !got.Nexthop.Equal(up.Nexthop):
			others = append(others, got)
		}
	}
	if !found {
		return BumUplink{}, nil, false, err
	}
	return up, others, disagree, nil
}

// bdBuild is a BD's pair of freshly built devmaps, not installed yet.
type bdBuild struct {
	bd           uint16
	flood, local *ebpf.Map
	devices      []uint32 // every device the devmaps send to
	slots        []bumSlot
	state        builtDevmaps
}

type bumSlot struct {
	index   uint16
	uplink  uint32
	nexthop net.IP
	// others are what the BD's other ACs answered where it differs. Their
	// next hops need their neighbour entries too.
	others []BumUplink
}

// bdSlot names a flood slot of a BD.
type bdSlot struct {
	bd, index uint16
}

// devmapSlotKey is the part of a slot the devmaps hold.
type devmapSlotKey struct {
	index  uint16
	uplink uint32
}

// devmapKey is what a BD's devmaps hold: ifindexes sorted, slots in slot
// order.
type devmapKey struct {
	acs   []uint32
	slots []devmapSlotKey
}

func (k devmapKey) equal(o devmapKey) bool {
	return slices.Equal(k.acs, o.acs) && slices.Equal(k.slots, o.slots)
}

// builtDevmaps records a BD's installed devmaps: want is what they were
// built from, placed what could be added (a device that is gone cannot).
type builtDevmaps struct {
	want, placed devmapKey
}

func slotKeys(slots []bumSlot) []devmapSlotKey {
	keys := make([]devmapSlotKey, 0, len(slots))
	for _, sl := range slots {
		keys = append(keys, devmapSlotKey{index: sl.index, uplink: sl.uplink})
	}
	return keys
}

func (b *bdBuild) close() {
	_ = b.flood.Close()
	_ = b.local.Close()
}

// buildBDLocked builds the devmaps of one BD. A BD that gets no devmap is
// cleared right away, and the build is nil.
func (s *BumDevmapSync) buildBDLocked(bdID uint16, acs []bumAC, seen map[string]struct{}) (*bdBuild, error) {
	if s.modeOf(bdID) != BumModeXDP {
		return nil, s.clearBDLocked(bdID, "")
	}
	// A BD without a local AC keeps no devmap: the post-decap flood then
	// falls back to the bridge, and there is no AC ingress to flood from.
	if len(acs) == 0 {
		return nil, s.clearBDLocked(bdID, "")
	}
	ifindexes := make([]uint32, 0, len(acs))
	for _, ac := range acs {
		if !slices.Contains(ifindexes, ac.ifindex) {
			ifindexes = append(ifindexes, ac.ifindex)
		}
	}
	slices.Sort(ifindexes) // the same AC answers first on every rebuild

	var (
		slots []bumSlot
		split bool
	)
	left := map[uint16]struct{}{}
	for i := uint16(0); i < MaxBumNexthops; i++ {
		var peer HeadendEntry
		err := s.objs.BdPeerMap.Lookup(&BdPeerKey{BdId: bdID, Index: i}, &peer)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bd %d: read bd_peer %d: %w", bdID, i, err)
		}
		if peer.FloodExclude != 0 || peer.NumSegments < 1 {
			continue
		}
		up, others, disagree, err := s.resolveUplink(ifindexes, &peer)
		split = split || disagree
		if err != nil {
			// Not fatal: the slot rejoins on the next rebuild (route change,
			// BD mutation or bumExcludedRetry). Until then that peer gets no
			// BUM copy. Logged when it starts or its cause changes: the
			// retries repeat this for as long as the failure lasts.
			left[i] = struct{}{}
			key, msg := bdSlot{bd: bdID, index: i}, err.Error()
			log := s.logger.Debug
			if s.excluded[key] != msg {
				log = s.logger.Warn
			}
			s.excluded[key] = msg
			log("xdp BUM: cannot resolve the uplink of a flood peer; slot left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", i),
				zap.String("segment", net.IP(peer.Segments[0][:]).String()), zap.Error(err))
			continue
		}
		slots = append(slots, bumSlot{index: i, uplink: up.Ifindex, nexthop: up.Nexthop, others: others})
	}
	for key := range s.excluded {
		if _, still := left[key.index]; key.bd != bdID || still {
			continue
		}
		delete(s.excluded, key)
		// Not when the peer is simply gone.
		if slices.ContainsFunc(slots, func(sl bumSlot) bool { return sl.index == key.index }) {
			s.logger.Info("xdp BUM: flood slot is no longer left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", key.index))
		}
	}
	reason := unservable(acs, ifindexes, len(slots))
	if reason == "" && split {
		reason = splitACsReason
	}
	if reason != "" {
		// The tc path drops a copy whose next hop is unresolved, so these
		// BDs need their next hops resolved as much as xdp mode does.
		s.keepNeighsLocked(bdID, slots, seen)
		return nil, s.clearBDLocked(bdID, reason)
	}
	if (len(slots) > 0 || s.native) && s.egress == nil {
		return nil, fmt.Errorf("bd %d: bum_remote_egress is not loaded", bdID)
	}

	// Nothing to install when the BD's devmaps would come out the same. The
	// rebuilds a persistent drop triggers then cost a probe per peer and no
	// map swap (uplinkResyncRose).
	want := devmapKey{acs: ifindexes, slots: slotKeys(slots)}
	if s.devmapsCurrentLocked(bdID, want) {
		s.keepNeighsLocked(bdID, slots, seen)
		return nil, nil
	}

	flood, err := ebpf.NewMap(s.innerSpec)
	if err != nil {
		return nil, fmt.Errorf("bd %d: create flood devmap: %w", bdID, err)
	}
	local, err := ebpf.NewMap(s.innerSpec)
	if err != nil {
		_ = flood.Close()
		return nil, fmt.Errorf("bd %d: create local devmap: %w", bdID, err)
	}
	b := &bdBuild{bd: bdID, flood: flood, local: local, slots: slots, state: builtDevmaps{want: want, placed: want}}
	uplinks := make(map[uint32]struct{}, len(slots))
	for _, sl := range slots {
		uplinks[sl.uplink] = struct{}{}
	}
	for _, ifindex := range ifindexes {
		v := devmapVal{Ifindex: ifindex}
		if s.native {
			v.ProgFD = uint32(s.egress.FD()) // see SetNativeXDP
		}
		err := local.Put(ifindex, v)
		if err == nil {
			// An AC on the uplink of one of the BD's slots: that device's
			// copies all go through the egress program, which sends the
			// slots' copies encapsulated and one more unchanged (bum_egress.c).
			if _, both := uplinks[ifindex]; both {
				v.ProgFD = uint32(s.egress.FD())
			}
			err = flood.Put(ifindex, v)
		}
		if err == nil {
			b.devices = append(b.devices, ifindex)
		} else {
			// Not fatal, like an unresolvable slot: an AC whose device is
			// gone must not keep the rest of the BD on stale devmaps.
			b.state.placed.acs = slices.DeleteFunc(slices.Clone(b.state.placed.acs), func(ac uint32) bool { return ac == ifindex })
			_ = local.Delete(ifindex)
			s.logger.Warn("xdp BUM: cannot add a local AC to the BD devmap; AC left out",
				zap.Uint16("bd_id", bdID), zap.Uint32("ifindex", ifindex), zap.Error(err))
		}
	}
	for _, sl := range slots {
		// One entry per peer: an uplink with k peers behind it gets k
		// copies, and the egress program hands each the next slot of the
		// frame's plan for that uplink.
		v := devmapVal{Ifindex: sl.uplink, ProgFD: uint32(s.egress.FD())}
		err := flood.Put(BumSlotKeyBase|uint32(sl.index), v)
		if err == nil && !slices.Contains(b.devices, sl.uplink) {
			b.devices = append(b.devices, sl.uplink)
		}
		if err != nil {
			// The devmap has room (unservable), so the uplink device is
			// gone: like an unresolvable uplink, the slot waits for the
			// next rebuild.
			b.state.placed.slots = slices.DeleteFunc(slices.Clone(b.state.placed.slots), func(k devmapSlotKey) bool { return k.index == sl.index })
			s.logger.Warn("xdp BUM: cannot add a flood slot to the BD devmap; slot left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", sl.index), zap.Uint32("uplink", sl.uplink), zap.Error(err))
		}
	}
	return b, nil
}

// devmapsCurrentLocked reports whether the BD's installed devmaps are still
// what a build from want would produce. Comparing want is not enough: the
// kernel removes a device's entries when it unregisters, which moving it to
// another namespace and back does while its ifindex stays the same.
func (s *BumDevmapSync) devmapsCurrentLocked(bdID uint16, want devmapKey) bool {
	cur, ok := s.built[bdID]
	if !ok || !cur.want.equal(want) {
		return false
	}
	// A device left out because it was gone may be back.
	for _, ac := range want.acs {
		if !slices.Contains(cur.placed.acs, ac) && linkExists(ac) {
			return false
		}
	}
	for _, sl := range want.slots {
		if !slices.Contains(cur.placed.slots, sl) && linkExists(sl.uplink) {
			return false
		}
	}

	floodWant := make(map[uint32]uint32, len(cur.placed.acs)+len(cur.placed.slots))
	localWant := make(map[uint32]uint32, len(cur.placed.acs))
	for _, ac := range cur.placed.acs {
		floodWant[ac], localWant[ac] = ac, ac
	}
	for _, sl := range cur.placed.slots {
		floodWant[BumSlotKeyBase|uint32(sl.index)] = sl.uplink
	}
	if !s.devmapHolds(s.objs.BumFloodMap, bdID, floodWant) || !s.devmapHolds(s.objs.BumLocalMap, bdID, localWant) {
		return false
	}
	if s.native {
		for _, dev := range floodWant {
			var v devmapVal
			if err := s.objs.BumTxMap.Lookup(dev, &v); err != nil {
				return false
			}
		}
	}
	return true
}

// devmapHolds reports whether outer[bdID] has every entry of want (key to
// device). Anything unexpected, a read error included, counts as no: the
// caller then rebuilds.
func (s *BumDevmapSync) devmapHolds(outer *ebpf.Map, bdID uint16, want map[uint32]uint32) bool {
	var id ebpf.MapID
	if err := outer.Lookup(uint32(bdID), &id); err != nil {
		return false
	}
	inner, err := ebpf.NewMapFromID(id)
	if err != nil {
		return false
	}
	defer func() { _ = inner.Close() }()
	for key, dev := range want {
		var v devmapVal
		if err := inner.Lookup(key, &v); err != nil || v.Ifindex != dev {
			return false
		}
	}
	return true
}

func linkExists(ifindex uint32) bool {
	_, err := netlink.LinkByIndex(int(ifindex))
	return err == nil
}

// installLocked swaps the builds' devmaps in. In native XDP every device
// they send to gets its bum_tx_map entry first (SetNativeXDP); a BD whose
// device finds no room there runs in tc mode instead. Builds are closed.
func (s *BumDevmapSync) installLocked(builds []*bdBuild, seen map[string]struct{}) error {
	defer func() {
		for _, b := range builds {
			b.close()
		}
	}()
	failed := map[uint16]string{}
	if s.native {
		added := false
		for _, b := range builds {
			for _, ifindex := range b.devices {
				fresh, err := s.ensureBumTx(ifindex)
				if err != nil {
					failed[b.bd] = err.Error()
					break
				}
				added = added || fresh
			}
		}
		// A NAPI poll that redirected to a new device with a plain
		// bpf_redirect just before its entry appeared must be over before
		// a BD's copies can join that poll's queue. Once for all the
		// builds, and only once XDP runs.
		if added && s.live {
			time.Sleep(bumTxGrace)
		}
	}

	var errs []error
	for _, b := range builds {
		if reason, ok := failed[b.bd]; ok {
			s.keepNeighsLocked(b.bd, b.slots, seen) // it takes the tc path
			errs = append(errs, s.clearBDLocked(b.bd, reason))
			continue
		}
		key := uint32(b.bd)
		delete(s.built, b.bd) // until both maps are in
		if err := s.objs.BumLocalMap.Update(key, b.local, ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("bd %d: install local devmap: %w", b.bd, err))
			continue
		}
		if err := s.objs.BumFloodMap.Update(key, b.flood, ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("bd %d: install flood devmap: %w", b.bd, err))
			continue
		}
		s.built[b.bd] = b.state
		s.noteServedLocked(b.bd, "")
		s.keepNeighsLocked(b.bd, b.slots, seen)
	}
	return errors.Join(errs...)
}

// keepNeighsLocked keeps the next hops of a BD's flood slots resolved.
// seen dedupes the (device, next hop) pairs of one rebuild: each is a dump
// of the device's neighbours.
func (s *BumDevmapSync) keepNeighsLocked(bd uint16, slots []bumSlot, seen map[string]struct{}) {
	if s.keepNeigh == nil {
		return
	}
	for _, sl := range slots {
		for _, up := range append([]BumUplink{{Ifindex: sl.uplink, Nexthop: sl.nexthop}}, sl.others...) {
			if up.Nexthop == nil {
				continue
			}
			key := fmt.Sprintf("%d/%s", up.Ifindex, up.Nexthop)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			if err := s.keepNeigh(up.Ifindex, up.Nexthop); err != nil {
				s.logger.Debug("xdp BUM: cannot keep a flood slot's next hop resolved",
					zap.Uint16("bd_id", bd), zap.Uint16("index", sl.index), zap.Error(err))
			}
		}
	}
}

// clearBDLocked removes the BD's devmaps. reason, when set, says why an
// xdp-mode BD cannot run in xdp mode (it then takes the tc path).
func (s *BumDevmapSync) clearBDLocked(bdID uint16, reason string) error {
	key := uint32(bdID)
	var errs []error
	for _, m := range []*ebpf.Map{s.objs.BumFloodMap, s.objs.BumLocalMap} {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	s.noteServedLocked(bdID, reason)
	delete(s.built, bdID)
	if reason == "" { // no xdp-mode BD left to retry the slots of
		for key := range s.excluded {
			if key.bd == bdID {
				delete(s.excluded, key)
			}
		}
	}
	return errors.Join(errs...)
}

// bumTxGrace outlasts any NAPI poll in flight when an uplink joins
// bum_tx_map (a poll handles at most its budget of frames).
const bumTxGrace = 10 * time.Millisecond

// ensureBumTx adds ifindex to bum_tx_map unless it is there, and
// reports whether it added it.
func (s *BumDevmapSync) ensureBumTx(ifindex uint32) (bool, error) {
	var cur devmapVal
	err := s.objs.BumTxMap.Lookup(ifindex, &cur)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("read bum_tx_map[%d]: %w", ifindex, err)
	}
	if s.egress == nil {
		return false, errors.New("bum_remote_egress is not loaded")
	}
	v := devmapVal{Ifindex: ifindex, ProgFD: uint32(s.egress.FD())}
	if err := s.objs.BumTxMap.Update(ifindex, v, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return false, nil
		}
		return false, fmt.Errorf("add device %d to bum_tx_map: %w", ifindex, err)
	}
	return true, nil
}

// noteServedLocked logs when an xdp-mode BD starts or stops falling back
// to the tc path because of its configuration.
func (s *BumDevmapSync) noteServedLocked(bdID uint16, reason string) {
	prev, had := s.unserved[bdID]
	switch {
	case reason != "" && prev != reason:
		s.unserved[bdID] = reason
		s.logger.Warn("xdp BUM: bridge domain replicates BUM in tc mode (counted as BUM_XDP_FALLBACK)",
			zap.Uint16("bd_id", bdID), zap.String("reason", reason))
	case reason == "" && had:
		delete(s.unserved, bdID)
		s.logger.Info("xdp BUM: bridge domain replicates BUM in xdp mode again", zap.Uint16("bd_id", bdID))
	}
}

// scanACs returns the headend_l2 entries of every BD, keyed by BD.
func (s *BumDevmapSync) scanACs() (map[uint16][]bumAC, error) {
	var (
		key   HeadendL2Key
		entry HeadendEntry
	)
	out := map[uint16][]bumAC{}
	iter := s.objs.HeadendL2Map.Iterate()
	for iter.Next(&key, &entry) {
		if entry.BdId == 0 || key.Ifindex == 0 {
			continue
		}
		out[entry.BdId] = append(out[entry.BdId], bumAC{ifindex: key.Ifindex, vlanID: key.VlanId})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan headend_l2: %w", err)
	}
	return out, nil
}

// SyncAll rebuilds every BD the maps know about and drops devmaps of BDs
// that no longer exist.
func (s *BumDevmapSync) SyncAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acs, err := s.scanACs()
	if err != nil {
		return err
	}
	bds := map[uint16]struct{}{}
	for bd := range acs {
		bds[bd] = struct{}{}
	}
	var outerKey uint32
	var innerID ebpf.MapID
	for _, outer := range []*ebpf.Map{s.objs.BumFloodMap, s.objs.BumLocalMap} {
		it := outer.Iterate()
		for it.Next(&outerKey, &innerID) {
			bds[uint16(outerKey)] = struct{}{}
		}
		if err := it.Err(); err != nil {
			return fmt.Errorf("scan BUM devmaps: %w", err)
		}
	}

	var (
		errs   []error
		builds []*bdBuild
		seen   = map[string]struct{}{}
	)
	for bd := range bds {
		b, err := s.buildBDLocked(bd, acs[bd], seen)
		if err != nil {
			errs = append(errs, err)
		}
		if b != nil {
			builds = append(builds, b)
		}
	}
	errs = append(errs, s.installLocked(builds, seen))
	return errors.Join(errs...)
}

// WatchRoutes rebuilds every BD (debounced) when the routing table or a
// nexthop object changes, or when the egress program drops copies whose
// uplink no longer matches the devmap, so a flood slot follows its peer's
// uplink and a slot whose route appears late joins. It returns when ctx is
// done.
func (s *BumDevmapSync) WatchRoutes(ctx context.Context, debounce time.Duration) error {
	sub, err := s.subscribeRoutes()
	if err != nil {
		return fmt.Errorf("subscribe to route updates: %w", err)
	}
	s.uplinkResyncRose() // copies dropped so far are not this watch's business
	go s.watchRoutes(ctx, sub, debounce)
	return nil
}

// routeSub is the route, nexthop-object and ip-rule subscription. nexthops
// carries a value per batch of nexthop and rule messages. Either channel
// closes when its subscription ends; done stops both.
type routeSub struct {
	routes   chan netlink.RouteUpdate
	nexthops chan struct{}
	done     chan struct{}
}

func (s *BumDevmapSync) subscribeRoutes() (*routeSub, error) {
	if s.routeSt == nil {
		s.routeSt = netlinksub.New(s.logger, "xdp BUM: routes")
	}
	return subscribeRouteEvents(s.routeSt)
}

// subscribeRouteEvents subscribes to route updates, nexthop-object updates
// and IPv6 rule updates (see routeSub). The BUM devmap sync and the
// encapsulation next-hop keeper share it; st gets the subscriptions' errors.
func subscribeRouteEvents(st *netlinksub.State) (*routeSub, error) {
	r := &routeSub{
		routes:   make(chan netlink.RouteUpdate, 256),
		nexthops: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	err := netlink.RouteSubscribeWithOptions(r.routes, r.done, netlink.RouteSubscribeOptions{
		ErrorCallback:     st.OnError,
		ReceiveBufferSize: 1 << 20, // a full table load must not overflow it
	})
	if err != nil {
		close(r.done)
		return nil, err
	}
	// A group change that does not touch routes (nexthop_compat_mode=0, a
	// member removed) only shows up here, and so does an ip rule that sends
	// an AC to another table. vishvananda/netlink has no API for the nexthop
	// group, but a raw subscription is enough: any message means a rebuild.
	nh, err := nl.Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_NEXTHOP, unix.RTNLGRP_IPV6_RULE)
	if err != nil {
		close(r.done)
		return nil, fmt.Errorf("subscribe to nexthop updates: %w", err)
	}
	if err := nh.SetReceiveBufferSize(1<<20, false); err != nil {
		st.OnError(fmt.Errorf("grow the nexthop socket's buffer: %w", err))
	}
	go func() {
		<-r.done
		nh.Close()
	}()
	go func() {
		defer close(r.nexthops)
		for {
			if _, _, err := nh.Receive(); err != nil {
				select {
				case <-r.done:
				default:
					st.OnError(fmt.Errorf("nexthop subscription: %w", err))
				}
				return
			}
			select {
			case r.nexthops <- struct{}{}:
			case <-r.done:
				return
			default: // a rebuild is already on its way
			}
		}
	}()
	return r, nil
}

// routeSyncMaxDelay caps how long a steady stream of route updates can
// postpone the rebuild, in multiples of the debounce.
const routeSyncMaxDelay = 10

// bumUplinkResyncPoll is how often the watch reads bum_uplink_resync.
const bumUplinkResyncPoll = time.Second

// uplinkResyncRose reports whether the egress program counted more copies
// in bum_uplink_resync since the last call (bum_xdp.h). No event announces
// some of what moves a peer to another next hop or leaves it unresolved: a
// sysctl (fib_multipath_hash_policy 3's fields, the hash seed), a gateway's
// neighbour going FAILED or INCOMPLETE in a hash-threshold group, a carrier
// change, a nexthop the kernel flushes when its device goes down. A rebuild
// probes again and makes the new next hop a managed neighbour.
func (s *BumDevmapSync) uplinkResyncRose() bool {
	var perCPU []uint64
	if err := s.objs.BumUplinkResync.Lookup(uint32(0), &perCPU); err != nil {
		s.logger.Debug("xdp BUM: cannot read bum_uplink_resync", zap.Error(err))
		return false
	}
	var sum uint64
	for _, n := range perCPU {
		sum += n
	}
	rose := sum != s.resync
	s.resync = sum
	return rose
}

// bumExcludedRetry is how often the watch rebuilds while something waits
// for a lookup to work again: a slot a failed probe left out, or a BD on the
// tc path because its ACs disagree. Those produce no copy, so the resync
// counter cannot report them, and what fixes them may send no event (the
// AC's forwarding sysctl). A pass is a probe per peer and AC, plus no map
// swap when the result is unchanged. 30 s bounds how long a peer stays dark
// after such a fix while keeping the rounds rare for as long as the failure
// lasts, which can be indefinitely on a misconfigured AC.
const bumExcludedRetry = 30 * time.Second

// retryPending reports whether a rebuild could bring something back. A BD
// that xdp mode cannot serve for its configuration cannot: its slots stay
// recorded, so they warn once, but only a BD that may return counts.
func (s *BumDevmapSync) retryPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.excluded {
		if reason, unserved := s.unserved[key.bd]; !unserved || reason == splitACsReason {
			return true
		}
	}
	for _, reason := range s.unserved {
		if reason == splitACsReason {
			return true
		}
	}
	return false
}

func (s *BumDevmapSync) watchRoutes(ctx context.Context, sub *routeSub, debounce time.Duration) {
	timer := time.NewTimer(debounce)
	timer.Stop()
	resync := time.NewTicker(s.resyncPoll)
	defer resync.Stop()
	retry := time.NewTicker(s.retryPoll)
	defer retry.Stop()
	var (
		fire  <-chan time.Time
		first time.Time // first update since the last rebuild
	)
	schedule := func(d time.Duration) {
		timer.Stop()
		timer.Reset(d)
		fire = timer.C
	}
	pending := func() {
		now := time.Now()
		if first.IsZero() {
			first = now
		}
		wait := debounce
		if left := first.Add(routeSyncMaxDelay * debounce).Sub(now); left < wait {
			wait = max(left, 0)
		}
		schedule(wait)
	}
	// The subscription ended (typically ENOBUFS: the kernel dropped
	// notifications). It is subscribed again after a wait (netlinksub)
	// while the polls go on, and as updates may be lost, everything is
	// rebuilt once it is back.
	var again <-chan time.Time
	ended := func() {
		close(sub.done)
		go drain(sub.routes)
		sub = nil
		again = time.After(s.routeSt.Ended())
	}
	defer func() {
		timer.Stop()
		if sub != nil {
			close(sub.done)
			go drain(sub.routes)
		}
	}()
	for {
		var (
			routesC   <-chan netlink.RouteUpdate
			nexthopsC <-chan struct{}
		)
		if sub != nil {
			routesC, nexthopsC = sub.routes, sub.nexthops
		}
		select {
		case <-ctx.Done():
			return
		case _, ok := <-routesC:
			if !ok {
				ended()
				continue
			}
			pending()
		case _, ok := <-nexthopsC:
			if !ok {
				ended()
				continue
			}
			pending()
		case <-again:
			again = nil
			next, err := s.subscribeRoutes()
			if err != nil {
				again = time.After(s.routeSt.Failed(err))
				continue
			}
			sub = next
			s.routeSt.Restored()
			first = time.Time{}
			schedule(0)
		case <-resync.C:
			if s.uplinkResyncRose() {
				pending()
			}
		case <-retry.C:
			if s.retryPending() {
				pending()
			}
		case <-fire:
			fire = nil
			first = time.Time{}
			if err := s.SyncAll(); err != nil {
				s.logger.Warn("xdp BUM: devmap rebuild after a route change failed", zap.Error(err))
			}
		}
	}
}

// SetBdBumMode writes a per-BD override into bd_config_map.
func (m *MapOperations) SetBdBumMode(bdID uint16, mode uint8) error {
	key := uint32(bdID)
	return m.objs.BdConfigMap.Put(key, &BpfBdConfig{BumMode: mode})
}

// SetBumDevmapSync wires the xdp-mode devmap rebuild into the bd_peer and
// headend_l2 mutations. Nil disables it.
func (m *MapOperations) SetBumDevmapSync(s *BumDevmapSync) {
	m.bumMu.Lock()
	m.bum = s
	m.bumMu.Unlock()
}

// resyncBum rebuilds a BD's devmaps after a mutation. Errors are logged by
// the sync, not returned: the authoritative maps are already written, and
// the next mutation or route change retries.
func (m *MapOperations) resyncBum(bdIDs ...uint16) {
	m.bumMu.Lock()
	s := m.bum
	m.bumMu.Unlock()
	if s == nil {
		return
	}
	for _, bd := range bdIDs {
		if err := s.SyncBD(bd); err != nil {
			s.logger.Warn("xdp BUM: devmap rebuild failed", zap.Uint16("bd_id", bd), zap.Error(err))
		}
	}
}
