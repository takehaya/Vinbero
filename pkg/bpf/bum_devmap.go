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
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
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

// UplinkResolver returns the uplink a remote PE's first segment is routed
// out of. The devmap entry of a flood slot transmits on that device.
type UplinkResolver func(firstSegment [IPv6AddrLen]byte) (BumUplink, error)

// RouteUplinkResolver resolves through the kernel routing table of the
// current network namespace.
func RouteUplinkResolver(seg [IPv6AddrLen]byte) (BumUplink, error) {
	dst := net.IP(seg[:])
	routes, err := netlink.RouteGet(dst)
	if err != nil {
		return BumUplink{}, err
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return BumUplink{}, fmt.Errorf("no route to %s", dst)
	}
	nh := routes[0].Gw
	if nh == nil {
		nh = dst
	}
	return BumUplink{Ifindex: uint32(routes[0].LinkIndex), Nexthop: nh}, nil
}

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
	native    bool // native XDP: keep uplink_tx_map in step too
	logger    *zap.Logger
	// keepNeigh, when set, keeps each flood slot's next hop resolved
	// (KeepNeighResolved).
	keepNeigh func(ifindex uint32, nexthop net.IP) error
	// unserved holds the xdp-mode BDs the sync leaves on the tc path,
	// with the reason (unservable), so the change is logged once.
	unserved map[uint16]string
}

// NewBumDevmapSync binds the sync to a loaded collection. modeOf returns the
// effective BUM_MODE_* of a BD (config default or override).
func NewBumDevmapSync(objs *BpfObjects, modeOf func(uint16) uint8, uplink UplinkResolver, logger *zap.Logger) *BumDevmapSync {
	if uplink == nil {
		uplink = RouteUplinkResolver
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
	}
}

// SetNativeXDP tells the sync that the data plane runs in native XDP
// (bum_xdp_native). Every uplink of a flood slot then also gets an
// uplink_tx_map entry carrying bum_remote_egress before the first BD devmap
// that sends through it is installed: native XDP runs one egress program
// per output-device queue, so all redirects to an uplink must carry the
// same one (src/core/xdp_redirect.h). An uplink that no BD uses any more
// keeps its entry; that only costs its unicast frames one pass through the
// program.
//
// A local AC of an xdp-mode BD cannot be an uplink: the BD devmaps send it
// local copies without a program, and its queue would mix those with
// remote copies or unicast frames that carry one. Such a slot is left out,
// and the AC's device is dropped from uplink_tx_map. Since an AC change can
// affect the slots of every BD, it rebuilds them all (SyncACs).
func (s *BumDevmapSync) SetNativeXDP(native bool) {
	s.mu.Lock()
	s.native = native
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
	return s.syncBDLocked(bdID, acs[bdID], s.xdpACsLocked(acs))
}

// xdpACsLocked returns the AC devices of every xdp-mode BD.
func (s *BumDevmapSync) xdpACsLocked(acs map[uint16][]bumAC) map[uint32]struct{} {
	all := map[uint32]struct{}{}
	for bd, list := range acs {
		if s.modeOf(bd) != BumModeXDP {
			continue
		}
		for _, ac := range list {
			all[ac.ifindex] = struct{}{}
		}
	}
	return all
}

// bumAC is one headend_l2 entry of a BD: a local AC.
type bumAC struct {
	ifindex uint32
	vlanID  uint16
}

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

func (s *BumDevmapSync) syncBDLocked(bdID uint16, acs []bumAC, allACs map[uint32]struct{}) error {
	if s.modeOf(bdID) != BumModeXDP {
		return s.clearBDLocked(bdID, "")
	}
	// A BD without a local AC keeps no devmap: the post-decap flood then
	// falls back to the bridge, and there is no AC ingress to flood from.
	if len(acs) == 0 {
		return s.clearBDLocked(bdID, "")
	}
	ifindexes := make([]uint32, 0, len(acs))
	for _, ac := range acs {
		if !slices.Contains(ifindexes, ac.ifindex) {
			ifindexes = append(ifindexes, ac.ifindex)
		}
	}

	type slot struct {
		index   uint16
		uplink  uint32
		nexthop net.IP
	}
	var slots []slot
	for i := uint16(0); i < MaxBumNexthops; i++ {
		var peer HeadendEntry
		err := s.objs.BdPeerMap.Lookup(&BdPeerKey{BdId: bdID, Index: i}, &peer)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("bd %d: read bd_peer %d: %w", bdID, i, err)
		}
		if peer.FloodExclude != 0 || peer.NumSegments < 1 {
			continue
		}
		up, err := s.uplink(peer.Segments[0])
		if err != nil {
			// Not fatal: the slot rejoins on the next rebuild (route change
			// or BD mutation). Until then that peer gets no BUM copy.
			s.logger.Warn("xdp BUM: cannot resolve the uplink of a flood peer; slot left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", i),
				zap.String("segment", net.IP(peer.Segments[0][:]).String()), zap.Error(err))
			continue
		}
		if _, isAC := allACs[up.Ifindex]; isAC && s.native {
			s.logger.Warn("xdp BUM: the uplink of a flood peer is also a local AC; native XDP cannot send both through it, slot left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", i), zap.Uint32("ifindex", up.Ifindex))
			continue
		}
		slots = append(slots, slot{index: i, uplink: up.Ifindex, nexthop: up.Nexthop})
	}
	if reason := unservable(acs, ifindexes, len(slots)); reason != "" {
		return s.clearBDLocked(bdID, reason)
	}

	flood, err := ebpf.NewMap(s.innerSpec)
	if err != nil {
		return fmt.Errorf("bd %d: create flood devmap: %w", bdID, err)
	}
	defer func() { _ = flood.Close() }()
	local, err := ebpf.NewMap(s.innerSpec)
	if err != nil {
		return fmt.Errorf("bd %d: create local devmap: %w", bdID, err)
	}
	defer func() { _ = local.Close() }()

	if len(slots) > 0 && s.egress == nil {
		return fmt.Errorf("bd %d: bum_remote_egress is not loaded", bdID)
	}
	uplinks := make(map[uint32]struct{}, len(slots))
	for _, sl := range slots {
		uplinks[sl.uplink] = struct{}{}
	}
	for _, ifindex := range ifindexes {
		v := devmapVal{Ifindex: ifindex}
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
		if err != nil {
			// Not fatal, like an unresolvable slot: an AC whose device is
			// gone must not keep the rest of the BD on stale devmaps.
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
		if err := flood.Put(BumSlotKeyBase|uint32(sl.index), v); err != nil {
			// The devmap has room (unservable), so the uplink device is
			// gone: like an unresolvable uplink, the slot waits for the
			// next rebuild.
			s.logger.Warn("xdp BUM: cannot add a flood slot to the BD devmap; slot left out",
				zap.Uint16("bd_id", bdID), zap.Uint16("index", sl.index), zap.Uint32("uplink", sl.uplink), zap.Error(err))
		}
	}

	if s.native {
		added := false
		for _, sl := range slots {
			fresh, err := s.ensureUplinkTx(sl.uplink)
			if err != nil {
				return fmt.Errorf("bd %d: flood slot %d: %w", bdID, sl.index, err)
			}
			added = added || fresh
		}
		// A NAPI poll that redirected to a new uplink with a plain
		// bpf_redirect just before the entry appeared must be over before
		// this BD's copies can join that poll's queue.
		if added {
			time.Sleep(uplinkTxGrace)
		}
	}

	key := uint32(bdID)
	if err := s.objs.BumLocalMap.Update(key, local, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bd %d: install local devmap: %w", bdID, err)
	}
	if err := s.objs.BumFloodMap.Update(key, flood, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bd %d: install flood devmap: %w", bdID, err)
	}
	s.noteServedLocked(bdID, "")
	if s.keepNeigh != nil {
		for _, sl := range slots {
			if sl.nexthop == nil {
				continue
			}
			if err := s.keepNeigh(sl.uplink, sl.nexthop); err != nil {
				s.logger.Debug("xdp BUM: cannot keep a flood slot's next hop resolved",
					zap.Uint16("bd_id", bdID), zap.Uint16("index", sl.index), zap.Error(err))
			}
		}
	}
	return nil
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
	return errors.Join(errs...)
}

// uplinkTxGrace outlasts any NAPI poll in flight when an uplink joins
// uplink_tx_map (a poll handles at most its budget of frames).
const uplinkTxGrace = 10 * time.Millisecond

// ensureUplinkTx adds ifindex to uplink_tx_map unless it is there, and
// reports whether it added it.
func (s *BumDevmapSync) ensureUplinkTx(ifindex uint32) (bool, error) {
	var cur devmapVal
	err := s.objs.UplinkTxMap.Lookup(ifindex, &cur)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("read uplink_tx_map[%d]: %w", ifindex, err)
	}
	if s.egress == nil {
		return false, errors.New("bum_remote_egress is not loaded")
	}
	v := devmapVal{Ifindex: ifindex, ProgFD: uint32(s.egress.FD())}
	if err := s.objs.UplinkTxMap.Update(ifindex, v, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return false, nil
		}
		return false, fmt.Errorf("add uplink %d to uplink_tx_map: %w", ifindex, err)
	}
	return true, nil
}

// pruneUplinkTxLocked drops the local ACs of xdp-mode BDs from
// uplink_tx_map, after every BD has been rebuilt without slots through them.
func (s *BumDevmapSync) pruneUplinkTxLocked(allACs map[uint32]struct{}) error {
	var errs []error
	for ifindex := range allACs {
		if err := s.objs.UplinkTxMap.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("drop AC %d from uplink_tx_map: %w", ifindex, err))
		}
	}
	return errors.Join(errs...)
}

// SyncACs rebuilds after a local AC of bdIDs was added, moved or removed.
// In native XDP the set of ACs decides which slots may use which uplink in
// every BD, so all BDs are rebuilt; otherwise only bdIDs.
func (s *BumDevmapSync) SyncACs(bdIDs ...uint16) error {
	s.mu.Lock()
	native := s.native
	s.mu.Unlock()
	if native {
		return s.SyncAll()
	}
	var errs []error
	for _, bd := range bdIDs {
		if err := s.SyncBD(bd); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

	allACs := s.xdpACsLocked(acs)
	var errs []error
	for bd := range bds {
		if err := s.syncBDLocked(bd, acs[bd], allACs); err != nil {
			errs = append(errs, err)
		}
	}
	if s.native {
		if err := s.pruneUplinkTxLocked(allACs); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WatchRoutes rebuilds every BD (debounced) when the main routing table
// changes, so a flood slot follows its peer's uplink and a slot whose route
// appears late joins. It returns when ctx is done.
func (s *BumDevmapSync) WatchRoutes(ctx context.Context, debounce time.Duration) error {
	sub, err := s.subscribeRoutes()
	if err != nil {
		return fmt.Errorf("subscribe to route updates: %w", err)
	}
	go s.watchRoutes(ctx, sub, debounce)
	return nil
}

type routeSub struct {
	updates chan netlink.RouteUpdate
	done    chan struct{}
}

func (s *BumDevmapSync) subscribeRoutes() (*routeSub, error) {
	r := &routeSub{updates: make(chan netlink.RouteUpdate, 256), done: make(chan struct{})}
	err := netlink.RouteSubscribeWithOptions(r.updates, r.done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			s.logger.Warn("xdp BUM: route subscription failed", zap.Error(err))
		},
		ReceiveBufferSize: 1 << 20, // a full table load must not overflow it
	})
	if err != nil {
		close(r.done)
		return nil, err
	}
	return r, nil
}

// routeSyncMaxDelay caps how long a steady stream of route updates can
// postpone the rebuild, in multiples of the debounce.
const routeSyncMaxDelay = 10

func (s *BumDevmapSync) watchRoutes(ctx context.Context, sub *routeSub, debounce time.Duration) {
	timer := time.NewTimer(debounce)
	timer.Stop()
	var (
		fire  <-chan time.Time
		first time.Time // first update since the last rebuild
	)
	schedule := func(d time.Duration) {
		timer.Stop()
		timer.Reset(d)
		fire = timer.C
	}
	defer func() {
		timer.Stop()
		if sub != nil {
			close(sub.done)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-sub.updates:
			if !ok {
				// The subscription ended (typically ENOBUFS: the kernel
				// dropped notifications). Updates may be lost, so
				// subscribe again and rebuild everything.
				close(sub.done)
				sub = nil
				for sub == nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
					var err error
					if sub, err = s.subscribeRoutes(); err != nil {
						s.logger.Warn("xdp BUM: route resubscribe failed; retrying", zap.Error(err))
					}
				}
				first = time.Time{}
				schedule(0)
				continue
			}
			now := time.Now()
			if first.IsZero() {
				first = now
			}
			wait := debounce
			if left := first.Add(routeSyncMaxDelay * debounce).Sub(now); left < wait {
				wait = max(left, 0)
			}
			schedule(wait)
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

// resyncBumACs is resyncBum for a change of local ACs (SyncACs).
func (m *MapOperations) resyncBumACs(bdIDs ...uint16) {
	m.bumMu.Lock()
	s := m.bum
	m.bumMu.Unlock()
	if s == nil {
		return
	}
	if err := s.SyncACs(bdIDs...); err != nil {
		s.logger.Warn("xdp BUM: devmap rebuild after an AC change failed", zap.Error(err))
	}
}
