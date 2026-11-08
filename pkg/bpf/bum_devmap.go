package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// UplinkResolver returns the ifindex a remote PE's first segment is routed
// out of. The devmap entry of a flood slot transmits on that device.
type UplinkResolver func(firstSegment [IPv6AddrLen]byte) (uint32, error)

// RouteUplinkResolver resolves through the kernel routing table of the
// current network namespace.
func RouteUplinkResolver(seg [IPv6AddrLen]byte) (uint32, error) {
	routes, err := netlink.RouteGet(net.IP(seg[:]))
	if err != nil {
		return 0, err
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return 0, fmt.Errorf("no route to %s", net.IP(seg[:]))
	}
	return uint32(routes[0].LinkIndex), nil
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
	logger    *zap.Logger
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
		modeOf: modeOf,
		uplink: uplink,
		logger: logger,
	}
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
	return s.syncBDLocked(bdID)
}

func (s *BumDevmapSync) syncBDLocked(bdID uint16) error {
	if bdID == 0 {
		return nil
	}
	if s.modeOf(bdID) != BumModeXDP {
		return s.clearBDLocked(bdID)
	}

	acs, err := s.localACs(bdID)
	if err != nil {
		return err
	}
	// A BD without a local AC keeps no devmap: the post-decap flood then
	// falls back to the bridge, and there is no AC ingress to flood from.
	if len(acs) == 0 {
		return s.clearBDLocked(bdID)
	}

	type slot struct {
		index  uint16
		uplink uint32
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
		slots = append(slots, slot{index: i, uplink: up})
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
	for _, ifindex := range acs {
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
			return fmt.Errorf("bd %d: add flood slot %d (uplink %d): %w", bdID, sl.index, sl.uplink, err)
		}
	}

	key := uint32(bdID)
	if err := s.objs.BumLocalMap.Update(key, local, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bd %d: install local devmap: %w", bdID, err)
	}
	if err := s.objs.BumFloodMap.Update(key, flood, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bd %d: install flood devmap: %w", bdID, err)
	}
	return nil
}

func (s *BumDevmapSync) clearBDLocked(bdID uint16) error {
	key := uint32(bdID)
	var errs []error
	for _, m := range []*ebpf.Map{s.objs.BumFloodMap, s.objs.BumLocalMap} {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// localACs returns the distinct ifindexes of the BD's headend_l2 entries.
func (s *BumDevmapSync) localACs(bdID uint16) ([]uint32, error) {
	var (
		key   HeadendL2Key
		entry HeadendEntry
		out   []uint32
	)
	seen := map[uint32]struct{}{}
	iter := s.objs.HeadendL2Map.Iterate()
	for iter.Next(&key, &entry) {
		if entry.BdId != bdID || key.Ifindex == 0 {
			continue
		}
		if _, dup := seen[key.Ifindex]; dup {
			continue
		}
		seen[key.Ifindex] = struct{}{}
		out = append(out, key.Ifindex)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("bd %d: scan headend_l2: %w", bdID, err)
	}
	return out, nil
}

// SyncAll rebuilds every BD the maps know about and drops devmaps of BDs
// that no longer exist.
func (s *BumDevmapSync) SyncAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bds := map[uint16]struct{}{}
	var (
		l2Key   HeadendL2Key
		l2Entry HeadendEntry
	)
	iter := s.objs.HeadendL2Map.Iterate()
	for iter.Next(&l2Key, &l2Entry) {
		if l2Entry.BdId != 0 {
			bds[l2Entry.BdId] = struct{}{}
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("scan headend_l2: %w", err)
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

	var errs []error
	for bd := range bds {
		if err := s.syncBDLocked(bd); err != nil {
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
