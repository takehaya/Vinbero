package netlinkwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// MACSink consumes local bridge FDB MAC changes the FDBWatcher observes, for
// EVPN RT2 auto-advertise. Adds are delivered only when the BPF map accepts
// local forwarding; kernel observations cannot overwrite managed remote MACs.
// Deletes withdraw local advertisements even if forwarding has since changed
// owner. A nil sink means no auto-advertise.
type MACSink interface {
	OnLocalMAC(bdID uint16, mac net.HardwareAddr, added bool)
}

// macSinkEntry is one registered sink and the id its removal is keyed by.
type macSinkEntry struct {
	id   uint64
	sink MACSink
}

// fdbMapOps is the subset of *bpf.MapOperations the FDBWatcher needs, narrowed
// to an interface so the watcher is unit-testable without a live BPF map.
type fdbMapOps interface {
	LearnFdb(bdID uint16, mac net.HardwareAddr, oif uint32) (bool, error)
	DeleteLearnedFdb(bdID uint16, mac net.HardwareAddr, oif uint32) error
	AgeFdbEntries(maxAgeNs uint64, keep func(bpf.FdbKey) bool) ([]bpf.AgedFdbEntry, error)
	AgeLocalFdbEntries(maxAgeNs uint64, inBD func(bdID uint16) bool, keep func(bpf.FdbKey) bool) ([]bpf.AgedFdbEntry, error)
	LocalFdbSeen(bdID uint16, mac net.HardwareAddr, withinNs uint64) bool
	ListLocalDynamicFdb(bdID uint16) (map[uint16][]net.HardwareAddr, error)
}

// FdbEventSource yields the local MACs the XDP learner installs in
// xdp-mode bridge domains (*bpf.FdbEventReader). Close must unblock Read.
type FdbEventSource interface {
	Read() (bpf.FdbEvent, error)
	Close() error
}

// FDBWatcher watches Linux bridge FDB updates via Netlink and syncs them to BPF fdb_map.
// Also runs a periodic aging timer to delete stale dynamic entries.
type FDBWatcher struct {
	mapOps  fdbMapOps
	logger  *zap.Logger
	mu      sync.RWMutex
	allowed map[int]uint16 // bridge ifindex → bd_id (for O(1) filter)
	// macSinks receives every local MAC change, in registration order.
	// Empty unless EVPN auto-advertise is on or a consumer added itself.
	macSinks []macSinkEntry
	// primarySinkID identifies the sink installed through SetMACSink, so a
	// later SetMACSink replaces it rather than stacking another consumer.
	// Zero means none is installed.
	primarySinkID uint64
	nextSinkID    uint64
	// neighList lists kernel neighbor entries (defaults to netlink.NeighList);
	// overridable in tests so DumpBridge's filter + sync path needs no live bridge.
	neighList func(linkIndex, family int) ([]netlink.Neigh, error)
	// subscribe opens the FDB event stream (netlink.NeighSubscribeWithOptions);
	// tests replace it.
	subscribe func(ch chan<- netlink.NeighUpdate, done <-chan struct{}, options netlink.NeighSubscribeOptions) error
	// subSt follows the subscription and logs its state changes.
	subSt *netlinksub.State
	// started is set once Start subscribed. Guarded by mu.
	started      bool
	done         chan struct{}
	wg           sync.WaitGroup
	agingSeconds int // 0=disabled
	// xdpLearned reports whether a BD runs in xdp BUM mode. Such a BD's
	// frames never reach the kernel bridge, so its local MACs come from the
	// XDP learner (StartXDPEvents) and fdb_map, and the bridge's own FDB
	// events are ignored: an idle bridge entry aging out must not delete an
	// entry the data plane keeps fresh, nor withdraw its RT2. Nil: none.
	xdpLearned func(bdID uint16) bool
	// deviceAddr returns a device's hardware address. Tests replace it; the
	// zero value is the kernel.
	deviceAddr func(ifindex int) (net.HardwareAddr, error)
	// localMu keeps a reconcile re-announcement from landing after the
	// withdrawal of the MAC it read.
	localMu sync.Mutex
}

// NewFDBWatcher creates a new FDB watcher
func NewFDBWatcher(mapOps *bpf.MapOperations, logger *zap.Logger) *FDBWatcher {
	return &FDBWatcher{
		mapOps:     mapOps,
		logger:     logger,
		allowed:    make(map[int]uint16),
		neighList:  netlink.NeighList,
		subscribe:  netlink.NeighSubscribeWithOptions,
		subSt:      netlinksub.New(logger, "FDB"),
		deviceAddr: linkHardwareAddr,
		done:       make(chan struct{}),
	}
}

// RegisterBridge adds a bridge to the FDB watch list. Register the bridges
// that exist at boot before Start: its dump of the existing FDB is filtered
// by the list. A bridge registered after Start has its existing FDB synced
// to fdb_map here instead (the EVPN coordinator advertises it, DumpBridge).
func (w *FDBWatcher) RegisterBridge(ifindex int, bdID uint16) {
	w.mu.Lock()
	prev, had := w.allowed[ifindex]
	w.allowed[ifindex] = bdID
	replay := w.started && (!had || prev != bdID) && !w.isXDPLearnedLocked(bdID)
	w.mu.Unlock()
	w.logger.Info("Registered bridge for FDB watching",
		zap.Int("ifindex", ifindex),
		zap.Uint16("bd_id", bdID))
	if replay {
		w.syncBridge(ifindex, bdID)
	}
}

// syncBridge syncs a bridge's existing FDB to fdb_map, the way the dump at
// Start does for the bridges registered by then.
func (w *FDBWatcher) syncBridge(ifindex int, bdID uint16) {
	neighs, err := w.neighList(0, unix.AF_BRIDGE)
	if err != nil {
		w.logger.Warn("list the FDB of a newly watched bridge; its MACs reach fdb_map as the bridge learns them again",
			zap.Int("ifindex", ifindex), zap.Error(err))
		return
	}
	for i := range neighs {
		n := &neighs[i]
		if n.MasterIndex == ifindex && isUnicastMAC(n.HardwareAddr) {
			w.learnFromBridge(nil, bdID, n)
		}
	}
}

// UnregisterBridge removes a bridge from the FDB watch list.
func (w *FDBWatcher) UnregisterBridge(ifindex int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.allowed, ifindex)
}

// Start begins watching FDB updates in the calling thread's network
// namespace. It subscribes, then replays the bridges' existing FDB as adds
// before it returns; the updates that arrived meanwhile are applied after
// the replay, so the latest state wins. A subscription that ends (e.g. a
// receive buffer overflow) is subscribed again (netlinksub), and the FDB is
// replayed again, so a MAC learned or moved in between still arrives. A MAC
// the bridge removed in between stays in fdb_map until an aging pass removes
// it (fdb_aging_seconds, or the local aging that runs for xdp-mode BDs and
// MAC sinks).
func (w *FDBWatcher) Start(ctx context.Context) error {
	if w.subSt == nil {
		w.subSt = netlinksub.New(w.logger, "FDB")
	}
	ns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("FDB watcher: %w", err)
	}
	updates, stop, err := w.subscribeFDB()
	if err != nil {
		_ = ns.Close()
		return err
	}
	listing := netlinksub.NewListing(w.logger, "FDB")
	again := listing.Result(w.replayFDB())
	w.mu.Lock()
	w.started = true
	w.mu.Unlock()

	w.wg.Go(func() {
		defer func() { _ = ns.Close() }()
		w.follow(ctx, ns, updates, stop, listing, again)
	})

	// Start aging timer if configured
	if w.agingSeconds > 0 {
		w.wg.Go(func() {
			w.runAging(ctx)
		})
	} else {
		w.wg.Go(func() {
			w.runLocalAging(ctx)
		})
	}

	return nil
}

// subscribeFDB subscribes to neighbour updates in the calling thread's
// network namespace. Closing stop ends the subscription.
func (w *FDBWatcher) subscribeFDB() (<-chan netlink.NeighUpdate, chan struct{}, error) {
	updates := make(chan netlink.NeighUpdate, 256)
	stop := make(chan struct{})
	if err := w.subscribe(updates, stop, netlink.NeighSubscribeOptions{
		ErrorCallback:     w.subSt.OnError,
		ReceiveBufferSize: 1 << 20, // a burst of learning must not overflow it
	}); err != nil {
		close(stop)
		return nil, nil, fmt.Errorf("subscribe to FDB updates: %w", err)
	}
	return updates, stop, nil
}

// replayFDB delivers the existing FDB entries of the registered bridges as
// adds. It lists them with a request of its own: the library's ListExisting
// would send the request to every other subscriber of the neighbour group
// (netlinksub). What an interrupted dump returned is delivered too, and the
// error is returned for a retry.
func (w *FDBWatcher) replayFDB() error {
	neighs, err := w.neighList(0, unix.AF_BRIDGE)
	for i := range neighs {
		w.handleNeighUpdate(netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: neighs[i]})
	}
	if err != nil {
		return fmt.Errorf("list the existing FDB: %w", err)
	}
	return nil
}

// follow applies the subscription's updates until the watcher stops. It
// subscribes again in ns each time the subscription ends and replays the FDB
// then, and repeats a replay that failed when again fires.
func (w *FDBWatcher) follow(ctx context.Context, ns netns.NsHandle, updates <-chan netlink.NeighUpdate, stop chan struct{}, listing *netlinksub.Listing, again <-chan time.Time) {
	if err := enterNetns(ns); err != nil {
		w.logger.Warn("FDB watcher: cannot enter the network namespace it watches; a resubscribe may watch another", zap.Error(err))
	}
	quit := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-w.done:
		}
		close(quit)
	}()
	for {
		select {
		case <-quit:
			close(stop)
			go drain(updates)
			return
		case <-again:
			again = listing.Result(w.replayFDB())
		case update, ok := <-updates:
			if ok {
				w.handleNeighUpdate(update)
				continue
			}
			close(stop)
			if !w.subSt.Again(quit, func() error {
				var err error
				updates, stop, err = w.subscribeFDB()
				return err
			}) {
				return
			}
			again = listing.Result(w.replayFDB())
		}
	}
}

// SetXDPLearnedBDs installs the predicate that marks xdp-mode BDs. Call
// before Start.
func (w *FDBWatcher) SetXDPLearnedBDs(isXDP func(bdID uint16) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.xdpLearned = isXDP
}

func (w *FDBWatcher) isXDPLearnedLocked(bdID uint16) bool {
	return w.xdpLearned != nil && w.xdpLearned(bdID)
}

// StartXDPEvents delivers XDP-learned local MACs to the MAC sinks as adds.
// The data plane already wrote the fdb_map entry, so nothing is synced
// here; aging withdraws them through the usual ageAndWithdraw path. The
// source is closed on Stop.
func (w *FDBWatcher) StartXDPEvents(src FdbEventSource) {
	w.wg.Go(func() {
		<-w.done
		_ = src.Close()
	})
	w.wg.Go(func() {
		for {
			ev, err := src.Read()
			if err != nil {
				if errors.Is(err, bpf.ErrFdbEventsClosed) {
					return
				}
				select {
				case <-w.done:
					return
				default:
				}
				w.logger.Debug("XDP FDB event read failed", zap.Error(err))
				continue
			}
			if ev.BdID == 0 || !isUnicastMAC(ev.MAC) {
				continue
			}
			w.logger.Debug("XDP learned local MAC",
				zap.Uint16("bd_id", ev.BdID), zap.String("mac", ev.MAC.String()),
				zap.Uint32("oif", ev.Oif), zap.Bool("move", ev.Kind == bpf.FdbEventMove))
			w.mu.RLock()
			sinks := w.snapshotMACSinks()
			w.mu.RUnlock()
			w.notifyMAC(sinks, ev.BdID, ev.MAC, true)
		}
	})
}

// reconcileLocalMACs re-announces the local MACs in fdb_map. A full ring
// buffer drops xdp-mode events, and in a tc-mode BD no event follows when
// XDP learns back a MAC the bridge has aged; the sinks dedup, so this pass
// only fills in what was lost. The addresses of bridge ports and of the bridge
// itself are not re-announced.
func (w *FDBWatcher) reconcileLocalMACs(kernel *bridgeFDB) {
	w.mu.RLock()
	sinks := w.snapshotMACSinks()
	w.mu.RUnlock()
	if len(sinks) == 0 {
		return
	}
	byBD, err := w.mapOps.ListLocalDynamicFdb(0)
	if err != nil {
		w.logger.Warn("FDB reconciliation failed", zap.Error(err))
		return
	}
	for bdID, macs := range byBD {
		w.mu.RLock()
		xdp := w.isXDPLearnedLocked(bdID)
		w.mu.RUnlock()
		for _, mac := range macs {
			if xdp || kernel.mayAdvertise(bdID, mac) {
				w.announceIfLocal(sinks, bdID, mac)
			}
		}
	}
}

// announceIfLocal re-announces a MAC only if it is still in fdb_map, so a MAC
// the list above read before its withdrawal does not come back. Holding
// localMu makes the check and the announcement atomic against a withdrawal.
func (w *FDBWatcher) announceIfLocal(sinks []MACSink, bdID uint16, mac net.HardwareAddr) {
	w.localMu.Lock()
	defer w.localMu.Unlock()
	if w.mapOps.LocalFdbSeen(bdID, mac, 0) {
		w.notifyMAC(sinks, bdID, mac, true)
	}
}

// bridgeFDB is one dump of the kernel FDB of the bridges in tc-mode BDs.
// unknown means the dump failed: nothing is known about those bridges.
type bridgeFDB struct {
	bds     map[uint16]struct{}     // BDs with a registered bridge
	held    map[bpf.FdbKey]struct{} // every MAC the bridges hold
	devices map[bpf.FdbKey]struct{} // the MACs that are a port's or a bridge's own address
	unknown bool
}

// holds reports whether the bridge still has an entry for k, or might have.
func (f *bridgeFDB) holds(k bpf.FdbKey) bool {
	if f.unknown {
		_, ok := f.bds[k.BdId]
		return ok
	}
	_, ok := f.held[k]
	return ok
}

// mayAdvertise reports whether a local MAC of the BD may be advertised: the BD
// has a registered bridge and the MAC is not a device's own address.
func (f *bridgeFDB) mayAdvertise(bd uint16, mac net.HardwareAddr) bool {
	if _, ok := f.bds[bd]; !ok || f.unknown {
		return false
	}
	_, device := f.devices[bpf.FdbKey{BdId: bd, Mac: [6]byte(mac)}]
	return !device
}

// dumpBridgeFDB returns the kernel FDB of the tc-mode bridges. A failed dump
// is logged and reported through unknown, so aging and reconciliation that do
// not depend on it can continue.
func (w *FDBWatcher) dumpBridgeFDB() *bridgeFDB {
	w.mu.RLock()
	bdOf := make(map[int]uint16, len(w.allowed))
	for ifindex, bd := range w.allowed {
		if !w.isXDPLearnedLocked(bd) {
			bdOf[ifindex] = bd
		}
	}
	w.mu.RUnlock()
	f := &bridgeFDB{
		bds:     make(map[uint16]struct{}, len(bdOf)),
		held:    make(map[bpf.FdbKey]struct{}),
		devices: make(map[bpf.FdbKey]struct{}),
	}
	for _, bd := range bdOf {
		f.bds[bd] = struct{}{}
	}
	if len(bdOf) == 0 {
		return f
	}
	neighs, err := w.neighList(0, unix.AF_BRIDGE)
	if err != nil {
		w.logger.Warn("FDB aging: dump the bridge FDB", zap.Error(err))
		f.unknown = true
		return f
	}
	for i := range neighs {
		n := &neighs[i]
		bd, ok := bdOf[n.MasterIndex]
		if !ok || !isUnicastMAC(n.HardwareAddr) {
			continue
		}
		k := bpf.FdbKey{BdId: bd, Mac: [6]byte(n.HardwareAddr)}
		f.held[k] = struct{}{}
		if w.isDeviceAddress(n) {
			f.devices[k] = struct{}{}
		}
	}
	return f
}

// SetAgingSeconds configures the FDB aging timeout.
func (w *FDBWatcher) SetAgingSeconds(seconds int) {
	w.agingSeconds = seconds
}

// SetMACSink installs the primary sink for local MAC add/delete events, used
// by EVPN RT2 auto-advertise. A second call replaces it, and a nil sink
// removes it, leaving any sink added through AddMACSink in place. It is safe
// to call at any time (guarded by w.mu), but setting it after Start means the
// boot-time replay of the existing FDB has already run, so MACs present at that point
// are not delivered to the sink.
func (w *FDBWatcher) SetMACSink(sink MACSink) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.primarySinkID != 0 {
		w.removeMACSinkLocked(w.primarySinkID)
		w.primarySinkID = 0
	}
	if sink == nil {
		return
	}
	w.primarySinkID = w.addMACSinkLocked(sink)
}

// AddMACSink registers an additional sink alongside the primary one and
// returns a remove func that is safe to call more than once. Sinks are
// notified in registration order; each gets its own copy of the MAC, so one
// consumer cannot corrupt another's.
func (w *FDBWatcher) AddMACSink(sink MACSink) func() {
	if sink == nil {
		return func() {}
	}
	w.mu.Lock()
	id := w.addMACSinkLocked(sink)
	w.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.removeMACSinkLocked(id)
			if w.primarySinkID == id {
				w.primarySinkID = 0
			}
		})
	}
}

// addMACSinkLocked appends sink and returns its id. Caller holds w.mu.
func (w *FDBWatcher) addMACSinkLocked(sink MACSink) uint64 {
	w.nextSinkID++
	id := w.nextSinkID
	w.macSinks = append(w.macSinks, macSinkEntry{id: id, sink: sink})
	return id
}

// removeMACSinkLocked drops the sink registered under id. Caller holds w.mu.
func (w *FDBWatcher) removeMACSinkLocked(id uint64) {
	for i, e := range w.macSinks {
		if e.id == id {
			w.macSinks = append(w.macSinks[:i], w.macSinks[i+1:]...)
			return
		}
	}
}

// snapshotMACSinks copies the current sink list so delivery runs without
// holding w.mu (a sink may call back into the watcher).
func (w *FDBWatcher) snapshotMACSinks() []MACSink {
	if len(w.macSinks) == 0 {
		return nil
	}
	out := make([]MACSink, 0, len(w.macSinks))
	for _, e := range w.macSinks {
		out = append(out, e.sink)
	}
	return out
}

func (w *FDBWatcher) runAging(ctx context.Context) {
	interval := time.Duration(w.agingSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.ageAndWithdraw(uint64(w.agingSeconds) * 1e9)
		}
	}
}

// Without fdb_aging_seconds, the kernel bridge still ages the local MACs it
// holds in a tc-mode BD, and its RTM_DELNEIGH withdraws them. Nothing else
// would age the local MACs of an xdp-mode BD, whose frames never reach the
// bridge, or those of a tc-mode BD that XDP has learned with no bridge entry
// behind them, so they are aged here at the bridge's default ageing time. The
// pass also re-announces what the data plane learned but no event reported.
const (
	localAgingDefault  = 300 * time.Second
	localAgingInterval = 30 * time.Second
	// recentlySeen is how recently XDP must have seen a MAC for an expiry in
	// the bridge not to count as the host being gone.
	recentlySeen = uint64(30 * time.Second)
)

func (w *FDBWatcher) runLocalAging(ctx context.Context) {
	ticker := time.NewTicker(localAgingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.ageLocal(uint64(localAgingDefault))
		}
	}
}

// ageLocal runs one pass of the above. It does nothing when no BD runs in xdp
// mode and nobody consumes local MACs.
func (w *FDBWatcher) ageLocal(maxAgeNs uint64) {
	w.mu.RLock()
	idle := w.xdpLearned == nil && len(w.macSinks) == 0
	w.mu.RUnlock()
	if idle {
		return
	}
	kernel := w.dumpBridgeFDB()
	defer w.reconcileLocalMACs(kernel)
	aged, err := w.mapOps.AgeLocalFdbEntries(maxAgeNs, func(bdID uint16) bool {
		if _, tc := kernel.bds[bdID]; tc {
			return true
		}
		w.mu.RLock()
		defer w.mu.RUnlock()
		return w.isXDPLearnedLocked(bdID)
	}, kernel.holds)
	if err != nil {
		w.logger.Warn("FDB aging error", zap.Error(err))
		return
	}
	w.withdrawAged(aged)
}

// ageAndWithdraw runs one BPF aging pass and withdraws the RT2 for each aged
// locally-learned MAC. A MAC the bridge of a tc-mode BD still holds stays: the
// kernel owns its lifetime, ages it on its own clock and reports the removal,
// and it sends no event that could put back an entry removed here. Entries
// that XDP learned without a bridge entry behind them still age here, so they
// cannot stay advertised with no data-plane entry behind them. Remote entries
// (IsRemote) were never advertised as RT2, so they are not withdrawn.
func (w *FDBWatcher) ageAndWithdraw(maxAgeNs uint64) {
	kernel := w.dumpBridgeFDB()
	defer w.reconcileLocalMACs(kernel)
	aged, err := w.mapOps.AgeFdbEntries(maxAgeNs, kernel.holds)
	if err != nil {
		w.logger.Warn("FDB aging error", zap.Error(err))
		return
	}
	w.withdrawAged(aged)
}

// withdrawAged withdraws the RT2 of each aged locally-learned MAC.
func (w *FDBWatcher) withdrawAged(aged []bpf.AgedFdbEntry) {
	if len(aged) == 0 {
		return
	}
	w.mu.RLock()
	sinks := w.snapshotMACSinks()
	w.mu.RUnlock()
	for _, a := range aged {
		if a.IsRemote {
			continue
		}
		w.notifyMAC(sinks, a.BDID, a.MAC, false)
	}
	w.logger.Info("FDB aging: deleted stale entries", zap.Int("count", len(aged)))
}

func (w *FDBWatcher) handleNeighUpdate(update netlink.NeighUpdate) {
	neigh := update.Neigh

	if neigh.Family != unix.AF_BRIDGE {
		return
	}

	// Filter: only process FDB entries from registered bridges
	w.mu.RLock()
	bdID, ok := w.allowed[neigh.MasterIndex]
	sinks := w.snapshotMACSinks()
	xdp := ok && w.isXDPLearnedLocked(bdID)
	w.mu.RUnlock()
	if !ok || xdp {
		return
	}

	mac := neigh.HardwareAddr
	if !isUnicastMAC(mac) {
		return
	}

	switch update.Type {
	case unix.RTM_NEWNEIGH:
		w.learnFromBridge(sinks, bdID, &neigh)

	case unix.RTM_DELNEIGH:
		// An expiry of a MAC XDP is still seeing only means the bridge lost
		// sight of it (the host sends to remote MACs, which XDP encapsulates
		// past the bridge). Keep it; the aging pass removes it once XDP stops
		// seeing it too.
		if neigh.State&netlink.NUD_STALE != 0 && w.mapOps.LocalFdbSeen(bdID, mac, recentlySeen) {
			return
		}
		w.localMu.Lock()
		defer w.localMu.Unlock()
		if err := w.mapOps.DeleteLearnedFdb(bdID, net.HardwareAddr(mac), uint32(neigh.LinkIndex)); err != nil {
			w.logger.Debug("Failed to delete FDB entry from BPF map",
				zap.String("mac", mac.String()),
				zap.Uint16("bd_id", bdID),
				zap.Error(err))
		}
		w.notifyMAC(sinks, bdID, mac, false)
	}
}

// learnFromBridge applies one bridge FDB entry. The address of a bridge port
// or of the bridge itself is synced to fdb_map, so frames to it are not
// flooded, but is not advertised: a frame decapsulated for it cannot reach the
// host through the bridge's transmit path, and advertising it would spend a
// route on every PE for each port. It is withdrawn in case it was advertised
// before the bridge took it over.
func (w *FDBWatcher) learnFromBridge(sinks []MACSink, bdID uint16, n *netlink.Neigh) {
	if w.isDeviceAddress(n) {
		w.syncAndNotify(nil, bdID, n.HardwareAddr, n.LinkIndex)
		w.notifyMAC(sinks, bdID, n.HardwareAddr, false)
		return
	}
	w.syncAndNotify(sinks, bdID, n.HardwareAddr, n.LinkIndex)
}

// isDeviceAddress reports whether a bridge entry is the address of the device
// it is on, or sits on the bridge device itself. Local entries also include
// the ones an operator pins on a port (`bridge fdb add MAC dev tap0 master` is
// permanent by default), which reach a workload through fdb_map and are
// advertised like any other. A device that no longer exists counts: it is
// about to go away. Any other lookup failure says nothing, so the entry stays
// advertised.
func (w *FDBWatcher) isDeviceAddress(n *netlink.Neigh) bool {
	if n.State&netlink.NUD_PERMANENT == 0 {
		return false
	}
	if n.LinkIndex == n.MasterIndex {
		return true
	}
	addr, err := w.lookupDeviceAddr(n.LinkIndex)
	if err != nil {
		return errors.As(err, &netlink.LinkNotFoundError{})
	}
	return bytes.Equal(addr, n.HardwareAddr)
}

func (w *FDBWatcher) lookupDeviceAddr(ifindex int) (net.HardwareAddr, error) {
	if w.deviceAddr != nil {
		return w.deviceAddr(ifindex)
	}
	return linkHardwareAddr(ifindex)
}

func linkHardwareAddr(ifindex int) (net.HardwareAddr, error) {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	return l.Attrs().HardwareAddr, nil
}

// syncAndNotify installs a locally-learned MAC into the BPF fdb_map and, only on
// acceptance, forwards it to the EVPN auto-advertise sink as an add. Gating the
// sink on the data-plane write means RT2 is never advertised for a MAC the data
// plane cannot decap to (which would blackhole remote traffic). Shared by the
// live update path (handleNeighUpdate) and the replay path (DumpBridge), so the
// two cannot drift on this safety rule. The caller has already filtered to a
// registered bridge and a unicast MAC.
func (w *FDBWatcher) syncAndNotify(sinks []MACSink, bdID uint16, mac net.HardwareAddr, linkIndex int) {
	local, err := w.mapOps.LearnFdb(bdID, mac, uint32(linkIndex))
	if err != nil {
		w.logger.Debug("Failed to sync FDB entry to BPF map",
			zap.String("mac", mac.String()), zap.Uint16("bd_id", bdID), zap.Error(err))
		return
	}
	if local {
		w.notifyMAC(sinks, bdID, mac, true)
	}
}

// notifyMAC forwards a local MAC change to every registered sink. Each gets its
// own copy: the netlink-supplied slice may be reused, and one sink retaining or
// mutating the MAC must not affect the next.
func (w *FDBWatcher) notifyMAC(sinks []MACSink, bdID uint16, mac net.HardwareAddr, added bool) {
	for _, sink := range sinks {
		sink.OnLocalMAC(bdID, append(net.HardwareAddr(nil), mac...), added)
	}
}

// isUnicastMAC reports whether mac is a 6-byte unicast address (the only FDB
// entries the watcher forwards: broadcast/multicast are skipped).
func isUnicastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&0x01 == 0
}

// DumpBridge replays a registered bridge's existing kernel FDB through the same
// sync-then-advertise path as a live add, for EVPN RT2 auto-advertise. The
// boot-time replay of the existing FDB in Start only reaches the sink if it was set
// before Start; a bridge registered later (or whose sink is wired after Start)
// needs this to pick up MACs already learned. Each MAC is re-synced into the BPF
// fdb_map (idempotent, and a backstop for a failed Start-time Put) and advertised
// only on success; the sink dedups, so a replay is idempotent. A no-op when no
// sink is set.
func (w *FDBWatcher) DumpBridge(ifindex int) error {
	w.mu.RLock()
	bdID, ok := w.allowed[ifindex]
	sinks := w.snapshotMACSinks()
	xdp := ok && w.isXDPLearnedLocked(bdID)
	w.mu.RUnlock()
	if !ok {
		return fmt.Errorf("bridge ifindex %d is not registered", ifindex)
	}
	if len(sinks) == 0 {
		return nil
	}
	if xdp {
		// The bridge never learned this BD's MACs; fdb_map has them.
		byBD, err := w.mapOps.ListLocalDynamicFdb(bdID)
		if err != nil {
			return fmt.Errorf("list XDP-learned FDB: %w", err)
		}
		for _, mac := range byBD[bdID] {
			w.notifyMAC(sinks, bdID, mac, true)
		}
		return nil
	}
	// neighList(0, AF_BRIDGE) lists every bridge FDB entry; filter by MasterIndex
	// to this bridge, mirroring the live handleNeighUpdate path.
	neighs, err := w.neighList(0, unix.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("list bridge FDB: %w", err)
	}
	for i := range neighs {
		n := &neighs[i]
		if n.MasterIndex != ifindex || !isUnicastMAC(n.HardwareAddr) {
			continue
		}
		// Same path as a live add: re-sync the BPF fdb_map (idempotent for entries
		// already present, and a backstop if a Start-time Put had failed) and only
		// then advertise RT2, so a MAC missing from the data plane is not advertised.
		w.learnFromBridge(sinks, bdID, n)
	}
	return nil
}

// Stop stops the FDB watcher and waits for cleanup
func (w *FDBWatcher) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.wg.Wait()
}
