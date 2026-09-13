package netlinkwatch

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// MACSink consumes local bridge FDB MAC changes the FDBWatcher observes, for
// EVPN RT2 auto-advertise. The kernel bridge FDB only holds locally-learned
// MACs -- the EVPN receive path installs remote MACs into the BPF fdb_map with
// IsRemote=1, never into the kernel FDB -- so every MAC delivered here is local
// and advertising it as RT2 cannot loop. nil sink means no auto-advertise.
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
	CreateFdb(bdID uint16, mac net.HardwareAddr, entry *bpf.FdbEntry) error
	DeleteFdb(bdID uint16, mac net.HardwareAddr) error
	AgeFdbEntries(maxAgeNs uint64) ([]bpf.AgedFdbEntry, error)
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
	neighList    func(linkIndex, family int) ([]netlink.Neigh, error)
	done         chan struct{}
	wg           sync.WaitGroup
	agingSeconds int // 0=disabled
}

// NewFDBWatcher creates a new FDB watcher
func NewFDBWatcher(mapOps *bpf.MapOperations, logger *zap.Logger) *FDBWatcher {
	return &FDBWatcher{
		mapOps:    mapOps,
		logger:    logger,
		allowed:   make(map[int]uint16),
		neighList: netlink.NeighList,
		done:      make(chan struct{}),
	}
}

// RegisterBridge dynamically adds a bridge to the FDB watch list.
func (w *FDBWatcher) RegisterBridge(ifindex int, bdID uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.allowed[ifindex] = bdID
	w.logger.Info("Registered bridge for FDB watching",
		zap.Int("ifindex", ifindex),
		zap.Uint16("bd_id", bdID))
}

// UnregisterBridge removes a bridge from the FDB watch list.
func (w *FDBWatcher) UnregisterBridge(ifindex int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.allowed, ifindex)
}

// Start begins watching FDB updates.
func (w *FDBWatcher) Start(ctx context.Context) error {

	updates := make(chan netlink.NeighUpdate, 256)

	if err := netlink.NeighSubscribeWithOptions(updates, w.done, netlink.NeighSubscribeOptions{
		ListExisting: true,
	}); err != nil {
		return err
	}

	w.wg.Go(func() {
		w.processUpdates(ctx, updates)
	})

	// Start aging timer if configured
	if w.agingSeconds > 0 {
		w.wg.Go(func() {
			w.runAging(ctx)
		})
	}

	return nil
}

// SetAgingSeconds configures the FDB aging timeout.
func (w *FDBWatcher) SetAgingSeconds(seconds int) {
	w.agingSeconds = seconds
}

// SetMACSink installs the primary sink for local MAC add/delete events, used
// by EVPN RT2 auto-advertise. A second call replaces it, and a nil sink
// removes it, leaving any sink added through AddMACSink in place. It is safe
// to call at any time (guarded by w.mu), but setting it after Start means the
// boot-time ListExisting replay has already run, so MACs present at that point
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

// ageAndWithdraw runs one BPF aging pass and withdraws the RT2 for each aged
// locally-learned MAC. Vinbero's BPF ager may remove an fdb_map entry the kernel
// FDB still holds (the kernel runs its own aging and would emit RTM_DELNEIGH), so
// without this the route stays advertised with no data-plane entry behind it --
// an aging-induced blackhole. Remote entries (IsRemote) were never advertised as
// RT2, so they are skipped.
func (w *FDBWatcher) ageAndWithdraw(maxAgeNs uint64) {
	aged, err := w.mapOps.AgeFdbEntries(maxAgeNs)
	if err != nil {
		w.logger.Warn("FDB aging error", zap.Error(err))
		return
	}
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

func (w *FDBWatcher) processUpdates(ctx context.Context, updates <-chan netlink.NeighUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			w.handleNeighUpdate(update)
		}
	}
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
	w.mu.RUnlock()
	if !ok {
		return
	}

	mac := neigh.HardwareAddr
	if !isUnicastMAC(mac) {
		return
	}

	switch update.Type {
	case unix.RTM_NEWNEIGH:
		w.syncAndNotify(sinks, bdID, mac, neigh.LinkIndex)

	case unix.RTM_DELNEIGH:
		if err := w.mapOps.DeleteFdb(bdID, net.HardwareAddr(mac)); err != nil {
			w.logger.Debug("Failed to delete FDB entry from BPF map",
				zap.String("mac", mac.String()),
				zap.Uint16("bd_id", bdID),
				zap.Error(err))
		}
		w.notifyMAC(sinks, bdID, mac, false)
	}
}

// syncAndNotify installs a locally-learned MAC into the BPF fdb_map and, only on
// success, forwards it to the EVPN auto-advertise sink as an add. Gating the
// sink on the data-plane write means RT2 is never advertised for a MAC the data
// plane cannot decap to (which would blackhole remote traffic). Shared by the
// live update path (handleNeighUpdate) and the replay path (DumpBridge), so the
// two cannot drift on this safety rule. The caller has already filtered to a
// registered bridge and a unicast MAC.
func (w *FDBWatcher) syncAndNotify(sinks []MACSink, bdID uint16, mac net.HardwareAddr, linkIndex int) {
	entry := &bpf.FdbEntry{Oif: uint32(linkIndex)}
	if err := w.mapOps.CreateFdb(bdID, mac, entry); err != nil {
		w.logger.Debug("Failed to sync FDB entry to BPF map",
			zap.String("mac", mac.String()), zap.Uint16("bd_id", bdID), zap.Error(err))
		return
	}
	w.notifyMAC(sinks, bdID, mac, true)
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
// boot-time ListExisting replay in Start only reaches the sink if it was set
// before Start; a bridge registered later (or whose sink is wired after Start)
// needs this to pick up MACs already learned. Each MAC is re-synced into the BPF
// fdb_map (idempotent, and a backstop for a failed Start-time Put) and advertised
// only on success; the sink dedups, so a replay is idempotent. A no-op when no
// sink is set.
func (w *FDBWatcher) DumpBridge(ifindex int) error {
	w.mu.RLock()
	bdID, ok := w.allowed[ifindex]
	sinks := w.snapshotMACSinks()
	w.mu.RUnlock()
	if !ok {
		return fmt.Errorf("bridge ifindex %d is not registered", ifindex)
	}
	if len(sinks) == 0 {
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
		w.syncAndNotify(sinks, bdID, n.HardwareAddr, n.LinkIndex)
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
