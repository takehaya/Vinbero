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

// fdbMapOps is the subset of *bpf.MapOperations the FDBWatcher needs, narrowed
// to an interface so the watcher is unit-testable without a live BPF map.
type fdbMapOps interface {
	CreateFdb(bdID uint16, mac net.HardwareAddr, entry *bpf.FdbEntry) error
	DeleteFdb(bdID uint16, mac net.HardwareAddr) error
	AgeFdbEntries(maxAgeNs uint64) (int, error)
}

// FDBWatcher watches Linux bridge FDB updates via Netlink and syncs them to BPF fdb_map.
// Also runs a periodic aging timer to delete stale dynamic entries.
type FDBWatcher struct {
	mapOps       fdbMapOps
	logger       *zap.Logger
	mu           sync.RWMutex
	allowed      map[int]uint16 // bridge ifindex → bd_id (for O(1) filter)
	macSink      MACSink        // nil unless EVPN auto-advertise is on
	done         chan struct{}
	wg           sync.WaitGroup
	agingSeconds int // 0=disabled
}

// NewFDBWatcher creates a new FDB watcher
func NewFDBWatcher(mapOps *bpf.MapOperations, logger *zap.Logger) *FDBWatcher {
	return &FDBWatcher{
		mapOps:  mapOps,
		logger:  logger,
		allowed: make(map[int]uint16),
		done:    make(chan struct{}),
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

// SetMACSink installs the sink that receives local MAC add/delete events for
// EVPN RT2 auto-advertise. It is safe to call at any time (guarded by w.mu),
// but setting it after Start means the boot-time ListExisting replay has already
// run, so MACs present at that point are not delivered to the sink.
func (w *FDBWatcher) SetMACSink(sink MACSink) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.macSink = sink
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
			maxAgeNs := uint64(w.agingSeconds) * 1e9
			deleted, err := w.mapOps.AgeFdbEntries(maxAgeNs)
			if err != nil {
				w.logger.Warn("FDB aging error", zap.Error(err))
			} else if deleted > 0 {
				w.logger.Info("FDB aging: deleted stale entries", zap.Int("count", deleted))
			}
		}
	}
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
	sink := w.macSink
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
		entry := &bpf.FdbEntry{
			Oif: uint32(neigh.LinkIndex),
		}
		if err := w.mapOps.CreateFdb(bdID, net.HardwareAddr(mac), entry); err != nil {
			w.logger.Debug("Failed to sync FDB entry to BPF map",
				zap.String("mac", mac.String()),
				zap.Uint16("bd_id", bdID),
				zap.Error(err))
			// The dataplane FDB was not installed; do not advertise RT2 for a MAC
			// the data plane cannot decap to, or remote traffic would blackhole.
			return
		}
		w.notifyMAC(sink, bdID, mac, true)

	case unix.RTM_DELNEIGH:
		if err := w.mapOps.DeleteFdb(bdID, net.HardwareAddr(mac)); err != nil {
			w.logger.Debug("Failed to delete FDB entry from BPF map",
				zap.String("mac", mac.String()),
				zap.Uint16("bd_id", bdID),
				zap.Error(err))
		}
		w.notifyMAC(sink, bdID, mac, false)
	}
}

// notifyMAC forwards a local MAC change to the EVPN auto-advertise sink, if one
// is set. It copies the MAC because the netlink-supplied slice may be reused.
func (w *FDBWatcher) notifyMAC(sink MACSink, bdID uint16, mac net.HardwareAddr, added bool) {
	if sink == nil {
		return
	}
	sink.OnLocalMAC(bdID, append(net.HardwareAddr(nil), mac...), added)
}

// isUnicastMAC reports whether mac is a 6-byte unicast address (the only FDB
// entries the watcher forwards: broadcast/multicast are skipped).
func isUnicastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&0x01 == 0
}

// DumpBridge replays a registered bridge's existing kernel FDB to the MAC sink
// as adds, for EVPN RT2 auto-advertise. The boot-time ListExisting replay in
// Start only reaches the sink if it was set before Start; a bridge registered
// later (or whose sink is wired after Start) needs this to pick up MACs already
// learned. It does not touch the BPF fdb_map (Start's sync already covers that);
// it only feeds the sink, which dedups, so a replay is idempotent. A no-op when
// no sink is set.
func (w *FDBWatcher) DumpBridge(ifindex int) error {
	w.mu.RLock()
	bdID, ok := w.allowed[ifindex]
	sink := w.macSink
	w.mu.RUnlock()
	if !ok {
		return fmt.Errorf("bridge ifindex %d is not registered", ifindex)
	}
	if sink == nil {
		return nil
	}
	// NeighList(0, AF_BRIDGE) lists every bridge FDB entry; filter by MasterIndex
	// to this bridge, mirroring the live handleNeighUpdate path.
	neighs, err := netlink.NeighList(0, unix.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("list bridge FDB: %w", err)
	}
	for i := range neighs {
		n := &neighs[i]
		if n.MasterIndex != ifindex || !isUnicastMAC(n.HardwareAddr) {
			continue
		}
		sink.OnLocalMAC(bdID, append(net.HardwareAddr(nil), n.HardwareAddr...), true)
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
