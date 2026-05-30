package netlinkwatch

import (
	"context"
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
// EVPN RT2 auto-advertise. Call before Start.
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
	if mac == nil || len(mac) != 6 {
		return
	}

	// Skip broadcast/multicast MACs
	if mac[0]&0x01 != 0 {
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

// Stop stops the FDB watcher and waits for cleanup
func (w *FDBWatcher) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.wg.Wait()
}
