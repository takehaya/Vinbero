package netlinkwatch

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// FDBWatcher watches Linux bridge FDB updates via Netlink and syncs them to BPF fdb_map
type FDBWatcher struct {
	mapOps  *bpf.MapOperations
	logger  *zap.Logger
	configs []config.BridgeDomainConfig
	allowed map[int]uint16 // bridge ifindex → bd_id (for O(1) filter)
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewFDBWatcher creates a new FDB watcher
func NewFDBWatcher(mapOps *bpf.MapOperations, configs []config.BridgeDomainConfig, logger *zap.Logger) *FDBWatcher {
	return &FDBWatcher{
		mapOps:  mapOps,
		logger:  logger,
		configs: configs,
		done:    make(chan struct{}),
	}
}

// Start resolves bridge names to ifindexes and begins watching FDB updates.
func (w *FDBWatcher) Start(ctx context.Context) error {
	// Resolve bridge names → ifindexes
	w.allowed = make(map[int]uint16, len(w.configs))
	for _, cfg := range w.configs {
		link, err := netlink.LinkByName(cfg.BridgeName)
		if err != nil {
			return fmt.Errorf("bridge %q not found: %w", cfg.BridgeName, err)
		}
		ifindex := link.Attrs().Index
		w.allowed[ifindex] = cfg.BdID
		w.logger.Info("Resolved bridge domain",
			zap.String("bridge", cfg.BridgeName),
			zap.Int("ifindex", ifindex),
			zap.Uint16("bd_id", cfg.BdID))
	}

	updates := make(chan netlink.NeighUpdate, 256)

	if err := netlink.NeighSubscribeWithOptions(updates, w.done, netlink.NeighSubscribeOptions{
		ListExisting: true,
	}); err != nil {
		return err
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.processUpdates(ctx, updates)
	}()

	return nil
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

	// Filter: only process FDB entries from configured bridges
	bdID, ok := w.allowed[neigh.MasterIndex]
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

	case unix.RTM_DELNEIGH:
		if err := w.mapOps.DeleteFdb(bdID, net.HardwareAddr(mac)); err != nil {
			w.logger.Debug("Failed to delete FDB entry from BPF map",
				zap.String("mac", mac.String()),
				zap.Uint16("bd_id", bdID),
				zap.Error(err))
		}
	}
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
