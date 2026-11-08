package vinbero

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

type Vinbero struct {
	cfg      *config.Config
	obj      *bpf.BpfObjects
	mapOps   *bpf.MapOperations
	devices  []net.Interface // internal.devices, resolved at startup
	devMu    sync.Mutex      // guards attached
	attached map[string]*deviceAttachment
	devOps   deviceLinkOps // nil = the kernel; tests replace it
	// unsaved names the detached devices whose state write failed, so a
	// retried detach writes the state again instead of NOT_FOUND. Guarded
	// by devMu.
	unsaved    map[string]bool
	fdbWatcher *netlinkwatch.FDBWatcher
	resMgr     *netresource.ResourceManager
	bumSync    *bpf.BumDevmapSync // nil unless a BD runs in xdp BUM mode
	logger     *zap.Logger
}

func NewVinbero(cfg *config.Config, logger *zap.Logger) (*Vinbero, error) {
	if l2 := &cfg.Setting.L2; l2.ConfiguresXDP() {
		if err := checkBumXDPKernel(kernelRealtimePath); err != nil {
			return nil, err
		}
		// Only generic XDP copies a broadcast as skb clones; native XDP
		// copies every frame (xdpf_clone).
		if cfg.InternalConfig.BpfOptions.DeviceMode == "generic" {
			if reason := bumXDPUnavailable(probeGenericBroadcastCopies); reason != "" {
				l2.DisableXDP(reason)
				logger.Warn("xdp BUM replication unavailable on this kernel: bridge domains configured with "+
					"bum_mode xdp replicate BUM in tc instead (counted as BUM_XDP_FALLBACK)",
					zap.String("reason", reason))
			}
		}
	}

	obj, err := bpf.ReadCollection(cfg.BpfConstants(), cfg)
	if err != nil {
		return nil, fmt.Errorf("fail to bpf load: %w", err)
	}

	// Create map operations and recover aux index state from existing entries
	mapOps := bpf.NewMapOperations(obj)
	if err := mapOps.RecoverAuxIndices(); err != nil {
		logger.Warn("failed to recover aux indices, starting fresh", zap.Error(err))
	}

	var bumSync *bpf.BumDevmapSync
	if l2 := &cfg.Setting.L2; l2.ConfiguresXDP() {
		native := cfg.InternalConfig.BpfOptions.DeviceMode == "driver"
		if bumSync, err = setupBumXDP(obj, mapOps, l2, native, logger); err != nil {
			_ = obj.Close()
			return nil, err
		}
	}

	// resolve device interfaces
	var devices []net.Interface
	for _, deviceName := range cfg.InternalConfig.Devices {
		iface, err := net.InterfaceByName(deviceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface %s: %w", deviceName, err)
		}
		devices = append(devices, *iface)
	}

	return &Vinbero{
		cfg:     cfg,
		obj:     obj,
		mapOps:  mapOps,
		devices: devices,
		bumSync: bumSync,
		logger:  logger,
	}, nil
}

// setupBumXDP writes the per-BD mode overrides and builds the xdp-mode
// devmaps from whatever headend_l2 / bd_peer state the maps already hold
// (pinned maps after a restart); every later mutation rebuilds its BD.
// When xdp mode is unavailable only the overrides are written, and no BD
// gets a devmap.
func setupBumXDP(obj *bpf.BpfObjects, mapOps *bpf.MapOperations, l2 *config.L2Config, native bool, logger *zap.Logger) (*bpf.BumDevmapSync, error) {
	for bd, mode := range l2.BumModeOverrides() {
		if err := mapOps.SetBdBumMode(bd, mode); err != nil {
			return nil, fmt.Errorf("write BUM mode of bd %d: %w", bd, err)
		}
	}
	if !l2.AnyXDP() {
		return nil, nil
	}
	bs := bpf.NewBumDevmapSync(obj, l2.EffectiveBumMode, bpf.RouteUplinkResolver, logger)
	bs.SetNeighKeeper(bpf.KeepNeighResolved)
	bs.SetNativeXDP(native)
	mapOps.SetBumDevmapSync(bs)
	if err := bs.SyncAll(); err != nil {
		logger.Warn("xdp BUM: initial devmap build incomplete", zap.Error(err))
	}
	logger.Info("BUM replication in XDP enabled",
		zap.String("default_mode", l2.BumMode), zap.Int("bd_overrides", len(l2.BridgeDomains)),
		zap.Bool("native_xdp", native))
	return bs, nil
}

// probeGenericBroadcastCopies is the startup check of bumXDPUnavailable.
var probeGenericBroadcastCopies = bpf.ProbeGenericBroadcastCopies

// bumProbeTimeout bounds the wait for the probe's frames; they normally
// come back within a millisecond.
const bumProbeTimeout = time.Second

// bumXDPUnavailable returns why this host cannot run xdp-mode BUM
// replication, or "". xdp mode writes a different encapsulation into each
// copy of a generic-XDP broadcast, which needs every copy on a buffer of its
// own; the probe tries exactly that in a throwaway network namespace. A
// probe that cannot run counts as unavailable: tc mode works everywhere.
func bumXDPUnavailable(probe func(time.Duration) (bool, error)) string {
	private, err := probe(bumProbeTimeout)
	if err != nil {
		return "the generic XDP broadcast check could not run: " + err.Error()
	}
	if !private {
		return "the copies of a generic XDP broadcast share one packet buffer on this kernel " +
			"(it lacks \"bpf: Run generic devmap egress prog on private skb\")"
	}
	return ""
}

// kernelRealtimePath reads "1" on a PREEMPT_RT kernel.
const kernelRealtimePath = "/sys/kernel/realtime"

// checkBumXDPKernel refuses xdp BUM mode on PREEMPT_RT. The devmap egress
// program finds a copy's replication plan as the latest one of its CPU,
// which holds because a BH-disabled section is never interleaved with
// another one on the same CPU. PREEMPT_RT kernels without
// CONFIG_PREEMPT_RT_NEEDS_BH_LOCK let one preempt another, so a second
// frame could be planned on that CPU before the first frame's copies run.
func checkBumXDPKernel(realtimePath string) error {
	b, err := os.ReadFile(realtimePath)
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		return nil
	}
	return errors.New("settings.l2: bum_mode \"xdp\" is not supported on a PREEMPT_RT kernel " +
		"(BH sections are preemptible there, and the per-CPU replication plan could belong to another frame); use bum_mode \"tc\"")
}

// StartBumRouteWatch rebuilds the xdp-mode devmaps on routing changes, so a
// flood slot follows its peer's uplink. A no-op without xdp-mode BDs.
func (v *Vinbero) StartBumRouteWatch(ctx context.Context) error {
	if v.bumSync == nil {
		return nil
	}
	return v.bumSync.WatchRoutes(ctx, bumRouteDebounce)
}

const bumRouteDebounce = 200 * time.Millisecond

const defaultStatePath = "/var/lib/vinbero/state.json"

// InitResourceManager initializes the resource manager and reconciles state.
func (v *Vinbero) InitResourceManager() error {
	statePath := v.cfg.Setting.StatePath
	if statePath == "" {
		statePath = defaultStatePath
	}

	resMgr, err := netresource.NewResourceManager(statePath, v.logger)
	if err != nil {
		return fmt.Errorf("init resource manager: %w", err)
	}

	// Fail-closed: a state entry that cannot be materialized aborts the boot
	// (the error carries a repair hint). Continuing with a phantom entry
	// would hand its stale ifindex to the FDB watcher, the EVPN machinery
	// and the SID-reference delete guards, which then silently mis-key.
	if err := resMgr.Reconcile(); err != nil {
		return fmt.Errorf("reconcile managed resources: %w", err)
	}

	v.resMgr = resMgr
	return nil
}

// StartFDBWatcher starts the FDB watcher and registers reconciled bridges.
func (v *Vinbero) StartFDBWatcher(ctx context.Context) error {
	v.fdbWatcher = netlinkwatch.NewFDBWatcher(v.mapOps, v.logger)
	v.fdbWatcher.SetAgingSeconds(v.cfg.Setting.FdbAgingSeconds)
	if l2 := &v.cfg.Setting.L2; l2.AnyXDP() {
		v.fdbWatcher.SetXDPLearnedBDs(func(bd uint16) bool {
			return l2.EffectiveBumMode(bd) == config.BumModeValueXDP
		})
	}
	if err := v.fdbWatcher.Start(ctx); err != nil {
		return fmt.Errorf("failed to start FDB watcher: %w", err)
	}
	if v.bumSync != nil {
		events, err := v.mapOps.NewFdbEventReader()
		if err != nil {
			return err
		}
		v.fdbWatcher.StartXDPEvents(events)
	}

	// Register bridges from reconciled state so FDB sync works after restart
	if v.resMgr != nil {
		for _, br := range v.resMgr.ListBridges() {
			v.fdbWatcher.RegisterBridge(int(br.Ifindex), br.BdID)
		}
	}

	v.logger.Info("FDB watcher started")
	return nil
}

// GetResourceManager returns the resource manager instance
func (v *Vinbero) GetResourceManager() *netresource.ResourceManager {
	return v.resMgr
}

// GetFDBWatcher returns the FDB watcher instance
func (v *Vinbero) GetFDBWatcher() *netlinkwatch.FDBWatcher {
	return v.fdbWatcher
}

// GetMapOperations returns the map operations instance
func (v *Vinbero) GetMapOperations() *bpf.MapOperations {
	return v.mapOps
}

// GetConfig returns the configuration
func (v *Vinbero) GetConfig() *config.Config {
	return v.cfg
}

func (v *Vinbero) Close() error {
	var errs []error

	if v.fdbWatcher != nil {
		v.fdbWatcher.Stop()
	}
	if err := v.closeAllDevices(); err != nil {
		errs = append(errs, err)
	}
	if err := v.obj.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close bpf objects: %w", err))
	}
	return errors.Join(errs...)
}
