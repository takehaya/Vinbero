package vinbero

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

type Vinbero struct {
	cfg        *config.Config
	obj        *bpf.BpfObjects
	mapOps     *bpf.MapOperations
	devices    []net.Interface
	devLinks   []link.Link
	tcLinks    []link.Link
	fdbWatcher *netlinkwatch.FDBWatcher
	resMgr     *netresource.ResourceManager
	logger     *zap.Logger
}

func NewVinbero(cfg *config.Config, logger *zap.Logger) (*Vinbero, error) {
	// Build BPF constants from config
	constants := buildBpfConstants(cfg)

	obj, err := bpf.ReadCollection(constants, cfg)
	if err != nil {
		return nil, fmt.Errorf("fail to bpf load: %w", err)
	}

	// Create map operations
	mapOps := bpf.NewMapOperations(obj)

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
		logger:  logger,
	}, nil
}

func (v *Vinbero) LoadXDPProgram() error {
	attachMode, err := config.ConvToStrXDPAttachMode(v.cfg.InternalConfig.BpfOptions.DeviceMode)
	if err != nil {
		return fmt.Errorf("invalid XDP attach mode: %w", err)
	}
	for _, dev := range v.devices {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   v.obj.VinberoMain,
			Interface: dev.Index,
			Flags:     attachMode,
		})
		if err != nil {
			return fmt.Errorf("failed to attach XDP program to device %s: %w", dev.Name, err)
		}
		v.devLinks = append(v.devLinks, l)
	}

	return nil
}

func (v *Vinbero) LoadTCProgram() error {
	for _, dev := range v.devices {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   v.obj.VinberoTcIngress,
			Attach:    ebpf.AttachTCXIngress,
			Interface: dev.Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC program to device %s: %w", dev.Name, err)
		}
		v.tcLinks = append(v.tcLinks, l)
	}
	return nil
}

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

	if err := resMgr.Reconcile(); err != nil {
		v.logger.Warn("resource reconciliation had issues", zap.Error(err))
	}

	v.resMgr = resMgr
	return nil
}

// StartFDBWatcher starts the FDB watcher and registers reconciled bridges.
func (v *Vinbero) StartFDBWatcher(ctx context.Context) error {
	v.fdbWatcher = netlinkwatch.NewFDBWatcher(v.mapOps, v.logger)
	if err := v.fdbWatcher.Start(ctx); err != nil {
		return fmt.Errorf("failed to start FDB watcher: %w", err)
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
	// Detach XDP first (stop ingress) before removing TC (BUM encap).
	// Otherwise XDP_PASS with BUM meta can reach a detached TC program.
	for _, l := range v.devLinks {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP link: %w", err))
		}
	}
	for _, l := range v.tcLinks {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TC link: %w", err))
		}
	}
	if err := v.obj.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close bpf objects: %w", err))
	}
	return errors.Join(errs...)
}

// buildBpfConstants creates BPF constant values from config
func buildBpfConstants(cfg *config.Config) map[string]interface{} {
	constants := make(map[string]interface{})

	// Convert bool to uint8 (BPF uses uint8 for these flags)
	if cfg.Setting.EnableStats {
		constants["enable_stats"] = uint8(1)
	} else {
		constants["enable_stats"] = uint8(0)
	}

	if cfg.Setting.EnableXdpcap {
		constants["enable_xdpcap"] = uint32(1)
	} else {
		constants["enable_xdpcap"] = uint32(0)
	}

	return constants
}
