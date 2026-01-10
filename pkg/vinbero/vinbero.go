package vinbero

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"go.uber.org/zap"
)

type Vinbero struct {
	cfg      *config.Config
	obj      *bpf.BpfObjects
	mapOps   *bpf.MapOperations
	devices  []net.Interface
	devLinks []link.Link
}

func NewVinbero(cfg *config.Config, logger *zap.Logger) (*Vinbero, error) {
	obj, err := bpf.ReadCollection(nil, cfg)
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

// GetMapOperations returns the map operations instance
func (v *Vinbero) GetMapOperations() *bpf.MapOperations {
	return v.mapOps
}

// GetConfig returns the configuration
func (v *Vinbero) GetConfig() *config.Config {
	return v.cfg
}

func (v *Vinbero) Close() error {
	for _, l := range v.devLinks {
		if err := l.Close(); err != nil {
			return fmt.Errorf("failed to close link: %w", err)
		}
	}
	if err := v.obj.Close(); err != nil {
		return fmt.Errorf("failed to close bpf objects: %w", err)
	}
	return nil
}
