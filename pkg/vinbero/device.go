package vinbero

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// Errors AttachDevice / DetachDevice return; the RPC layer maps them to
// status codes.
var (
	// ErrNoInterface: no network interface has the requested name.
	ErrNoInterface = errors.New("no such interface")
	// ErrNotAttached: the device is not on the data plane.
	ErrNotAttached = errors.New("device is not attached")
	// ErrModeConflict: the device is attached in a different XDP mode.
	ErrModeConflict = errors.New("device is attached in another mode")
	// ErrConfigDevice: the device comes from internal.devices, which owns it.
	ErrConfigDevice = errors.New("device is declared in internal.devices")
	// ErrInvalidMode: the XDP mode is not one config.ConvToStrXDPAttachMode knows.
	ErrInvalidMode = errors.New("invalid XDP mode")
)

// Device describes one interface the data plane is attached to.
type Device struct {
	Name    string
	Ifindex int
	// Mode is the XDP attach mode in config spelling ("driver", "generic", ...).
	Mode string
	// Config is true for an internal.devices entry. Those are attached at
	// boot from the config file and are not persisted in the state file.
	Config bool
}

// deviceAttachment is an attached device and the two links that put it on
// the data plane: the XDP entry program and the TCX ingress program (BUM).
type deviceAttachment struct {
	Device
	xdp link.Link
	tc  link.Link
}

// deviceLinkOps is the kernel surface of a device attach. Tests replace it.
type deviceLinkOps interface {
	ifindex(name string) (int, error)
	attachXDP(ifindex int, flags link.XDPAttachFlags) (link.Link, error)
	attachTC(ifindex int) (link.Link, error)
}

type kernelLinkOps struct{ v *Vinbero }

// ifindex looks the name up with one RTM_GETLINK request (net.InterfaceByName
// dumps every link, which adds up when ListDevices checks each attachment).
func (k kernelLinkOps) ifindex(name string) (int, error) {
	l, err := netlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return 0, fmt.Errorf("%w: %s", ErrNoInterface, name)
	}
	if err != nil {
		return 0, fmt.Errorf("look up interface %s: %w", name, err)
	}
	return l.Attrs().Index, nil
}

func (k kernelLinkOps) attachXDP(ifindex int, flags link.XDPAttachFlags) (link.Link, error) {
	return link.AttachXDP(link.XDPOptions{
		Program:   k.v.obj.VinberoMain,
		Interface: ifindex,
		Flags:     flags,
	})
}

func (k kernelLinkOps) attachTC(ifindex int) (link.Link, error) {
	return link.AttachTCX(link.TCXOptions{
		Program:   k.v.obj.VinberoTcIngress,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifindex,
	})
}

func (v *Vinbero) linkOps() deviceLinkOps {
	if v.devOps != nil {
		return v.devOps
	}
	return kernelLinkOps{v}
}

// resolveMode returns the config spelling and the attach flags of an XDP
// mode; "" selects internal.bpf.device_mode.
func (v *Vinbero) resolveMode(mode string) (string, link.XDPAttachFlags, error) {
	if mode == "" {
		mode = v.cfg.InternalConfig.BpfOptions.DeviceMode
	}
	flags, err := config.ConvToStrXDPAttachMode(mode)
	if err != nil {
		return "", 0, fmt.Errorf("%w %q (want generic, driver or offload)", ErrInvalidMode, mode)
	}
	return mode, flags, nil
}

// AttachConfigDevices attaches every internal.devices entry, in the mode
// internal.bpf.device_mode names. A failure is fatal for the boot, as it
// was before devices could be attached at runtime.
func (v *Vinbero) AttachConfigDevices() error {
	if v.bumSync != nil {
		// From here on a device joining bum_tx_map waits for the NAPI
		// polls in flight (native XDP).
		v.bumSync.SetLive()
	}
	v.devMu.Lock()
	defer v.devMu.Unlock()
	for _, dev := range v.devices {
		if _, err := v.attachLocked(dev.Name, ""); err != nil {
			return err
		}
	}
	return nil
}

// AttachDevice puts an interface on the data plane at runtime and records
// it in the state file, so a daemon restart attaches it again. mode ""
// selects internal.bpf.device_mode. Attaching a device that is already
// attached in the same mode succeeds without touching the kernel.
//
// A failure to write the state file is returned, but the attach is kept:
// a retry is idempotent and writes the state again.
func (v *Vinbero) AttachDevice(name, mode string) (Device, error) {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	a, err := v.attachLocked(name, mode)
	if err != nil {
		return Device{}, err
	}
	if !a.Config && v.resMgr != nil {
		if err := v.resMgr.AddDevice(a.Name, a.Mode); err != nil {
			return a.Device, err
		}
	}
	return a.Device, nil
}

// attachLocked attaches XDP and TCX to name as a pair: if the TCX attach
// fails, the XDP link is closed again so no half-attached device is left.
// An internal.devices entry always uses internal.bpf.device_mode, the mode
// the next start attaches it in. Caller holds v.devMu.
func (v *Vinbero) attachLocked(name, mode string) (*deviceAttachment, error) {
	mode, flags, err := v.resolveMode(mode)
	if err != nil {
		return nil, err
	}
	fromConfig := v.isConfigDevice(name)
	if fromConfig && mode != v.cfg.InternalConfig.BpfOptions.DeviceMode {
		return nil, fmt.Errorf("%w: %s is declared in internal.devices, which attaches it in %s mode",
			ErrModeConflict, name, v.cfg.InternalConfig.BpfOptions.DeviceMode)
	}
	ops := v.linkOps()
	ifindex, err := ops.ifindex(name)
	if err != nil {
		return nil, err
	}
	if a, ok := v.attached[name]; ok {
		if a.Ifindex == ifindex {
			if a.Mode != mode {
				return nil, fmt.Errorf("%w: %s is attached in %s mode, requested %s (detach it first)", ErrModeConflict, name, a.Mode, mode)
			}
			return a, nil
		}
		// The interface was deleted and a new one took its name. The old
		// links point at a device that no longer exists.
		v.dropLocked(a, "interface was recreated")
	}

	xdp, err := ops.attachXDP(ifindex, flags)
	if err != nil {
		return nil, fmt.Errorf("attach XDP program to device %s: %w", name, err)
	}
	tc, err := ops.attachTC(ifindex)
	if err != nil {
		if cerr := xdp.Close(); cerr != nil {
			v.logger.Warn("rollback: close XDP link", zap.String("device", name), zap.Error(cerr))
		}
		return nil, fmt.Errorf("attach TC program to device %s: %w", name, err)
	}
	a := &deviceAttachment{
		Device: Device{Name: name, Ifindex: ifindex, Mode: mode, Config: fromConfig},
		xdp:    xdp,
		tc:     tc,
	}
	if v.attached == nil {
		v.attached = make(map[string]*deviceAttachment)
	}
	v.attached[name] = a
	v.logger.Info("Attached device", zap.String("device", name), zap.Int("ifindex", ifindex),
		zap.String("mode", mode), zap.Bool("config", fromConfig))
	return a, nil
}

// DetachDevice takes a runtime-attached device off the data plane and out
// of the state file. A device whose interface is already gone detaches
// successfully. internal.devices entries are refused: the config file owns
// them and would attach them again on the next start.
func (v *Vinbero) DetachDevice(name string) error {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	a, ok := v.attached[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotAttached, name)
	}
	if a.Config {
		return fmt.Errorf("%w: %s (remove it from the config file and restart)", ErrConfigDevice, name)
	}
	// The links are closed even when Close reports an error, so the record
	// goes either way: keeping it would only make the next detach fail.
	closeErr := v.closeLinks(a)
	delete(v.attached, name)
	v.logger.Info("Detached device", zap.String("device", name))
	var persistErr error
	if v.resMgr != nil {
		persistErr = v.resMgr.RemoveDevices(name)
	}
	return errors.Join(closeErr, persistErr)
}

// closeLinks closes XDP before TC, the same order as Close: XDP is the
// ingress, and an XDP_PASS carrying BUM metadata must not reach a detached
// TC program. A close error is ignored when the interface is gone (the
// kernel already released the attachment).
func (v *Vinbero) closeLinks(a *deviceAttachment) error {
	err := closeAttachments(a)
	if err == nil || !v.alive(a) {
		return nil
	}
	return fmt.Errorf("detach device %s: %w", a.Name, err)
}

// closeAttachments closes the XDP links of every attachment, then their TC
// links (see closeLinks for the order), and returns every close error.
func closeAttachments(as ...*deviceAttachment) error {
	var errs []error
	for _, a := range as {
		if err := a.xdp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close XDP link of %s: %w", a.Name, err))
		}
	}
	for _, a := range as {
		if err := a.tc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close TC link of %s: %w", a.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (v *Vinbero) isConfigDevice(name string) bool {
	return slices.ContainsFunc(v.devices, func(d net.Interface) bool { return d.Name == name })
}

// alive reports whether the interface the attachment was made on still
// carries its name. Only a definite answer counts as gone (no interface by
// that name, or one with another ifindex): a failed lookup must not take a
// working device off the data plane.
func (v *Vinbero) alive(a *deviceAttachment) bool {
	ifindex, err := v.linkOps().ifindex(a.Name)
	if err != nil {
		return !errors.Is(err, ErrNoInterface)
	}
	return ifindex == a.Ifindex
}

// dropLocked forgets a stale attachment (its interface is gone or was
// recreated). Caller holds v.devMu.
func (v *Vinbero) dropLocked(a *deviceAttachment, why string) {
	if err := closeAttachments(a); err != nil {
		v.logger.Debug("close stale device links", zap.String("device", a.Name), zap.Error(err))
	}
	delete(v.attached, a.Name)
	v.logger.Info("Dropped stale device", zap.String("device", a.Name), zap.String("reason", why))
}

// ListDevices returns the attached devices sorted by name. Attachments whose
// interface has disappeared are dropped first (and removed from the state
// file), so a pod veth deleted without a detach does not linger.
func (v *Vinbero) ListDevices() []Device {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	var gone []string
	out := make([]Device, 0, len(v.attached))
	for _, a := range v.attached {
		if !v.alive(a) {
			if !a.Config {
				gone = append(gone, a.Name)
			}
			v.dropLocked(a, "interface is gone")
			continue
		}
		out = append(out, a.Device)
	}
	if len(gone) > 0 && v.resMgr != nil {
		if err := v.resMgr.RemoveDevices(gone...); err != nil {
			v.logger.Warn("persist state after dropping vanished devices", zap.Error(err))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ReconcileDevices attaches the devices the state file records, after a
// restart. An entry is dropped from the state, with a warning, when its
// interface is gone (a pod deleted while the daemon was down) or it cannot be
// attached; one device must not keep the daemon from starting. An entry that
// internal.devices now declares is dropped too: the config owns it.
// Call after AttachConfigDevices and InitResourceManager.
func (v *Vinbero) ReconcileDevices() error {
	if v.resMgr == nil {
		return errors.New("reconcile devices: resource manager is not initialized")
	}
	v.devMu.Lock()
	defer v.devMu.Unlock()
	var drop []string
	for _, d := range v.resMgr.ListDevices() {
		if v.isConfigDevice(d.Name) {
			v.logger.Info("Reconcile: device is declared in internal.devices; dropping its state entry",
				zap.String("device", d.Name))
			drop = append(drop, d.Name)
			continue
		}
		if _, err := v.attachLocked(d.Name, d.Mode); err != nil {
			v.logger.Warn("Reconcile: dropping device that cannot be attached",
				zap.String("device", d.Name), zap.String("mode", d.Mode), zap.Error(err))
			drop = append(drop, d.Name)
		}
	}
	// The dropped entries are gone from memory either way; a state file that
	// cannot be written must not keep the daemon from starting either.
	if err := v.resMgr.RemoveDevices(drop...); err != nil {
		v.logger.Warn("Reconcile: persist state after dropping devices", zap.Error(err))
	}
	return nil
}

// closeAllDevices detaches every device: all XDP links first, then all TC
// links (see closeLinks for the order).
func (v *Vinbero) closeAllDevices() error {
	v.devMu.Lock()
	defer v.devMu.Unlock()
	err := closeAttachments(slices.Collect(maps.Values(v.attached))...)
	clear(v.attached)
	return err
}
