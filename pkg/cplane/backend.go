package cplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/tetratelabs/wazero"
)

const (
	BackendWASM   = "wasm"
	BackendNative = "native"
)

var ErrNativeDisabled = errors.New("cplane: native controllers are disabled")

type pluginInstance interface {
	HandleEvents(context.Context, []byte) ([]byte, error)
	Tick(context.Context, int64) error
	Close(context.Context) error
}

func (m *Manager) validateBackend(reg *Registration) error {
	if reg.Backend == "" {
		reg.Backend = BackendNative
		// A supplied module remains an explicit WASM choice for older clients.
		if len(reg.Module) != 0 {
			reg.Backend = BackendWASM
		}
	}
	switch reg.Backend {
	case BackendWASM:
		if reg.NativeID != "" || reg.NativeVersion != "" || reg.NativeIdentity != "" {
			return fmt.Errorf("%w: WASM registration has native identity", wasm.ErrAdmission)
		}
	case BackendNative:
		if !m.allowNative {
			return ErrNativeDisabled
		}
		if len(reg.Module) != 0 {
			return fmt.Errorf("%w: native registration contains a WASM module", wasm.ErrAdmission)
		}
		if reg.NativeID == "" {
			reg.NativeID = reg.Name
		}
		desc, _ := native.Lookup(reg.NativeID)
		if reg.NativeVersion == "" {
			reg.NativeVersion = desc.Version
		}
		if err := native.ValidateIdentity(reg.NativeID, reg.NativeVersion); err != nil {
			return err
		}
		if reg.NativeIdentity != "" && reg.NativeIdentity != desc.Identity {
			return fmt.Errorf("%w: native implementation identity changed", wasm.ErrAdmission)
		}
		reg.NativeIdentity = desc.Identity
	default:
		return fmt.Errorf("%w: unknown backend %q", wasm.ErrAdmission, reg.Backend)
	}
	return nil
}

// One factory is used for initial registration, replacement and restart.
func (m *Manager) instantiate(ctx context.Context, reg Registration, config []byte, ops *PluginOps, cache wazero.CompilationCache) (pluginInstance, error) {
	cfg := wasm.Config{NowMonotonic: m.nowMonotonic, Name: reg.Name, Module: reg.Module, ConfigBlob: config, Limits: reg.Limits, Ops: ops, Capabilities: reg.Capabilities, Logger: m.logger}
	if reg.Backend == BackendNative {
		return native.Instantiate(ctx, native.Config{Config: cfg, Implementation: reg.NativeID, Version: reg.NativeVersion})
	}
	cfg.CompilationCache = cache
	return wasm.Instantiate(ctx, cfg)
}
