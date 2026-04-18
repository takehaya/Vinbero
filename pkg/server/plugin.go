package server

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type pluginSlotKey struct {
	MapType string
	Slot    uint32
}

// pluginEntry captures per-slot metadata the server needs after the
// Collection has been closed. AuxType is nil for plugins that did not
// declare a <program>_aux struct — those plugins can still be driven by
// plugin_aux_raw (hex), they just lose the JSON path.
type pluginEntry struct {
	program string
	auxType *btf.Struct
}

type PluginServer struct {
	mapOps       *bpf.MapOperations
	bpfConstants map[string]any

	mu       sync.RWMutex
	registry map[pluginSlotKey]*pluginEntry
}

func NewPluginServer(mapOps *bpf.MapOperations, bpfConstants map[string]any) *PluginServer {
	return &PluginServer{
		mapOps:       mapOps,
		bpfConstants: bpfConstants,
		registry:     make(map[pluginSlotKey]*pluginEntry),
	}
}

// SnapshotNames returns slot -> program name for plugins currently
// registered under the given map type. Used by StatsServer for labeling.
func (s *PluginServer) SnapshotNames(mapType string) map[uint32]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint32]string)
	for k, entry := range s.registry {
		if k.MapType == mapType {
			out[k.Slot] = entry.program
		}
	}
	return out
}

// AuxType returns the BTF struct describing the plugin's aux layout, or
// nil if the plugin did not declare <program>_aux. Callers use this to
// encode plugin_aux_json into bytes.
func (s *PluginServer) AuxType(mapType string, slot uint32) *btf.Struct {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.registry[pluginSlotKey{MapType: mapType, Slot: slot}]
	if !ok {
		return nil
	}
	return entry.auxType
}

func (s *PluginServer) PluginRegister(
	ctx context.Context,
	req *connect.Request[v1.PluginRegisterRequest],
) (*connect.Response[v1.PluginRegisterResponse], error) {
	msg := req.Msg

	if len(msg.BpfElf) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bpf_elf is empty"))
	}
	if msg.Program == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("program is required"))
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(msg.BpfElf))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse BPF ELF: %w", err))
	}

	if _, err := bpf.ValidatePluginCollection(spec, msg.Program); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// The plugin ELF ships its own copy of shared `const volatile` vars
	// (notably enable_stats). Rewrite them to match vinbero's runtime
	// config so that gated helpers like stats_inc() behave consistently
	// between the main data plane and the plugin.
	for name, value := range s.bpfConstants {
		varSpec, ok := spec.Variables[name]
		if !ok {
			continue
		}
		if err := varSpec.Set(value); err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("failed to rewrite BPF constant %s: %w", name, err))
		}
	}

	// Build map replacements: for maps that exist in both the plugin spec
	// and vinbero's shared maps. Update the spec's MaxEntries to match the
	// runtime map (plugin ELF has compile-time defaults, but vinbero config
	// may override them at runtime).
	sharedMaps := s.mapOps.GetSharedMaps()
	replacements := make(map[string]*ebpf.Map)
	for name, m := range sharedMaps {
		if ms, exists := spec.Maps[name]; exists {
			if info, err := m.Info(); err == nil {
				ms.MaxEntries = info.MaxEntries
			}
			replacements[name] = m
		}
	}

	// Load the collection with shared map references from vinbero.
	// This allows the plugin to access tailcall_ctx_map, stats_map, etc.
	// Plugin-specific maps (e.g., plugin_counter_map) are created fresh.
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: replacements,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to load BPF program: %w", err))
	}
	// Close the collection when done. The PROG_ARRAY map holds a kernel
	// reference to the program, so closing the userspace FD is safe.
	defer coll.Close()

	prog, ok := coll.Programs[msg.Program]
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("program %q disappeared after load", msg.Program))
	}

	if err := s.mapOps.RegisterPlugin(msg.MapType, msg.Index, prog.FD()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to register plugin: %w", err))
	}

	// Capture the plugin's aux struct type, if it declared one via
	// VINBERO_PLUGIN_AUX_TYPE. The struct lives on in the server after
	// Collection.Close() because *btf.Struct is a pure Go value copied out
	// of spec.Types. Plugins without the anchor get auxType == nil, which
	// the JSON encoder treats as "use plugin_aux_raw instead".
	var auxType *btf.Struct
	if spec.Types != nil {
		var t *btf.Struct
		if err := spec.Types.TypeByName(msg.Program+"_aux", &t); err == nil {
			auxType = t
		}
	}

	s.mu.Lock()
	s.registry[pluginSlotKey{MapType: msg.MapType, Slot: msg.Index}] = &pluginEntry{
		program: msg.Program,
		auxType: auxType,
	}
	s.mu.Unlock()

	return connect.NewResponse(&v1.PluginRegisterResponse{}), nil
}

func (s *PluginServer) PluginUnregister(
	ctx context.Context,
	req *connect.Request[v1.PluginUnregisterRequest],
) (*connect.Response[v1.PluginUnregisterResponse], error) {
	msg := req.Msg

	if err := s.mapOps.UnregisterPlugin(msg.MapType, msg.Index); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to unregister plugin: %w", err))
	}

	s.mu.Lock()
	delete(s.registry, pluginSlotKey{MapType: msg.MapType, Slot: msg.Index})
	s.mu.Unlock()

	return connect.NewResponse(&v1.PluginUnregisterResponse{}), nil
}
