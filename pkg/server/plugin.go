package server

import (
	"bytes"
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type PluginServer struct {
	mapOps *bpf.MapOperations
}

func NewPluginServer(mapOps *bpf.MapOperations) *PluginServer {
	return &PluginServer{mapOps: mapOps}
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

	return connect.NewResponse(&v1.PluginUnregisterResponse{}), nil
}
