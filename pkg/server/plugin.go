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
	if msg.Section == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("section is required"))
	}

	// Load BPF collection spec from ELF bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(msg.BpfElf))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse BPF ELF: %w", err))
	}

	// Find the requested program section
	if _, ok := spec.Programs[msg.Section]; !ok {
		var available []string
		for name := range spec.Programs {
			available = append(available, name)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("section %q not found in ELF; available: %v", msg.Section, available))
	}

	// Verify the plugin includes tailcall_epilogue (required by plugin contract).
	// tailcall_epilogue is a __noinline BPF subprogram that appears in the ELF
	// as a function in the .text section. cilium/ebpf attaches subprograms to
	// their calling program, so we check if any program references it by
	// looking for it in the ELF's program specs (it may be in .text or as a
	// subprogram of the main function). We verify by checking the function name
	// exists in any program's instructions.
	hasEpilogue := false
	for _, ps := range spec.Programs {
		for _, fn := range ps.Instructions.FunctionReferences() {
			if fn == "tailcall_epilogue" {
				hasEpilogue = true
				break
			}
		}
		if hasEpilogue {
			break
		}
	}
	if !hasEpilogue {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("plugin does not include tailcall_epilogue; include core/xdp_tailcall_helpers.h and call tailcall_epilogue() before returning"))
	}

	// Ensure all programs are XDP type
	for _, ps := range spec.Programs {
		ps.Type = ebpf.XDP
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

	prog, ok := coll.Programs[msg.Section]
	if !ok {
		coll.Close()
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("program %q disappeared after load", msg.Section))
	}

	if err := s.mapOps.RegisterPlugin(msg.MapType, msg.Index, prog.FD()); err != nil {
		coll.Close()
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
