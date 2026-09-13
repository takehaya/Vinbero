package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pluginIdentRe matches the BPF section-name alphabet. Applied to the
// caller-controlled program / map_type strings before they hit the audit
// log so a malicious caller cannot inject newlines or quotes that would
// forge a synthetic event line in grep-based monitoring pipelines.
var pluginIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// validPluginIdent reports whether s is a safe identifier to interpolate
// into a structured log record. Empty strings are rejected; the proto
// layer already screens those, this is defense in depth.
func validPluginIdent(s string) bool {
	return pluginIdentRe.MatchString(s)
}

type pluginSlotKey struct {
	MapType string
	Slot    uint32
}

// pluginEntry captures per-slot metadata the server needs after the
// Collection has been closed. AuxType is nil for plugins that did not
// declare a <program>_aux struct — those plugins can still be driven by
// plugin_aux_raw (hex), they just lose the JSON path.
type pluginEntry struct {
	program       string
	auxType       *btf.Struct
	ownedMapNames []string
	sharedRWNames []string
	sharedRONames []string
	registeredAt  time.Time
}

// PluginEntryInfo is a read-only snapshot of a registered plugin's metadata.
// Returned by SnapshotEntries for PluginList RPC and logging.
type PluginEntryInfo struct {
	MapType       string
	Slot          uint32
	Program       string
	HasAuxType    bool
	AuxTypeName   string
	OwnedMapNames []string
	SharedRWNames []string
	SharedRONames []string
	RegisteredAt  time.Time
}

type PluginServer struct {
	mapOps       *bpf.MapOperations
	bpfConstants map[string]any
	roEnforce    bpf.ROEnforceMode
	logger       *zap.Logger

	mu       sync.RWMutex
	registry map[pluginSlotKey]*pluginEntry

	// cplane runs the control-plane (WebAssembly) plugins. Nil when the
	// daemon was built without them, in which case those RPCs answer
	// Unimplemented rather than pretending to work.
	cplane CplaneManager
}

func NewPluginServer(mapOps *bpf.MapOperations, bpfConstants map[string]any, roEnforce bpf.ROEnforceMode, logger *zap.Logger) *PluginServer {
	return &PluginServer{
		mapOps:       mapOps,
		bpfConstants: bpfConstants,
		roEnforce:    roEnforce,
		logger:       logger,
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

// SnapshotEntries returns a deterministic snapshot of all registered plugins.
// Optional filter restricts results to a single map_type ("" means all).
func (s *PluginServer) SnapshotEntries(mapTypeFilter string) []PluginEntryInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PluginEntryInfo, 0, len(s.registry))
	for k, e := range s.registry {
		if mapTypeFilter != "" && k.MapType != mapTypeFilter {
			continue
		}
		info := PluginEntryInfo{
			MapType:       k.MapType,
			Slot:          k.Slot,
			Program:       e.program,
			HasAuxType:    e.auxType != nil,
			OwnedMapNames: append([]string(nil), e.ownedMapNames...),
			SharedRWNames: append([]string(nil), e.sharedRWNames...),
			SharedRONames: append([]string(nil), e.sharedRONames...),
			RegisteredAt:  e.registeredAt,
		}
		if e.auxType != nil {
			info.AuxTypeName = e.auxType.Name
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MapType != out[j].MapType {
			return out[i].MapType < out[j].MapType
		}
		return out[i].Slot < out[j].Slot
	})
	return out
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
	// Constrain program / map_type to the BPF section-name alphabet so a
	// caller cannot smuggle newlines or quotes through to the audit log
	// and forge a synthetic event line in stdout-grep style monitoring.
	if !validPluginIdent(msg.Program) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("program must match [A-Za-z_][A-Za-z0-9_]{0,63}"))
	}
	if !validPluginIdent(msg.MapType) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("map_type must match [A-Za-z_][A-Za-z0-9_]{0,63}"))
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(msg.BpfElf))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse BPF ELF: %w", err))
	}

	// The shared-RO set is rebuilt per call so a future runtime
	// reconfiguration can change it without rebooting; the helper is
	// O(1) per name so the cost is in the noise compared to ELF parsing.
	roSet := bpf.SharedReadOnlyMapNamesSet()
	if _, err := bpf.ValidatePluginCollection(spec, msg.Program, roSet); err != nil {
		// In warn mode we keep loading the plugin but surface every
		// detected violation to the audit log so ops can see who would
		// be rejected once enforce is flipped on. Other validator
		// failures (forbidden helper, missing epilogue, BTF mismatch,
		// ...) are not warn-eligible and always reject.
		// A write to a dispatch/aux integrity map is never warn-downgradable:
		// it lets the plugin forge the action the aux discriminator reads or
		// install a SID function outside its scope, so no deployment may run
		// it regardless of ro_enforce.
		if s.roEnforce == bpf.ROEnforceWarn && errors.Is(err, bpf.ErrPluginROWrite) &&
			!errors.Is(err, bpf.ErrPluginIntegrityMapWrite) {
			s.logger.Warn("plugin RO write violation (warn-only)",
				zap.String("program", msg.Program),
				zap.String("map_type", msg.MapType),
				zap.Uint32("slot", msg.Index),
				zap.Error(err),
			)
		} else {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
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
	// may override them at runtime). Classify each replacement as RO or RW
	// so PluginList / audit can show intent; any map declared by the plugin
	// ELF that is not a shared vinbero map is recorded as plugin-owned.
	sharedRO := s.mapOps.GetSharedReadOnlyMaps()
	sharedRW := s.mapOps.GetSharedReadWriteMaps()
	replacements := make(map[string]*ebpf.Map)
	var usedRO, usedRW, ownedMaps []string
	for name, ms := range spec.Maps {
		if m, ok := sharedRO[name]; ok {
			if info, err := m.Info(); err == nil {
				ms.MaxEntries = info.MaxEntries
			}
			replacements[name] = m
			usedRO = append(usedRO, name)
			continue
		}
		if m, ok := sharedRW[name]; ok {
			if info, err := m.Info(); err == nil {
				ms.MaxEntries = info.MaxEntries
			}
			replacements[name] = m
			usedRW = append(usedRW, name)
			continue
		}
		ownedMaps = append(ownedMaps, name)
	}
	sort.Strings(usedRO)
	sort.Strings(usedRW)
	sort.Strings(ownedMaps)
	s.logger.Info("plugin map linkage",
		zap.String("program", msg.Program),
		zap.String("map_type", msg.MapType),
		zap.Uint32("slot", msg.Index),
		zap.Strings("shared_ro", usedRO),
		zap.Strings("shared_rw", usedRW),
		zap.Strings("owned_maps", ownedMaps),
	)

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
		program:       msg.Program,
		auxType:       auxType,
		ownedMapNames: ownedMaps,
		sharedRWNames: usedRW,
		sharedRONames: usedRO,
		registeredAt:  time.Now(),
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

	// Surface orphan aux indices owned by this slot. PluginUnregister does
	// not free them — callers are expected to PluginAuxFree per index before
	// retiring the slot, otherwise the indices leak in the in-memory
	// allocator until daemon restart. Log only; do not fail the RPC because
	// the registry / PROG_ARRAY removal already succeeded.
	ownerTag := bpf.AuxOwnerPluginTag(msg.MapType, msg.Index)
	if remaining := s.mapOps.CountAuxByOwner(ownerTag); remaining > 0 {
		s.logger.Warn("plugin slot unregistered with live aux entries",
			zap.String("owner", ownerTag),
			zap.String("map_type", msg.MapType),
			zap.Uint32("slot", msg.Index),
			zap.Int("remaining_aux", remaining),
		)
	}

	return connect.NewResponse(&v1.PluginUnregisterResponse{}), nil
}

func (s *PluginServer) PluginList(
	ctx context.Context,
	req *connect.Request[v1.PluginListRequest],
) (*connect.Response[v1.PluginListResponse], error) {
	entries := s.SnapshotEntries(req.Msg.MapTypeFilter)
	resp := &v1.PluginListResponse{Plugins: make([]*v1.PluginInfo, 0, len(entries))}
	for _, e := range entries {
		resp.Plugins = append(resp.Plugins, &v1.PluginInfo{
			MapType:       e.MapType,
			Slot:          e.Slot,
			Program:       e.Program,
			HasAuxType:    e.HasAuxType,
			AuxTypeName:   e.AuxTypeName,
			OwnedMapNames: e.OwnedMapNames,
			SharedRwNames: e.SharedRWNames,
			SharedRoNames: e.SharedRONames,
			RegisteredAt:  timestamppb.New(e.RegisteredAt),
		})
	}
	return connect.NewResponse(resp), nil
}
