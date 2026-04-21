package bpf

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// SymTailcallEpilogue is the BPF subprogram every plugin must call before
// returning an XDP action so per-action stats are recorded.
const SymTailcallEpilogue = "tailcall_epilogue"

// ValidTailCallMaps lists the vinbero-managed PROG_ARRAYs a plugin is allowed
// to bpf_tail_call into. Dispatching back to a vinbero PROG_ARRAY is how a
// plugin hands control to another validated slot; tail-calling into a plugin-
// owned map would escape the validation boundary.
var ValidTailCallMaps = []string{
	MapNameSidEndpointProgs,
	MapNameHeadendV4Progs,
	MapNameHeadendV6Progs,
}

// ForbiddenHelpers names BPF helpers whose direct use from a plugin would
// bypass vinbero's dispatch/stats/ownership invariants. Packet-level redirect
// decisions must flow through the epilogue or a vinbero PROG_ARRAY.
var ForbiddenHelpers = map[asm.BuiltinFunc]string{
	asm.FnRedirect:      "bpf_redirect (go through tailcall_epilogue)",
	asm.FnRedirectMap:   "bpf_redirect_map (plugins cannot own redirect maps)",
	asm.FnRedirectNeigh: "bpf_redirect_neigh",
	asm.FnRedirectPeer:  "bpf_redirect_peer",
	asm.FnXdpOutput:     "bpf_xdp_output",
}

// ExitProximityWindow is how many instructions validator will scan backwards
// from each exit to look for a tailcall_epilogue call or bpf_tail_call. Chosen
// to cover clang's typical register-restore prologue between the call and the
// exit while staying cheap enough to run on every plugin.
const ExitProximityWindow = 64

// ValidatePluginProgram enforces the plugin contract:
//
//  1. The program must be SEC("xdp").
//  2. The program either references tailcall_epilogue (leaf) or
//     bpf_tail_calls into one of ValidTailCallMaps (handoff). Programs
//     that do neither are rejected.
//  3. bpf_tail_call into any other map is rejected.
//  4. Forbidden helpers (ForbiddenHelpers) are rejected — they let a plugin
//     bypass vinbero dispatch. Kfunc calls are allowed; restrict specific
//     kfuncs by extending the denylist if a concrete abuse emerges.
//  5. Every exit instruction must be preceded, within ExitProximityWindow
//     instructions, by a tailcall_epilogue call or a vinbero PROG_ARRAY
//     tail-call. This is a structural check, not a full CFG analysis —
//     plugins built with VINBERO_PLUGIN always pass because the macro
//     produces a single exit; hand-written plugins must keep each return
//     close to an epilogue or tail-call.
func ValidatePluginProgram(spec *ebpf.ProgramSpec) error {
	if spec == nil {
		return fmt.Errorf("plugin ProgramSpec is nil")
	}
	if spec.Type != ebpf.XDP {
		return fmt.Errorf(
			"plugin program %q must be SEC(\"xdp\") (got type %s)",
			spec.Name, spec.Type,
		)
	}

	hasEpilogue := slices.Contains(spec.Instructions.FunctionReferences(), SymTailcallEpilogue)

	var (
		foreignTailCalls []string
		forbiddenHits    []string
		hasValidTailCall bool
	)
	for i, ins := range spec.Instructions {
		if ins.IsBuiltinCall() {
			if name, bad := ForbiddenHelpers[asm.BuiltinFunc(ins.Constant)]; bad {
				forbiddenHits = append(forbiddenHits, name)
			}
		}
		if !isBpfTailCall(ins) {
			continue
		}
		mapName := findTailCallMapName(spec.Instructions[:i])
		if mapName == "" {
			foreignTailCalls = append(foreignTailCalls, "(dynamic)")
			continue
		}
		if slices.Contains(ValidTailCallMaps, mapName) {
			hasValidTailCall = true
		} else {
			foreignTailCalls = append(foreignTailCalls, mapName)
		}
	}

	if len(forbiddenHits) > 0 {
		return fmt.Errorf(
			"plugin program %q calls forbidden helper(s) %v; redirect decisions "+
				"must flow through tailcall_epilogue or a vinbero PROG_ARRAY",
			spec.Name, forbiddenHits,
		)
	}

	if len(foreignTailCalls) > 0 {
		return fmt.Errorf(
			"plugin program %q calls bpf_tail_call with unauthorized map(s) %v "+
				"(plugins may only tail-call into vinbero PROG_ARRAYs: %s); "+
				"use a static `&sid_endpoint_progs` / `&headend_v4_progs` / "+
				"`&headend_v6_progs` reference, or return via tailcall_epilogue. "+
				"\"(dynamic)\" means R2 was not a compile-time map pointer",
			spec.Name, foreignTailCalls, strings.Join(ValidTailCallMaps, ", "),
		)
	}

	if !hasEpilogue && !hasValidTailCall {
		return fmt.Errorf(
			"plugin program %q neither calls %s nor tail-calls into a vinbero "+
				"PROG_ARRAY; write `return tailcall_epilogue(ctx, action);` at every exit, "+
				"or bpf_tail_call into one of (%s)",
			spec.Name, SymTailcallEpilogue, strings.Join(ValidTailCallMaps, ", "),
		)
	}

	if err := checkExitProximity(spec); err != nil {
		return err
	}

	return nil
}

// ValidatePluginCollection locates the named program in spec, forces its
// type to XDP, and enforces the plugin contract on it. Used by the server,
// the CLI, and the SDK to keep the lookup/validation flow consistent.
func ValidatePluginCollection(spec *ebpf.CollectionSpec, program string) (*ebpf.ProgramSpec, error) {
	if spec == nil {
		return nil, fmt.Errorf("plugin CollectionSpec is nil")
	}
	target, ok := spec.Programs[program]
	if !ok {
		names := make([]string, 0, len(spec.Programs))
		for n := range spec.Programs {
			names = append(names, n)
		}
		return nil, fmt.Errorf("program %q not found in ELF; available: %v", program, names)
	}
	target.Type = ebpf.XDP
	if err := ValidatePluginProgram(target); err != nil {
		return nil, err
	}
	if err := validatePluginMapTypes(spec); err != nil {
		return nil, err
	}
	if err := validatePluginAuxType(spec, program); err != nil {
		return nil, err
	}
	return target, nil
}

// validatePluginAuxType rejects plugin aux structs that would not fit in the
// plugin_raw variant of sid_aux_entry. The anchor is VINBERO_PLUGIN_AUX_TYPE,
// which emits a `<program>_aux` BTF struct; plugins without the anchor pass
// through untouched (they are limited to the plugin_aux_raw hex path).
func validatePluginAuxType(spec *ebpf.CollectionSpec, program string) error {
	if spec.Types == nil {
		return nil
	}
	var t *btf.Struct
	if err := spec.Types.TypeByName(program+"_aux", &t); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("failed to look up %s_aux BTF type: %w", program, err)
	}
	size, err := btf.Sizeof(t)
	if err != nil {
		return fmt.Errorf("cannot determine size of %s_aux: %w", program, err)
	}
	if size > SidAuxPluginRawMax {
		return fmt.Errorf(
			"plugin aux type %s_aux size %d exceeds SidAuxPluginRawMax (%d); "+
				"reduce struct size or split state across multiple SID entries",
			program, size, SidAuxPluginRawMax,
		)
	}
	return nil
}

// isBpfTailCall reports whether ins is a BPF_CALL to the tail_call helper.
func isBpfTailCall(ins asm.Instruction) bool {
	return ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall)
}

// findTailCallMapName walks backwards to find the most recent instruction
// that wrote R2 (the map argument of bpf_tail_call). Returns the map name
// when R2 was set by a static LoadMapPtr; "" otherwise.
//
// Assumes clang's canonical `LoadMapPtr R2, <map>; ...; bpf_tail_call`
// emission pattern. Inline assembly or hand-edited BPF that derives R2
// from a non-map-pointer source is reported as "(dynamic)" and rejected.
func findTailCallMapName(prev asm.Instructions) string {
	for i := len(prev) - 1; i >= 0; i-- {
		ins := prev[i]
		if ins.Dst != asm.R2 {
			continue
		}
		if ins.IsLoadFromMap() {
			return ins.Reference()
		}
		return ""
	}
	return ""
}

// checkExitProximity verifies every exit instruction in the main program
// has a tailcall_epilogue call or bpf_tail_call within the preceding
// ExitProximityWindow. Only the main program is scanned — plugin ELFs
// often carry subprogram bodies (e.g. tailcall_epilogue's own
// implementation, emitted by clang when the SDK header is included) after
// the main program, and those have their own exit that we must not
// mistake for a plugin exit.
//
// This guards against hand-written plugins that forget the epilogue on
// one branch but happen to have a call-site presence on another. Full
// CFG analysis would be stronger but adds complexity the current threat
// model does not warrant.
func checkExitProximity(spec *ebpf.ProgramSpec) error {
	ins := spec.Instructions
	for i, in := range ins {
		// Stop at the start of any subprogram past the entry point;
		// subprogram bodies are appended after the main program.
		if i > 0 && in.Symbol() != "" {
			break
		}
		if in.OpCode.JumpOp() != asm.Exit {
			continue
		}
		start := max(i-ExitProximityWindow, 0)
		covered := false
		for j := i - 1; j >= start; j-- {
			prev := ins[j]
			if isBpfTailCall(prev) {
				covered = true
				break
			}
			if prev.IsFunctionCall() && prev.Reference() == SymTailcallEpilogue {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf(
				"plugin program %q has an exit at instruction %d with no "+
					"%s call or bpf_tail_call in the previous %d instructions; "+
					"wrap the program with VINBERO_PLUGIN or ensure every "+
					"`return` goes through tailcall_epilogue",
				spec.Name, i, SymTailcallEpilogue, ExitProximityWindow,
			)
		}
	}
	return nil
}
