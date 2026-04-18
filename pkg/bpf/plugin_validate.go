package bpf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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

// ValidatePluginProgram enforces the plugin contract:
//
//  1. The program must be SEC("xdp").
//  2. The program either references tailcall_epilogue (leaf) or
//     bpf_tail_calls into one of ValidTailCallMaps (handoff). Programs
//     that do neither are rejected.
//  3. bpf_tail_call into any other map is rejected.
//
// The leaf/handoff check is call-site presence only — it does not prove
// every exit path satisfies the contract. But the tail-call whitelist is
// enforced hard, so a plugin cannot escape the validation boundary by
// routing packets through an unrelated PROG_ARRAY.
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

	var foreignTailCalls []string
	hasValidTailCall := false
	for i, ins := range spec.Instructions {
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
	return target, nil
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
