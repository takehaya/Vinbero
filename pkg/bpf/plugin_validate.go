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

// ErrPluginROWrite is the sentinel returned (wrapped via fmt.Errorf("%w"))
// by the validator when a plugin writes to a vinbero shared RO map or to
// a map pointer that cannot be statically resolved. Callers (notably the
// daemon's PluginRegister) use errors.Is to decide whether the staged
// warn-only rollout applies; CLI shift-left always rejects.
var ErrPluginROWrite = errors.New("plugin RO map write")

// SymTailcallEpilogue is the BPF subprogram every plugin must call before
// returning an XDP action so per-action stats are recorded.
const SymTailcallEpilogue = "tailcall_epilogue"

// ROEnforceMode selects how the asm-level RO-write violation is surfaced.
// The validator itself always returns the violation as an error; the mode
// is consumed by callers (typically PluginRegister) to decide whether to
// reject the request or just log a warning. CLI shift-left uses the
// returned error directly and ignores the mode.
type ROEnforceMode int

const (
	// ROEnforceWarn is the default: the violation is logged but the
	// register/load proceeds. Used during the staged rollout so existing
	// plugins keep working while ops watches the warn audit log.
	ROEnforceWarn ROEnforceMode = iota
	// ROEnforceEnforce hard-rejects the register call. CLI's `plugin
	// validate` is always effectively in this mode regardless of config.
	ROEnforceEnforce
)

// String renders the mode as the same token accepted by ParseROEnforceMode
// so logs and config dumps stay reversible.
func (m ROEnforceMode) String() string {
	switch m {
	case ROEnforceEnforce:
		return "enforce"
	default:
		return "warn"
	}
}

// ParseROEnforceMode converts a config string into a mode. Empty / "warn"
// map to warn-only; "enforce" maps to hard-reject. Anything else is a
// config error so typos don't silently downgrade the policy.
func ParseROEnforceMode(s string) (ROEnforceMode, error) {
	switch s {
	case "", "warn":
		return ROEnforceWarn, nil
	case "enforce":
		return ROEnforceEnforce, nil
	default:
		return 0, fmt.Errorf("invalid ro_enforce: %q (expected 'warn' or 'enforce')", s)
	}
}

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
//  6. Stores into vinbero shared read-only maps are rejected (the
//     RO-enforce). roMaps == nil disables the check; production callers
//     pass SharedReadOnlyMapNamesSet().
func ValidatePluginProgram(spec *ebpf.ProgramSpec, roMaps map[string]struct{}) error {
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

	if err := checkROWrites(spec, roMaps); err != nil {
		return err
	}

	return nil
}

// ValidatePluginCollection locates the named program in spec, forces its
// type to XDP, and enforces the plugin contract on it. Used by the server,
// the CLI, and the SDK to keep the lookup/validation flow consistent.
//
// roMaps == nil skips the asm-level RO-write check (back-compat for tests
// that exercise the rest of the pipeline). Production callers must pass
// SharedReadOnlyMapNamesSet().
func ValidatePluginCollection(spec *ebpf.CollectionSpec, program string, roMaps map[string]struct{}) (*ebpf.ProgramSpec, error) {
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
	if err := ValidatePluginProgram(target, roMaps); err != nil {
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
// through untouched (they are limited to the plugin_aux_raw hex path, where
// the 196-byte cap is enforced at the RPC layer instead).
func validatePluginAuxType(spec *ebpf.CollectionSpec, program string) error {
	// Plugins compiled without BTF (e.g. -g omitted) cannot be size-checked
	// here. They lose the json payload path (encodePluginAuxJSON requires the
	// aux type) but the raw path still enforces the 196-byte cap, so skipping
	// is safe.
	if spec.Types == nil {
		return nil
	}
	var t *btf.Struct
	if err := spec.Types.TypeByName(program+"_aux", &t); err != nil {
		// No anchor → plugin opted out of typed aux. Same fallback as above.
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

// findStaticMapPtrSource walks back to the most recent instruction that
// wrote dstReg and returns the map name when that origin is a static
// LoadMapPtr. Anything else (BPF_CALL return value, register copy from
// another register, stack reload) yields "" so the caller can reject
// the access conservatively.
//
// Assumes clang's canonical `LoadMapPtr Rx, &m; ...; <use Rx>` emission
// pattern. Optimised paths that move the map pointer through the stack
// or another register fall through to the conservative empty result.
func findStaticMapPtrSource(prev asm.Instructions, dstReg asm.Register) string {
	for i := len(prev) - 1; i >= 0; i-- {
		ins := prev[i]
		if ins.Dst != dstReg {
			continue
		}
		if ins.IsLoadFromMap() {
			return ins.Reference()
		}
		return "" // overwritten by something we can't trace statically
	}
	return ""
}

// findTailCallMapName resolves the map argument (R2) of a bpf_tail_call.
// Thin specialization of findStaticMapPtrSource fixed to R2; "(dynamic)"
// pointers are reported as "" and rejected upstream.
func findTailCallMapName(prev asm.Instructions) string {
	return findStaticMapPtrSource(prev, asm.R2)
}

// isMapWrite reports whether ins writes to memory through a register-based
// destination. We treat both classic stores (BPF_ST/BPF_STX, regardless of
// MemMode vs immediate) and atomic RMW operations (BPF_STX | AtomicMode,
// which covers BPF_ATOMIC and the legacy BPF_XADD) as writes; LDX (read)
// is intentionally excluded.
func isMapWrite(ins asm.Instruction) bool {
	cls := ins.OpCode.Class()
	return cls == asm.StClass || cls == asm.StXClass
}

// isStackStore reports whether the store targets the BPF stack frame
// (R10 / RFP). R10 is the read-only frame pointer; clang lowers C local
// variables (including the `struct foo key;` pattern feeding
// bpf_map_lookup_elem) to *(R10 + off) = ... stores. These are not map
// writes and must be excluded from the RO-write enforcer to avoid
// false-positives on every plugin that uses a stack-allocated key.
func isStackStore(ins asm.Instruction) bool {
	return ins.Dst == asm.RFP
}

// roViolation describes one disallowed map write detected during static
// analysis. Aggregated across the program so a single error message can
// list every offender; mapName == "" means the store target could not be
// resolved to a static map reference.
type roViolation struct {
	insIdx  int
	mapName string
}

// checkROWrites scans the main program (subprograms excluded) for stores
// whose target is a vinbero shared RO map, or whose target cannot be
// statically resolved. The check is a no-op when roMaps is empty, for
// back-compat with callers that don't yet supply the set (notably tests).
//
// Subprogram exclusion mirrors checkExitProximity. Plugin ELFs that pull
// in tailcall_epilogue end up with the epilogue body appended after the
// main program; that body legitimately writes to slot_stats_* (currently
// RW, but we don't want to lock out the epilogue if/when it migrates to
// RO), so scanning past the first sub-program would risk false positives
// on every plugin.
func checkROWrites(spec *ebpf.ProgramSpec, roMaps map[string]struct{}) error {
	if len(roMaps) == 0 {
		return nil
	}
	// One forward pass: track the most recent LoadMapPtr-sourced map name
	// per destination register. Anything else that writes a register
	// invalidates the entry. This avoids a quadratic reverse-scan per
	// store on adversarial inputs.
	const numRegs = 11 // R0..R10
	var lastMap [numRegs]string
	var violations []roViolation
	ins := spec.Instructions
	for i, in := range ins {
		// Stop at the start of any subprogram past the entry point.
		if i > 0 && in.Symbol() != "" {
			break
		}
		if isMapWrite(in) {
			// Stack stores (Dst == R10) are local-variable assignments,
			// not map writes — clang emits one for every `struct k key;`
			// that later feeds bpf_map_lookup_elem.
			if !isStackStore(in) {
				dst := int(in.Dst)
				var mapName string
				if dst >= 0 && dst < numRegs {
					mapName = lastMap[dst]
				}
				if mapName == "" {
					violations = append(violations, roViolation{insIdx: i})
				} else if _, ro := roMaps[mapName]; ro {
					violations = append(violations, roViolation{insIdx: i, mapName: mapName})
				}
			}
		}
		// Update the map-pointer table for this instruction's Dst.
		// LoadMapPtr writes a known map name; any other write to a
		// register invalidates whatever was there. Stores (BPF_ST*) do
		// not modify Dst (they write *through* it), so they leave the
		// table alone.
		if in.OpCode.Class() == asm.StClass || in.OpCode.Class() == asm.StXClass {
			continue
		}
		dst := int(in.Dst)
		if dst < 0 || dst >= numRegs {
			continue
		}
		if in.IsLoadFromMap() {
			lastMap[dst] = in.Reference()
		} else if in.Dst != 0 || in.OpCode != 0 { // any real instruction with Dst
			lastMap[dst] = ""
		}
	}
	if len(violations) == 0 {
		return nil
	}
	details := make([]string, 0, len(violations))
	for _, v := range violations {
		if v.mapName == "" {
			details = append(details, fmt.Sprintf(
				"instruction #%d: store target could not be resolved to a "+
					"known map; route writes through scratch_map / stats_map "+
					"or a plugin-owned map", v.insIdx))
		} else {
			details = append(details, fmt.Sprintf(
				"instruction #%d: store into read-only map %q",
				v.insIdx, v.mapName))
		}
	}
	return fmt.Errorf(
		"%w: plugin program %q has %d disallowed map write(s); shared RO "+
			"maps are read-only from plugins (use scratch_map / stats_map "+
			"or plugin-owned maps for state). Violations:\n  - %s",
		ErrPluginROWrite, spec.Name, len(violations), strings.Join(details, "\n  - "),
	)
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
