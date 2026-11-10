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

// ErrPluginIntegrityMapWrite is returned when a plugin writes to a map the
// dispatch and scope integrity depend on: the per-CPU tail-call context,
// the SID aux table, or the SID function table. Unlike ErrPluginROWrite it
// is NOT warn-downgradable -- a plugin that can write these maps can forge
// the action a built-in reads to gate a plugin-owned aux (defeating the
// aux discriminator) or install a SID function outside its scope, so no
// deployment may run such a plugin regardless of ro_enforce. No legitimate
// plugin ever writes them.
var ErrPluginIntegrityMapWrite = errors.New("plugin integrity map write")

// integrityMapNames are the shared RO maps whose plugin-write must be fatal
// even under ro_enforce=warn, because the dispatch/aux/scope machinery
// trusts their contents: the tail-call context carries the SID action the
// aux discriminator reads, the aux table holds behavior parameters, and the
// SID function table maps SIDs to actions. A plugin that writes any of them
// forges the scope. The PROG_ARRAYs are included so a plugin cannot swap
// the program a slot dispatches to.
var integrityMapNames = map[string]struct{}{
	"fdb_map":               {},
	"bd_peer_map":           {},
	"bd_peer_reverse_map":   {},
	"esi_peer_map":          {}, // RT4 split-horizon membership is host-only.
	"mup_uplink_v4_map":     {},
	"mup_uplink_v6_map":     {},
	"tailcall_ctx_map":      {},
	"sid_aux_map":           {},
	"sid_function_map":      {},
	MapNameSidEndpointProgs: {},
	MapNameHeadendV4Progs:   {},
	MapNameHeadendV6Progs:   {},
	MapNameHeadendL2Progs:   {},
}

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
	MapNameHeadendL2Progs,
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

	// RO-write is run by ValidatePluginCollection AFTER the always-fatal
	// validators, not from inside this function, so warn-mode callers
	// (PluginRegister with ro_enforce=warn) can downgrade just that one
	// error without skipping the rest of the validator. Keeping the
	// parameter here for callers that still want the bundled behaviour
	// (notably tests under pkg/bpf that exercise the asm-level enforcer
	// without going through ValidatePluginCollection).
	if roMaps != nil {
		if err := checkROWrites(spec, roMaps); err != nil {
			return err
		}
	}

	return nil
}

// ValidatePluginCollection locates the named program in spec, forces its
// type to XDP, and enforces the plugin contract on it. Used by the server,
// the CLI, and the SDK to keep the lookup/validation flow consistent.
//
// Check order is intentional:
//  1. validatePluginMapTypes — BTF map types match shared-map declarations
//  2. validatePluginAuxType  — <program>_aux fits SidAuxPluginRawMax
//  3. ValidatePluginProgram  — XDP class, epilogue/tail-call, forbidden
//     helpers, exit proximity (called with roMaps==nil so RO-write runs
//     separately below)
//  4. checkROWrites          — only step that may be warn-downgraded
//
// Steps 1-3 always fatal. Step 4 returns ErrPluginROWrite, which a caller
// running under ro_enforce=warn may choose to log instead of reject; the
// returned ProgramSpec is non-nil in that case so the caller can proceed
// with the same target the strict path would have produced.
//
// roMaps == nil skips step 4 entirely (used by tests / callers that have
// no shared-map context). Production callers pass SharedReadOnlyMapNamesSet().
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

	// Run mandatory (always-fatal) checks first so the warn-eligible
	// RO-write check below runs LAST. Otherwise a caller that swallows
	// ErrPluginROWrite in warn mode would also be implicitly swallowing
	// any map-type or aux-size violation that came in alongside it,
	// because the early return from ValidatePluginProgram would short-
	// circuit the rest of the pipeline.
	if err := validatePluginMapTypes(spec); err != nil {
		return nil, err
	}
	if err := validatePluginAuxType(spec, program); err != nil {
		return nil, err
	}
	if err := ValidatePluginProgram(target, nil); err != nil {
		return nil, err
	}

	// RO-write is intentionally split out: it is the only validator
	// failure mode that may be downgraded to a warn-only log under
	// settings.validate.ro_enforce=warn. Returning the target spec
	// alongside the error lets warn-mode callers proceed with the same
	// program ref the strict path would have produced.
	if roMaps != nil {
		if err := checkROWrites(target, roMaps); err != nil {
			return target, err
		}
	}
	return target, nil
}

// validatePluginAuxType rejects plugin aux structs that would not fit in the
// plugin_raw variant of sid_aux_entry. The anchor is VINBERO_PLUGIN_AUX_TYPE,
// which emits a `<program>_aux` BTF struct; plugins without the anchor pass
// through untouched (they are limited to the plugin_aux_raw hex path, where
// the 256-byte cap is enforced at the RPC layer instead).
func validatePluginAuxType(spec *ebpf.CollectionSpec, program string) error {
	// Plugins compiled without BTF (e.g. -g omitted) cannot be size-checked
	// here. They lose the json payload path (encodePluginAuxJSON requires the
	// aux type) but the raw path still enforces the 256-byte cap, so skipping
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

// loadAcqAtomicOp is the AtomicOp value encoded by BPF_LOAD_ACQ. cilium's
// loadAcquire constant is package-private, so we reconstruct it once from
// the LoadAcquire constructor and compare in the hot path.
var loadAcqAtomicOp = asm.LoadAcquire(asm.R0, asm.R0, asm.DWord, 0).OpCode.AtomicOp()

// isMapWrite reports whether ins writes to memory through a register-based
// destination. Classic stores (BPF_ST/BPF_STX MemMode) and atomic RMW ops
// (BPF_STX | AtomicMode — Add/And/Or/Xor, the Fetch* variants, Xchg,
// CmpXchg, StoreRelease) are writes; BPF_LOAD_ACQ also encodes as
// StXClass | AtomicMode but is a load with acquire semantics, so it must
// not be flagged. Plain BPF_LDX (read) is excluded by class.
func isMapWrite(ins asm.Instruction) bool {
	cls := ins.OpCode.Class()
	switch cls {
	case asm.StClass:
		return true
	case asm.StXClass:
		if ins.OpCode.Mode() == asm.AtomicMode &&
			ins.OpCode.AtomicOp() == loadAcqAtomicOp {
			return false
		}
		return true
	}
	return false
}

// isMapMutateHelper reports whether a BPF helper writes the map passed as its
// first argument. These forge map state without a store instruction, so the
// RO-write scan checks them the same way it checks ST/STX. Read helpers
// (bpf_map_lookup_elem, bpf_map_peek_elem) are excluded: a plugin may read a
// shared RO map, only not write it.
func isMapMutateHelper(fn asm.BuiltinFunc) bool {
	switch fn {
	case asm.FnMapUpdateElem, asm.FnMapDeleteElem, asm.FnMapPushElem, asm.FnMapPopElem:
		return true
	}
	return false
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

// knownSubprogNames returns the set of subprogram names actually invoked
// from somewhere in ins via a BPF2BPF call. Cilium's ELF loader places
// per-symbol metadata on instructions wherever an ELF STT_FUNC sits,
// including symbols a malicious author injects mid-main. Trusting
// in.Symbol() == "" as the only "still in main" signal lets such a forged
// symbol terminate the scan early while the kernel verifier — which
// resolves subprogram boundaries from BPF2BPF call instructions, not
// symbol metadata — happily executes the writes that follow. Restricting
// the break trigger to names that something actually calls keeps the
// kernel and validator on the same view of what counts as a subprogram.
func knownSubprogNames(ins asm.Instructions) map[string]struct{} {
	names := ins.FunctionReferences()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// roViolation describes one disallowed map write detected during static
// analysis. Aggregated across the program so a single error message can
// list every offender; mapName == "" means the store target could not be
// resolved to a static map reference.
type roViolation struct {
	insIdx  int
	mapName string
	// fatal marks a violation that must never be warn-downgraded: an
	// integrity-map write, or a main-body store whose target could not be
	// resolved (fail-closed, since a lost provenance cannot be proven to
	// miss an integrity map).
	fatal bool
}

const roRegisterCount = 11 // R0..R10

type roRegisterIdentity struct {
	mapName string
	seeded  bool
}

type roStepResult struct {
	mutatesMap bool
	mapName    string
}

// stepRORegisters applies one instruction's register transfer rules.
func stepRORegisters(in asm.Instruction, regs *[roRegisterCount]roRegisterIdentity) roStepResult {
	if cls := in.OpCode.Class(); cls == asm.StClass || cls == asm.StXClass {
		isLoadAcquire := cls == asm.StXClass && in.OpCode.Mode() == asm.AtomicMode &&
			in.OpCode.AtomicOp() == loadAcqAtomicOp
		if isLoadAcquire {
			dst := int(in.Dst)
			if dst >= 0 && dst < len(regs) {
				regs[dst] = roRegisterIdentity{}
			}
		}
		return roStepResult{}
	}

	if in.OpCode.JumpOp() == asm.Call {
		r1 := regs[1]
		result := roStepResult{mapName: r1.mapName}
		if in.IsBuiltinCall() {
			fn := asm.BuiltinFunc(in.Constant)
			result.mutatesMap = isMapMutateHelper(fn)
			if fn == asm.FnMapLookupElem || fn == asm.FnMapLookupPercpuElem {
				regs[0] = r1
			} else {
				regs[0] = roRegisterIdentity{}
			}
		} else {
			regs[0] = roRegisterIdentity{}
		}
		for r := 1; r <= 5; r++ {
			regs[r] = roRegisterIdentity{}
		}
		return result
	}

	op := in.OpCode
	if (op.Class() == asm.ALU64Class || op.Class() == asm.ALUClass) &&
		op.ALUOp() == asm.Mov && op.Source() == asm.RegSource {
		src := int(in.Src)
		dst := int(in.Dst)
		if dst >= 0 && dst < len(regs) && src >= 0 && src < len(regs) {
			regs[dst] = regs[src]
			return roStepResult{}
		}
	}

	cls := in.OpCode.Class()
	if cls != asm.LdClass && cls != asm.LdXClass &&
		cls != asm.ALUClass && cls != asm.ALU64Class {
		return roStepResult{}
	}
	dst := int(in.Dst)
	if dst < 0 || dst >= len(regs) {
		return roStepResult{}
	}
	if in.IsLoadFromMap() {
		regs[dst] = roRegisterIdentity{mapName: in.Reference()}
	} else if (cls != asm.ALUClass && cls != asm.ALU64Class) ||
		(in.OpCode.ALUOp() != asm.Add && in.OpCode.ALUOp() != asm.Sub) {
		regs[dst] = roRegisterIdentity{}
	}
	return roStepResult{}
}

// jumpTargetOffsets returns branch targets in raw BPF instruction units.
func jumpTargetOffsets(ins asm.Instructions) map[asm.RawInstructionOffset]struct{} {
	symbols := make(map[string]asm.RawInstructionOffset)
	iter := ins.Iterate()
	for iter.Next() {
		if sym := iter.Ins.Symbol(); sym != "" {
			symbols[sym] = iter.Offset
		}
	}

	targets := make(map[asm.RawInstructionOffset]struct{})
	iter = ins.Iterate()
	for iter.Next() {
		in := iter.Ins
		cls := in.OpCode.Class()
		op := in.OpCode.JumpOp()
		if !cls.IsJump() || op == asm.Call || op == asm.Exit {
			continue
		}
		if target, ok := symbols[in.Reference()]; ok && in.Reference() != "" {
			targets[target] = struct{}{}
			continue
		}
		delta := int64(in.Offset)
		if cls == asm.Jump32Class && op == asm.Ja {
			delta = in.Constant
		}
		width := asm.RawInstructionOffset(in.Size() / asm.InstructionSize)
		target := int64(iter.Offset) + int64(width) + delta
		if target >= 0 {
			targets[asm.RawInstructionOffset(target)] = struct{}{}
		}
	}
	return targets
}

type subprogRegisterEntry struct {
	writableMap string
	readOnlyMap string
}

func (e subprogRegisterEntry) identity() roRegisterIdentity {
	name := e.writableMap
	if e.readOnlyMap != "" {
		name = e.readOnlyMap
	}
	return roRegisterIdentity{mapName: name, seeded: name != ""}
}

// subprogMapEntries propagates direct call-site identities for at most the
// kernel's eight call frames. Entry facts only grow and an RO identity wins
// permanently, so stopping early can miss a detection but cannot add one.
func subprogMapEntries(
	ins asm.Instructions,
	subprogs map[string]struct{},
	roMaps map[string]struct{},
) map[string][roRegisterCount]roRegisterIdentity {
	const maxCallFrames = 8
	targets := jumpTargetOffsets(ins)
	facts := make(map[string][roRegisterCount]subprogRegisterEntry)

	for range maxCallFrames {
		var regs [roRegisterCount]roRegisterIdentity
		callSites := make(map[string][][roRegisterCount]roRegisterIdentity)
		iter := ins.Iterate()
		for iter.Next() {
			in := *iter.Ins
			if iter.Index > 0 {
				if _, ok := subprogs[in.Symbol()]; ok {
					regs = [roRegisterCount]roRegisterIdentity{}
					for r, entry := range facts[in.Symbol()] {
						regs[r] = entry.identity()
					}
				}
			}
			if _, ok := targets[iter.Offset]; ok {
				regs = [roRegisterCount]roRegisterIdentity{}
			}
			if in.IsLoadOfFunctionPointer() {
				callSites[in.Reference()] = append(callSites[in.Reference()], [roRegisterCount]roRegisterIdentity{})
			}
			if in.IsFunctionCall() {
				callSites[in.Reference()] = append(callSites[in.Reference()], regs)
			}
			stepRORegisters(in, &regs)
		}

		added := false
		for name, sites := range callSites {
			entry := facts[name]
			for r := 1; r <= 5; r++ {
				if entry[r].readOnlyMap == "" {
					for _, site := range sites {
						if _, ro := roMaps[site[r].mapName]; ro {
							entry[r].readOnlyMap = site[r].mapName
							added = true
							break
						}
					}
				}
				if entry[r].writableMap == "" {
					agreed := sites[0][r].mapName
					for _, site := range sites[1:] {
						if site[r].mapName != agreed {
							agreed = ""
							break
						}
					}
					if agreed != "" {
						entry[r].writableMap = agreed
						added = true
					}
				}
			}
			facts[name] = entry
		}
		if !added {
			break
		}
	}

	entries := make(map[string][roRegisterCount]roRegisterIdentity, len(facts))
	for name, fact := range facts {
		var regs [roRegisterCount]roRegisterIdentity
		for r, entry := range fact {
			regs[r] = entry.identity()
		}
		entries[name] = regs
	}
	return entries
}

// checkROWrites scans the program -- the entry body and every subprogram --
// for stores whose target is a vinbero shared RO map, or whose target cannot
// be statically resolved. The check is a no-op when roMaps is empty, for
// back-compat with callers that don't yet supply the set (notably tests).
//
// Provenance is tracked per register: a store is attributed to the map its
// destination pointer was loaded from, following LoadMapPtr, register MOVs,
// map-lookup returns, and constant/register pointer arithmetic (p += off
// still points into the same map's value, so laundering a write through an
// offset does not erase the map identity). At each subprogram boundary,
// R1..R5 start with direct call-site map names; an RO map wins disagreements.
// Seed-derived identities stop at branch targets, and nested calls propagate
// for at most the kernel's eight call frames.
//
// A resolved write to an RO map is flagged anywhere it occurs, so an
// integrity-map write hidden in a noinline helper is caught, not only one in
// the entry body. An unresolved store is flagged fail-closed in the entry
// body (it cannot be proven to miss an integrity map) but not inside a
// subprogram when its argument remains unresolved. The only added rejection
// is an RO shared-map write through a directly passed, resolved pointer;
// everything else accepted by this check remains accepted.
//
// Historically this scanned only the entry body: the epilogue body appended
// after it stores to slot_stats_* through a map pointer passed as an argument,
// which the tracker cannot resolve and would have flagged. That false positive
// is now avoided by not flagging unresolved stores inside a subprogram, rather
// than by stopping at the first one -- so a resolved integrity-map write in a
// helper is no longer invisible.
func checkROWrites(spec *ebpf.ProgramSpec, roMaps map[string]struct{}) error {
	if len(roMaps) == 0 {
		return nil
	}
	var regs [roRegisterCount]roRegisterIdentity
	var violations []roViolation
	ins := spec.Instructions
	subprogs := knownSubprogNames(ins)
	targets := jumpTargetOffsets(ins)
	entries := subprogMapEntries(ins, subprogs, roMaps)
	mainBody := true
	iter := ins.Iterate()
	for iter.Next() {
		i := iter.Index
		in := *iter.Ins
		// At the start of a real subprogram (one something references), seed
		// the tracker from its direct call sites, or leave it empty for a
		// callback-only body. Stop treating unresolved stores as fatal (a
		// helper legitimately stores through a map-pointer argument). Do not
		// stop the scan -- a resolved
		// integrity-map write in a helper must still be caught. A bare
		// Symbol() with no caller is metadata noise or an injected fake and
		// does not begin a subprogram.
		if i > 0 {
			if sym := in.Symbol(); sym != "" {
				if _, ok := subprogs[sym]; ok {
					regs = entries[sym]
					mainBody = false
				}
			}
		}
		// Preserve main's branch-insensitive behavior, but never carry a
		// caller seed across a join inside a subprogram. Identities established
		// by the subprogram itself keep the existing behavior.
		if !mainBody {
			if _, ok := targets[iter.Offset]; ok {
				for r := range regs {
					if regs[r].seeded {
						regs[r] = roRegisterIdentity{}
					}
				}
			}
		}
		if isMapWrite(in) {
			// Stack stores (Dst == R10) are local-variable assignments,
			// not map writes — clang emits one for every `struct k key;`
			// that later feeds bpf_map_lookup_elem.
			if !isStackStore(in) {
				dst := int(in.Dst)
				var mapName string
				if dst >= 0 && dst < len(regs) {
					mapName = regs[dst].mapName
				}
				if mapName == "" {
					// Unresolved. In the entry body this is fail-closed
					// fatal: a laundered pointer cannot be proven to miss an
					// integrity map. In a subprogram it is not flagged, since
					// a helper storing through a map-pointer argument is the
					// legitimate shape the tracker cannot resolve.
					if mainBody {
						violations = append(violations, roViolation{insIdx: i, fatal: true})
					}
				} else if _, ro := roMaps[mapName]; ro {
					_, integrity := integrityMapNames[mapName]
					violations = append(violations, roViolation{insIdx: i, mapName: mapName, fatal: integrity})
				}
			}
		}
		step := stepRORegisters(in, &regs)
		if step.mutatesMap {
			if step.mapName != "" {
				if _, ro := roMaps[step.mapName]; ro {
					_, integrity := integrityMapNames[step.mapName]
					violations = append(violations, roViolation{
						insIdx: i, mapName: step.mapName, fatal: integrity,
					})
				}
			} else if mainBody {
				violations = append(violations, roViolation{insIdx: i, fatal: true})
			}
		}
	}
	if len(violations) == 0 {
		return nil
	}
	details := make([]string, 0, len(violations))
	integrity := false
	for _, v := range violations {
		if v.fatal {
			integrity = true
		}
		if v.mapName == "" {
			details = append(details, fmt.Sprintf(
				"instruction #%d: store target could not be resolved to a "+
					"known map; a plugin-owned RW map write resolves to its "+
					"map, so an unresolved store in the entry body is refused "+
					"fail-closed rather than assumed safe", v.insIdx))
		} else {
			details = append(details, fmt.Sprintf(
				"instruction #%d: store into read-only map %q",
				v.insIdx, v.mapName))
		}
	}
	// A write to a dispatch/aux/scope integrity map is fatal even under
	// ro_enforce=warn: it lets the plugin forge the very state the scope and
	// the aux discriminator trust. The warn downgrade is for the migration
	// maps, not these.
	if integrity {
		// An integrity-map write IS a read-only-map write, so the error
		// satisfies errors.Is(ErrPluginROWrite) too; the extra
		// ErrPluginIntegrityMapWrite is what the warn-mode caller checks to
		// refuse the downgrade. It also covers an entry-body store whose
		// target could not be resolved: that cannot be proven to miss an
		// integrity map, so it is refused fail-closed rather than downgraded.
		return fmt.Errorf(
			"%w: %w: plugin program %q has %d disallowed map write(s); at least one targets a "+
				"dispatch/aux integrity map or an unresolved entry-body address, which no plugin may "+
				"write under any ro_enforce setting. Violations:\n  - %s",
			ErrPluginIntegrityMapWrite, ErrPluginROWrite, spec.Name, len(violations), strings.Join(details, "\n  - "),
		)
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
	subprogs := knownSubprogNames(ins)
	for i, in := range ins {
		// See knownSubprogNames: only Symbol()s that match a called
		// subprogram terminate the scan. A forged symbol mid-main must
		// not let an exit-without-epilogue slip through.
		if i > 0 {
			if sym := in.Symbol(); sym != "" {
				if _, ok := subprogs[sym]; ok {
					break
				}
			}
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
