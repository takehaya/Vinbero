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

// checkROWrites scans the program -- the entry body and every subprogram --
// for stores whose target is a vinbero shared RO map, or whose target cannot
// be statically resolved. The check is a no-op when roMaps is empty, for
// back-compat with callers that don't yet supply the set (notably tests).
//
// Provenance is tracked per register: a store is attributed to the map its
// destination pointer was loaded from, following LoadMapPtr, register MOVs,
// map-lookup returns, and constant/register pointer arithmetic (p += off
// still points into the same map's value, so laundering a write through an
// offset does not erase the map identity). The register table is reset at
// each subprogram boundary, where the callee's registers start fresh.
//
// A resolved write to an RO map is flagged anywhere it occurs, so an
// integrity-map write hidden in a noinline helper is caught, not only one in
// the entry body. An unresolved store is flagged fail-closed in the entry
// body (it cannot be proven to miss an integrity map) but not inside a
// subprogram, where a helper legitimately stores through a map pointer passed
// as an argument (the epilogue's slot_stats_inc is exactly this) that the
// intra-procedural tracker cannot resolve. The residual this leaves -- a
// write whose map pointer is passed as a call argument and stored in the
// callee -- needs inter-procedural argument propagation and is a known limit.
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
	// One forward pass: track the most recent LoadMapPtr-sourced map name
	// per destination register. Anything else that writes a register
	// invalidates the entry. This avoids a quadratic reverse-scan per
	// store on adversarial inputs.
	const numRegs = 11 // R0..R10
	var lastMap [numRegs]string
	var violations []roViolation
	ins := spec.Instructions
	subprogs := knownSubprogNames(ins)
	mainBody := true
	for i, in := range ins {
		// At the start of a real subprogram (one something actually calls),
		// the callee's registers start fresh: reset the tracker rather than
		// carrying stale identities across the boundary, and stop treating
		// unresolved stores as fatal (a helper legitimately stores through a
		// map-pointer argument). Do not stop the scan -- a resolved
		// integrity-map write in a helper must still be caught. A bare
		// Symbol() with no caller is metadata noise or an injected fake and
		// does not begin a subprogram.
		if i > 0 {
			if sym := in.Symbol(); sym != "" {
				if _, ok := subprogs[sym]; ok {
					for r := range lastMap {
						lastMap[r] = ""
					}
					mainBody = false
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
				if dst >= 0 && dst < numRegs {
					mapName = lastMap[dst]
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
		// Update the map-pointer table for this instruction's Dst.
		// LoadMapPtr writes a known map name; any other write to a
		// register invalidates whatever was there. Stores (BPF_ST*) do
		// not modify Dst (they write *through* it), so they leave the
		// table alone — with one exception: BPF_LOAD_ACQ is encoded as
		// StXClass | AtomicMode but actually loads memory into Dst with
		// acquire semantics. Skipping the table update there would let
		// a stale map name carry past the load and either spuriously
		// detect a "store into RO" or hide a real violation behind the
		// stale tracking. Fall through to invalidate Dst for it.
		if cls := in.OpCode.Class(); cls == asm.StClass || cls == asm.StXClass {
			isLoadAcquire := cls == asm.StXClass &&
				in.OpCode.Mode() == asm.AtomicMode &&
				in.OpCode.AtomicOp() == loadAcqAtomicOp
			if !isLoadAcquire {
				continue
			}
			dst := int(in.Dst)
			if dst >= 0 && dst < numRegs {
				lastMap[dst] = ""
			}
			continue
		}
		// BPF helper / subprogram calls. The kernel ABI hands the return
		// value back in R0 and treats R1..R5 as caller-saved. For map
		// lookup helpers we additionally propagate the map identity from
		// R1 (the &map argument established by a preceding LoadMapPtr)
		// into R0 — without this every `*(u64 *)(r0 + 0) += ...` after a
		// bpf_map_lookup_elem looks "dynamic" to the analyzer and trips
		// a false-positive RO violation on plugins that legitimately
		// mutate their own RW maps.
		if in.OpCode.JumpOp() == asm.Call {
			fn := asm.BuiltinFunc(in.Constant)
			r1Map := lastMap[1]
			// A map-mutating helper writes the map named by its first
			// argument, which the ABI passes in R1. A store instruction is
			// not the only way to write a map: bpf_map_update_elem /
			// bpf_map_delete_elem on a hash map (sid_function_map,
			// sid_aux_map) forge state without ever emitting a ST/STX, so
			// they are checked here on the same footing. The map is a
			// LoadMapPtr constant tracked in lastMap[1]; an integrity map is
			// fatal, an unresolved argument in the entry body is fail-closed
			// fatal (a subprogram may receive the map as an argument).
			if isMapMutateHelper(fn) {
				if r1Map != "" {
					if _, ro := roMaps[r1Map]; ro {
						_, integrity := integrityMapNames[r1Map]
						violations = append(violations, roViolation{insIdx: i, mapName: r1Map, fatal: integrity})
					}
				} else if mainBody {
					violations = append(violations, roViolation{insIdx: i, fatal: true})
				}
			}
			for r := 1; r <= 5; r++ {
				lastMap[r] = ""
			}
			switch fn {
			case asm.FnMapLookupElem, asm.FnMapLookupPercpuElem:
				lastMap[0] = r1Map
			default:
				lastMap[0] = ""
			}
			continue
		}
		// Register-to-register MOV propagates the map identity from src
		// to dst. clang frequently emits `Rn = R0` between a lookup and
		// the subsequent store; without this propagation the dst is
		// treated as dynamic and the write is flagged spuriously.
		op := in.OpCode
		if (op.Class() == asm.ALU64Class || op.Class() == asm.ALUClass) &&
			op.ALUOp() == asm.Mov && op.Source() == asm.RegSource {
			src := int(in.Src)
			dst := int(in.Dst)
			if dst >= 0 && dst < numRegs && src >= 0 && src < numRegs {
				lastMap[dst] = lastMap[src]
				continue
			}
		}
		// Only load / ALU classes actually write Dst. Jump and Jump32
		// reference Dst as the left-hand operand of a compare; clobbering
		// lastMap[Dst] for those would erase the just-propagated lookup
		// result on the canonical clang `if (r0 == 0) goto ...; *(r0 +
		// 0) += rN` pattern emitted after every bpf_map_lookup_elem and
		// resurface the very false-positive we are trying to kill.
		cls := in.OpCode.Class()
		if cls != asm.LdClass && cls != asm.LdXClass &&
			cls != asm.ALUClass && cls != asm.ALU64Class {
			continue
		}
		dst := int(in.Dst)
		if dst < 0 || dst >= numRegs {
			continue
		}
		if in.IsLoadFromMap() {
			lastMap[dst] = in.Reference()
		} else if (cls == asm.ALUClass || cls == asm.ALU64Class) &&
			(in.OpCode.ALUOp() == asm.Add || in.OpCode.ALUOp() == asm.Sub) {
			// Pointer arithmetic keeps the map identity: `p += off` (or
			// `p -= off`) still points into the same map's value, so a store
			// through the result is a store into that map. Leaving lastMap[dst]
			// intact is what stops a plugin from erasing the identity with an
			// offset and slipping an integrity-map write into the unresolved
			// (entry-body-fatal, subprogram-ignored) bucket. It only ever adds
			// detections on the map already tracked, so a write to a
			// plugin-owned RW map stays unflagged.
		} else {
			lastMap[dst] = ""
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
