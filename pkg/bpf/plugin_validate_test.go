package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// buildBTFSpec round-trips a list of types through Builder.Marshal +
// LoadSpecFromReader so the resulting *btf.Spec actually answers TypeByName
// queries. btf.Spec has unexported fields and no public constructor, so this
// is the supported way to synthesize one from Go-side struct literals.
func buildBTFSpec(t *testing.T, types []btf.Type) *btf.Spec {
	t.Helper()
	b, err := btf.NewBuilder(types)
	if err != nil {
		t.Fatalf("btf.NewBuilder: %v", err)
	}
	raw, err := b.Marshal(nil, &btf.MarshalOptions{Order: binary.NativeEndian})
	if err != nil {
		t.Fatalf("btf Marshal: %v", err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("btf.LoadSpecFromReader: %v", err)
	}
	return spec
}

func buildSpec(name string, progType ebpf.ProgramType, ins asm.Instructions) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:         name,
		Type:         progType,
		Instructions: ins,
	}
}

// callToSymbol emits a BPF_CALL referencing the given subprogram symbol.
func callToSymbol(sym string) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
		Src:      asm.PseudoCall,
		Constant: -1,
	}.WithReference(sym)
}

// tailCallTo emits the three-instruction prologue + bpf_tail_call sequence
// for a static PROG_ARRAY map reference.
func tailCallTo(mapName string, index int64) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R1),
		asm.LoadMapPtr(asm.R2, 0).WithReference(mapName),
		asm.Mov.Imm(asm.R3, int32(index)),
		asm.FnTailCall.Call(),
	}
}

func TestValidatePluginProgram_Valid(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil); err != nil {
		t.Fatalf("expected valid spec to pass, got: %v", err)
	}
}

func TestValidatePluginProgram_MissingEpilogueAndTailCall(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
	}
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil)
	if err == nil {
		t.Fatal("expected error when neither epilogue nor tail call present")
	}
	if !strings.Contains(err.Error(), SymTailcallEpilogue) {
		t.Errorf("error message should mention tailcall_epilogue, got: %v", err)
	}
}

func TestValidatePluginProgram_WrongProgType(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	err := ValidatePluginProgram(buildSpec("tc", ebpf.SchedCLS, ins), nil)
	if err == nil || !strings.Contains(err.Error(), "xdp") {
		t.Fatalf("expected 'xdp' in error, got: %v", err)
	}
}

func TestValidatePluginProgram_NilSpec(t *testing.T) {
	if err := ValidatePluginProgram(nil, nil); err == nil {
		t.Fatal("expected error for nil spec")
	}
}

func TestValidatePluginProgram_CallsOtherSymbol(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		callToSymbol("some_helper"),
		asm.Return(),
	}
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil); err == nil {
		t.Fatal("expected error when tailcall_epilogue absent even with other calls")
	}
}

// Plugin dispatches back into a vinbero PROG_ARRAY instead of returning.
func TestValidatePluginProgram_ValidTailCallOnly(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("sid_endpoint_progs", 33)...)
	ins = append(ins, asm.Mov.Imm(asm.R0, 2), asm.Return())
	if err := ValidatePluginProgram(buildSpec("dispatch", ebpf.XDP, ins), nil); err != nil {
		t.Fatalf("expected tail-call-only plugin to pass, got: %v", err)
	}
}

func TestValidatePluginProgram_ValidTailCallHeadendV4(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("headend_v4_progs", 20)...)
	ins = append(ins, asm.Mov.Imm(asm.R0, 2), asm.Return())
	if err := ValidatePluginProgram(buildSpec("dispatch", ebpf.XDP, ins), nil); err != nil {
		t.Fatalf("expected tail-call into headend_v4_progs to pass, got: %v", err)
	}
}

// Plugin uses both routes: leaf on one path, dispatch on another.
func TestValidatePluginProgram_BothEpilogueAndTailCall(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("sid_endpoint_progs", 40)...)
	ins = append(ins, callToSymbol(SymTailcallEpilogue), asm.Return())
	if err := ValidatePluginProgram(buildSpec("mixed", ebpf.XDP, ins), nil); err != nil {
		t.Fatalf("expected leaf+dispatch plugin to pass, got: %v", err)
	}
}

// Plugin tries to tail-call into a map that is not a vinbero PROG_ARRAY.
func TestValidatePluginProgram_ForeignTailCall(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("my_private_progs", 0)...)
	ins = append(ins, callToSymbol(SymTailcallEpilogue), asm.Return())
	err := ValidatePluginProgram(buildSpec("escape", ebpf.XDP, ins), nil)
	if err == nil {
		t.Fatal("expected error for tail-call into unauthorized map")
	}
	if !strings.Contains(err.Error(), "my_private_progs") {
		t.Errorf("error should name the foreign map, got: %v", err)
	}
}

// bpf_tail_call whose R2 is set dynamically cannot be proven safe — reject.
func TestValidatePluginProgram_DynamicTailCall(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 0),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	err := ValidatePluginProgram(buildSpec("dyn", ebpf.XDP, ins), nil)
	if err == nil {
		t.Fatal("expected error for dynamic (non-static-map) tail call")
	}
	if !strings.Contains(err.Error(), "dynamic") {
		t.Errorf("error should flag dynamic tail call, got: %v", err)
	}
}

// Plugin calls bpf_redirect_map directly — must be rejected so all redirect
// paths stay under vinbero's control.
func TestValidatePluginProgram_ForbiddenHelper_RedirectMap(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.FnRedirectMap.Call(),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil)
	if err == nil {
		t.Fatal("expected error for bpf_redirect_map call")
	}
	if !strings.Contains(err.Error(), "bpf_redirect_map") {
		t.Errorf("error should name the forbidden helper, got: %v", err)
	}
}

// Kfuncs are allowed so plugins can access BPF-exposed kernel APIs.
// Specific kfuncs can be blocked later by extending ForbiddenHelpers-style
// lists if a concrete abuse emerges.
func TestValidatePluginProgram_KfuncCall_Allowed(t *testing.T) {
	kfunc := asm.Instruction{
		OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
		Src:      asm.PseudoKfuncCall,
		Constant: -1,
	}.WithReference("some_kfunc")
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		kfunc,
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil); err != nil {
		t.Fatalf("expected kfunc call to pass validation, got: %v", err)
	}
}

// An exit far from any epilogue call must be caught by the proximity check,
// even though the call-site presence test alone would pass.
func TestValidatePluginProgram_ExitWithoutEpilogueNearby(t *testing.T) {
	ins := asm.Instructions{
		// early exit with no epilogue nearby
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
	// pad with > ExitProximityWindow no-ops, then a covered exit.
	for range ExitProximityWindow + 4 {
		ins = append(ins, asm.Mov.Imm(asm.R1, 0))
	}
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 2),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	)
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins), nil)
	if err == nil {
		t.Fatal("expected error for exit with no epilogue in proximity")
	}
	if !strings.Contains(err.Error(), "exit") {
		t.Errorf("error should mention the exit, got: %v", err)
	}
}

// BTF: plugin declares sid_function_map with a value struct whose name does
// not match the core expectation. Must be caught at collection validation.
func TestValidatePluginCollection_BTF_MapValueTypeMismatch(t *testing.T) {
	prog := buildSpec("xdp_entry", ebpf.XDP, asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	})
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"xdp_entry": prog},
		Maps: map[string]*ebpf.MapSpec{
			"sid_function_map": {
				Name:       "sid_function_map",
				Type:       ebpf.LPMTrie,
				KeySize:    20,
				ValueSize:  12,
				MaxEntries: 1024,
				Value:      &btf.Struct{Name: "wrong_name"},
			},
		},
	}
	if _, err := ValidatePluginCollection(spec, "xdp_entry", nil); err == nil {
		t.Fatal("expected BTF type mismatch to be rejected")
	} else if !strings.Contains(err.Error(), "sid_function_entry") {
		t.Errorf("error should name the expected type, got: %v", err)
	}
}

// validatePluginAuxType short-circuits when spec.Types is nil. Covers the
// stripped-BTF fallback path so a plugin without BTF can still register.
func TestValidatePluginAuxType_NilTypes(t *testing.T) {
	spec := &ebpf.CollectionSpec{}
	if err := validatePluginAuxType(spec, "my_program"); err != nil {
		t.Errorf("nil spec.Types should pass, got: %v", err)
	}
}

// auxStruct fabricates a `<program>_aux` struct of the requested size with a
// single byte-array member so btf.Sizeof yields exactly size. Both Array
// fields (Index and Type) must be non-nil — BTF traversal panics otherwise.
func auxStruct(name string, size uint32) *btf.Struct {
	idxInt := &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}
	byteInt := &btf.Int{Name: "u8", Size: 1, Encoding: btf.Unsigned}
	arr := &btf.Array{
		Index:  idxInt,
		Type:   byteInt,
		Nelems: size,
	}
	return &btf.Struct{
		Name:    name,
		Size:    size,
		Members: []btf.Member{{Name: "buf", Type: arr}},
	}
}

// validatePluginAuxType must reject aux structs larger than the plugin_raw
// variant — otherwise we would silently truncate state at runtime.
func TestValidatePluginAuxType_Oversize(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"foo": {Name: "foo", Type: ebpf.XDP},
		},
		Types: buildBTFSpec(t, []btf.Type{auxStruct("foo_aux", 200)}),
	}
	err := validatePluginAuxType(spec, "foo")
	if err == nil {
		t.Fatal("expected oversize aux type to be rejected")
	}
	if !strings.Contains(err.Error(), "196") {
		t.Errorf("error should mention SidAuxPluginRawMax (196), got: %v", err)
	}
}

// Boundary case: a struct exactly equal to SidAuxPluginRawMax must pass.
// Guards against off-by-one regressions in the size check.
func TestValidatePluginAuxType_Boundary(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"foo": {Name: "foo", Type: ebpf.XDP},
		},
		Types: buildBTFSpec(t, []btf.Type{auxStruct("foo_aux", SidAuxPluginRawMax)}),
	}
	if err := validatePluginAuxType(spec, "foo"); err != nil {
		t.Errorf("size == SidAuxPluginRawMax must pass, got: %v", err)
	}
}

// Plugin built without the VINBERO_PLUGIN_AUX_TYPE anchor exposes no
// `<program>_aux` BTF struct. validatePluginAuxType must treat that as
// "raw bytes only" (no error) — not as a hard failure.
func TestValidatePluginAuxType_AnchorMissing(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"foo": {Name: "foo", Type: ebpf.XDP},
		},
		Types: buildBTFSpec(t, []btf.Type{auxStruct("unrelated_struct", 8)}),
	}
	if err := validatePluginAuxType(spec, "foo"); err != nil {
		t.Errorf("missing foo_aux must pass (raw-bytes path), got: %v", err)
	}
}

// roSet is the canonical Phase 2 RO set used across the asm-level write
// tests. Keeping the helper close to the tests makes intent obvious — a
// real-world miswire would be a no-op for the dispatch tests above
// (which pass nil) but invalidate the tests below (which need a non-nil
// set to exercise checkROWrites).
func roSet() map[string]struct{} {
	return SharedReadOnlyMapNamesSet()
}

// roSpec wraps a sequence of instructions in the minimal "valid plugin"
// shell (epilogue call + return) so individual write tests don't have to
// duplicate boilerplate. The caller provides the lead-in instructions
// that exercise the RO-write detection.
func roSpec(name string, lead asm.Instructions) *ebpf.ProgramSpec {
	ins := append(asm.Instructions{}, lead...)
	ins = append(ins, callToSymbol(SymTailcallEpilogue), asm.Return())
	return buildSpec(name, ebpf.XDP, ins)
}

// Direct store into a vinbero-managed read-only map must reject. Mirrors
// the canonical clang sequence `LoadMapPtr Rx, &m; *(Rx + off) = imm`.
func TestValidatePluginROWrites_DirectROWrite(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.StoreImm(asm.R1, 0, 99, asm.Word),
	}
	err := ValidatePluginProgram(roSpec("evil", lead), roSet())
	if err == nil {
		t.Fatal("expected RO write to be rejected")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sid_function_map") {
		t.Errorf("error should name the RO map, got: %v", err)
	}
}

// Atomic RMW (BPF_ATOMIC family, e.g. __sync_fetch_and_add) into an RO
// map must also reject — atomic encodes as StXClass with AtomicMode and
// is a write as far as the kernel verifier is concerned.
func TestValidatePluginROWrites_DirectROAtomic(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.Mov.Imm(asm.R2, 1),
		asm.FetchAdd.Mem(asm.R1, asm.R2, asm.DWord, 0),
	}
	err := ValidatePluginProgram(roSpec("evil_atomic", lead), roSet())
	if err == nil {
		t.Fatal("expected atomic RO write to be rejected")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
}

// Writes targeting an RW map (scratch_map / stats_map) are the supported
// way for plugins to keep mutable state and must pass.
func TestValidatePluginROWrites_RWAllowed(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("scratch_map"),
		asm.StoreImm(asm.R1, 0, 7, asm.Word),
	}
	if err := ValidatePluginProgram(roSpec("ok", lead), roSet()); err != nil {
		t.Fatalf("write into scratch_map (RW) should pass, got: %v", err)
	}
}

// A store whose destination register cannot be traced back to a static
// LoadMapPtr must reject conservatively — typical case is writing
// through a map_lookup_elem return value (R0 after a BPF_CALL).
func TestValidatePluginROWrites_DynamicReject(t *testing.T) {
	// Sequence simulates: `R1 = bpf_map_lookup_elem(...); *(R1 + 0) = 1;`
	// The R1 source is the helper return (R0 → R1 mov), not a LoadMapPtr,
	// so findStaticMapPtrSource returns "" and the violation falls into
	// the "could not be resolved" branch.
	lead := asm.Instructions{
		asm.FnMapLookupElem.Call(),  // R0 = lookup result
		asm.Mov.Reg(asm.R1, asm.R0), // hide the origin
		asm.StoreImm(asm.R1, 0, 1, asm.Word),
	}
	err := ValidatePluginProgram(roSpec("dyn", lead), roSet())
	if err == nil {
		t.Fatal("expected dynamic store target to be rejected")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be resolved") {
		t.Errorf("error should describe the unresolved store, got: %v", err)
	}
}

// `bpf_map_lookup_elem(&owned_rw, &key); lock *(u64 *)(r0 + 0) += rN`
// is what clang emits for `__sync_fetch_and_add(counter, step)` against
// a plugin-owned PERCPU_ARRAY. R0 is the helper return, so without the
// lookup-aware propagation the analyzer sees a "dynamic" store target
// and falsely flags every plugin-owned counter update. The fix tracks
// LoadMapPtr → R1 → call FnMapLookupElem → R0 so the write resolves to
// the plugin-owned map name and clears the RO contract.
func TestValidatePluginROWrites_LookupOwnedRW_Allowed(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("plugin_counter_map"),
		asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R7, 1),
		asm.FetchAdd.Mem(asm.R0, asm.R7, asm.DWord, 0),
	}
	if err := ValidatePluginProgram(roSpec("owned_atomic", lead), roSet()); err != nil {
		t.Fatalf("atomic into looked-up plugin-owned RW map should pass, got: %v", err)
	}
}

// BPF_LOAD_ACQ encodes as StXClass | AtomicMode but is a read with
// acquire semantics. The validator must not classify it as a write —
// otherwise every plugin doing a load-acquire from a shared RO map
// (e.g. atomically reading a config field that another updater
// store-releases) gets rejected. clang 17+ emits this for
// __atomic_load_n with __ATOMIC_ACQUIRE.
func TestValidatePluginROWrites_LoadAcquireFromRO_Allowed(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.LoadAcquire(asm.R2, asm.R1, asm.DWord, 0),
	}
	if err := ValidatePluginProgram(roSpec("ldacq", lead), roSet()); err != nil {
		t.Fatalf("load-acquire on RO map is a read, must pass: %v", err)
	}
}

// Symmetric to the above: BPF_STORE_REL *is* a write (release-store
// semantics), so storing into an RO map via store-release must still
// reject. This catches the easy mistake of widening the load-acquire
// exception to all atomic ops.
func TestValidatePluginROWrites_StoreReleaseToRO_Rejected(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.Mov.Imm(asm.R2, 99),
		asm.StoreRelease(asm.R1, asm.R2, asm.DWord, 0),
	}
	err := ValidatePluginProgram(roSpec("strel", lead), roSet())
	if err == nil {
		t.Fatal("store-release into RO map must reject")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sid_function_map") {
		t.Errorf("error should name the RO map, got: %v", err)
	}
}

// Same lookup-then-write pattern but with the clang-canonical NULL
// check (`if (r0 == 0) goto skip`) between the helper and the store.
// JEq references R0 as the compare LHS but does not write it; the
// validator must not invalidate lastMap[R0] on that read, otherwise
// every plugin that follows the kernel-mandated NULL check (i.e. every
// real plugin) trips a false positive.
func TestValidatePluginROWrites_LookupThenNullCheck_Allowed(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("plugin_counter_map"),
		asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R7, 1),
		asm.JEq.Imm(asm.R0, 0, "skip"), // NULL check; reads R0, must not clear lastMap[R0]
		asm.FetchAdd.Mem(asm.R0, asm.R7, asm.DWord, 0),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("skip"),
	}
	if err := ValidatePluginProgram(roSpec("nullcheck", lead), roSet()); err != nil {
		t.Fatalf("lookup → null check → atomic update should pass, got: %v", err)
	}
}

// Symmetric to the case above but with an RO map: lookup-aware
// propagation must not become a hole — a write through R0 (or any
// reg-MOV-derived alias) into an RO map must still be flagged with the
// proper map name, not as "unresolved".
func TestValidatePluginROWrites_LookupROReject(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.FnMapLookupElem.Call(),
		asm.Mov.Reg(asm.R2, asm.R0), // alias R0 through R2
		asm.StoreImm(asm.R2, 0, 1, asm.Word),
	}
	err := ValidatePluginProgram(roSpec("lookup_ro", lead), roSet())
	if err == nil {
		t.Fatal("write through lookup of RO map must reject")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sid_function_map") {
		t.Errorf("error should name the RO map, got: %v", err)
	}
}

// Register-to-register MOV must propagate the tracked map identity so
// `LoadMapPtr R1, &ro_map; R2 = R1; *(R2 + 0) = ...` is still caught.
// Without this propagation an attacker could trivially launder the
// origin through a single MOV.
func TestValidatePluginROWrites_MovPropagatesRO(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.Mov.Reg(asm.R2, asm.R1),
		asm.StoreImm(asm.R2, 0, 99, asm.Word),
	}
	err := ValidatePluginProgram(roSpec("ro_via_mov", lead), roSet())
	if err == nil {
		t.Fatal("RO write laundered through MOV must still reject")
	}
	if !errors.Is(err, ErrPluginROWrite) {
		t.Errorf("expected ErrPluginROWrite, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sid_function_map") {
		t.Errorf("error should name the RO map, got: %v", err)
	}
}

// Subprogram body sitting after the main program (clang appends them
// after the entry point) must NOT be scanned. Otherwise legitimate
// epilogue writes to slot_stats_* would trip the check the moment we
// re-classify those maps as RO.
func TestValidatePluginROWrites_SubprogramSkipped(t *testing.T) {
	main := asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	}
	// Subprogram boundary: an instruction with a non-empty Symbol().
	// We simulate `slot_stats_endpoint` (currently RW, classified as
	// such; for the purposes of the test we treat it as RO via the set
	// override below) being written from inside the subprogram.
	subStart := asm.LoadMapPtr(asm.R1, 0).
		WithReference("slot_stats_endpoint").
		WithSymbol("subprogram_body")
	sub := asm.Instructions{
		subStart,
		asm.StoreImm(asm.R1, 0, 1, asm.Word),
		asm.Return(),
	}
	prog := buildSpec("with_sub", ebpf.XDP, append(main, sub...))

	// Force "slot_stats_endpoint" into the RO set so the test can prove
	// the scope guard wins even when the map name would otherwise match.
	ro := map[string]struct{}{"slot_stats_endpoint": {}}
	if err := ValidatePluginProgram(prog, ro); err != nil {
		t.Fatalf("subprogram writes must be skipped, got: %v", err)
	}
}

// A plugin-owned map (not in any vinbero shared set) is fine; the
// validator only enforces the RO contract for vinbero-managed names.
func TestValidatePluginROWrites_OwnedMapAllowed(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("plugin_counter_map"),
		asm.StoreImm(asm.R1, 0, 42, asm.Word),
	}
	if err := ValidatePluginProgram(roSpec("owned", lead), roSet()); err != nil {
		t.Fatalf("plugin-owned map write should pass, got: %v", err)
	}
}

// Stack writes (Dst == R10/RFP) are how clang lowers C local variables
// such as `struct ipv6_key key;`. They must not be flagged as map
// writes — otherwise every plugin that builds a lookup key on the
// stack would be rejected as (dynamic). Regression test pinning the
// fix that landed alongside the simple-acl example.
func TestValidatePluginROWrites_StackStoreIgnored(t *testing.T) {
	lead := asm.Instructions{
		// `*(R10 - 8) = 0;` — clang's typical stack-zero before key
		// construction. Should be silently ignored.
		asm.StoreImm(asm.RFP, -8, 0, asm.DWord),
		// And a register store to the stack as well, to cover both
		// StClass (immediate) and StXClass (register) opcodes.
		asm.Mov.Imm(asm.R1, 42),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.Word),
	}
	if err := ValidatePluginProgram(roSpec("stack", lead), roSet()); err != nil {
		t.Fatalf("stack stores must be ignored, got: %v", err)
	}
}

// Back-compat path: when roMaps is nil the check is a no-op even if the
// plugin clearly writes to an RO map. Tests and any internal callers
// that don't supply the set must keep working.
func TestValidatePluginROWrites_NilROSet(t *testing.T) {
	lead := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sid_function_map"),
		asm.StoreImm(asm.R1, 0, 99, asm.Word),
	}
	if err := ValidatePluginProgram(roSpec("legacy", lead), nil); err != nil {
		t.Fatalf("nil roMaps must skip the RO check, got: %v", err)
	}
}

// ParseROEnforceMode round-trip: empty / "warn" → ROEnforceWarn,
// "enforce" → ROEnforceEnforce, anything else is an error so a typo in
// vinbero.yaml can't silently downgrade the policy.
func TestParseROEnforceMode(t *testing.T) {
	cases := []struct {
		in     string
		want   ROEnforceMode
		hasErr bool
	}{
		{"", ROEnforceWarn, false},
		{"warn", ROEnforceWarn, false},
		{"enforce", ROEnforceEnforce, false},
		{"strict", 0, true},
	}
	for _, c := range cases {
		got, err := ParseROEnforceMode(c.in)
		if (err != nil) != c.hasErr {
			t.Errorf("ParseROEnforceMode(%q) err=%v hasErr=%v", c.in, err, c.hasErr)
			continue
		}
		if !c.hasErr && got != c.want {
			t.Errorf("ParseROEnforceMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// Stringer round-trips so log output stays parseable.
	if ROEnforceWarn.String() != "warn" || ROEnforceEnforce.String() != "enforce" {
		t.Errorf("String() round-trip mismatch: warn=%q enforce=%q",
			ROEnforceWarn.String(), ROEnforceEnforce.String())
	}
}

// BTF absent (stripped ELF): validation falls back to asm-level checks and
// must succeed if those pass.
func TestValidatePluginCollection_BTF_MissingOK(t *testing.T) {
	prog := buildSpec("xdp_entry", ebpf.XDP, asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		callToSymbol(SymTailcallEpilogue),
		asm.Return(),
	})
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"xdp_entry": prog},
		Maps: map[string]*ebpf.MapSpec{
			"sid_function_map": {
				Name:       "sid_function_map",
				Type:       ebpf.LPMTrie,
				KeySize:    20,
				ValueSize:  12,
				MaxEntries: 1024,
				// Value: nil — stripped BTF
			},
		},
	}
	if _, err := ValidatePluginCollection(spec, "xdp_entry", nil); err != nil {
		t.Fatalf("expected stripped-BTF plugin to pass, got: %v", err)
	}
}
