package bpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

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
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins)); err != nil {
		t.Fatalf("expected valid spec to pass, got: %v", err)
	}
}

func TestValidatePluginProgram_MissingEpilogueAndTailCall(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
	}
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins))
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
	err := ValidatePluginProgram(buildSpec("tc", ebpf.SchedCLS, ins))
	if err == nil || !strings.Contains(err.Error(), "xdp") {
		t.Fatalf("expected 'xdp' in error, got: %v", err)
	}
}

func TestValidatePluginProgram_NilSpec(t *testing.T) {
	if err := ValidatePluginProgram(nil); err == nil {
		t.Fatal("expected error for nil spec")
	}
}

func TestValidatePluginProgram_CallsOtherSymbol(t *testing.T) {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		callToSymbol("some_helper"),
		asm.Return(),
	}
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins)); err == nil {
		t.Fatal("expected error when tailcall_epilogue absent even with other calls")
	}
}

// Plugin dispatches back into a vinbero PROG_ARRAY instead of returning.
func TestValidatePluginProgram_ValidTailCallOnly(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("sid_endpoint_progs", 33)...)
	ins = append(ins, asm.Mov.Imm(asm.R0, 2), asm.Return())
	if err := ValidatePluginProgram(buildSpec("dispatch", ebpf.XDP, ins)); err != nil {
		t.Fatalf("expected tail-call-only plugin to pass, got: %v", err)
	}
}

func TestValidatePluginProgram_ValidTailCallHeadendV4(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("headend_v4_progs", 20)...)
	ins = append(ins, asm.Mov.Imm(asm.R0, 2), asm.Return())
	if err := ValidatePluginProgram(buildSpec("dispatch", ebpf.XDP, ins)); err != nil {
		t.Fatalf("expected tail-call into headend_v4_progs to pass, got: %v", err)
	}
}

// Plugin uses both routes: leaf on one path, dispatch on another.
func TestValidatePluginProgram_BothEpilogueAndTailCall(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("sid_endpoint_progs", 40)...)
	ins = append(ins, callToSymbol(SymTailcallEpilogue), asm.Return())
	if err := ValidatePluginProgram(buildSpec("mixed", ebpf.XDP, ins)); err != nil {
		t.Fatalf("expected leaf+dispatch plugin to pass, got: %v", err)
	}
}

// Plugin tries to tail-call into a map that is not a vinbero PROG_ARRAY.
func TestValidatePluginProgram_ForeignTailCall(t *testing.T) {
	ins := append(asm.Instructions{}, tailCallTo("my_private_progs", 0)...)
	ins = append(ins, callToSymbol(SymTailcallEpilogue), asm.Return())
	err := ValidatePluginProgram(buildSpec("escape", ebpf.XDP, ins))
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
	err := ValidatePluginProgram(buildSpec("dyn", ebpf.XDP, ins))
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
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins))
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
	if err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins)); err != nil {
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
	err := ValidatePluginProgram(buildSpec("p", ebpf.XDP, ins))
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
	if _, err := ValidatePluginCollection(spec, "xdp_entry"); err == nil {
		t.Fatal("expected BTF type mismatch to be rejected")
	} else if !strings.Contains(err.Error(), "sid_function_entry") {
		t.Errorf("error should name the expected type, got: %v", err)
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
	if _, err := ValidatePluginCollection(spec, "xdp_entry"); err != nil {
		t.Fatalf("expected stripped-BTF plugin to pass, got: %v", err)
	}
}
