package bpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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
