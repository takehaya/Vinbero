package bpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// fibLookupTBIDFlags are BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID, the
// flags the data plane uses for a tenant packet's outer header
// (srv6_fib_v6_params_set in src/core/srv6_fib.h).
const fibLookupTBIDFlags = 1<<0 | 1<<3

// ProbeFibLookupTBID reports whether the kernel's bpf_fib_lookup accepts
// BPF_FIB_LOOKUP_TBID (Linux 6.5, and kernels it was backported to). Without
// it the helper refuses the lookup the data plane makes for the outer header
// of a tenant AC's encapsulation, so those packets are not encapsulated.
//
// The probe is a small XDP program run through BPF_PROG_TEST_RUN in the
// calling thread's namespace: it calls bpf_fib_lookup with those flags on
// the loopback device and stores the return value in the packet. The helper
// checks the flags before anything else, so -EINVAL means the flag is
// unknown; any other answer (a route or none) means it is accepted.
func ProbeFibLookupTBID() (bool, error) {
	const paramsLen = 64 // sizeof(struct bpf_fib_lookup)
	const pktLen = paramsLen + 8
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word), // data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word), // data_end
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, pktLen),
		asm.JGT.Reg(asm.R4, asm.R3, "out"),
	}
	// The packet carries the params; copy them to the stack for the helper.
	for i := int16(0); i < paramsLen/8; i++ {
		ins = append(ins,
			asm.LoadMem(asm.R0, asm.R2, 8*i, asm.DWord),
			asm.StoreMem(asm.R10, -paramsLen+8*i, asm.R0, asm.DWord))
	}
	ins = append(ins,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -paramsLen),
		asm.Mov.Imm(asm.R3, paramsLen),
		asm.Mov.Imm(asm.R4, fibLookupTBIDFlags),
		asm.FnFibLookup.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, pktLen),
		asm.JGT.Reg(asm.R4, asm.R3, "out"),
		asm.StoreMem(asm.R2, paramsLen, asm.R7, asm.Word),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("out"), // XDP_PASS
		asm.Return(),
	)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fib_tbid_probe", Type: ebpf.XDP, License: "GPL", Instructions: ins,
	})
	if err != nil {
		return false, fmt.Errorf("load the bpf_fib_lookup probe: %w", err)
	}
	defer func() { _ = prog.Close() }()

	in := make([]byte, pktLen)
	in[0] = unix.AF_INET6
	binary.NativeEndian.PutUint32(in[8:], 1)    // ifindex: loopback
	in[32+15] = 1                               // ipv6_dst ::1
	binary.NativeEndian.PutUint32(in[48:], 254) // tbid: main
	// A value the helper never returns, so an unwritten result is visible.
	binary.NativeEndian.PutUint32(in[paramsLen:], 0x7fffffff)
	out := make([]byte, pktLen)
	if _, err := prog.Run(&ebpf.RunOptions{Data: in, DataOut: out}); err != nil {
		return false, fmt.Errorf("run the bpf_fib_lookup probe: %w", err)
	}
	ret := int32(binary.NativeEndian.Uint32(out[paramsLen:]))
	if ret == 0x7fffffff {
		return false, fmt.Errorf("the bpf_fib_lookup probe did not run the helper")
	}
	return ret != -int32(unix.EINVAL), nil
}
