package bpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// uplinkProbeIOLen is sizeof(struct bum_uplink_probe_io): src, dst, ifindex,
// ret (bum_egress.c).
const uplinkProbeIOLen = IPv6AddrLen + IPv6AddrLen + 4 + 4

// ProbeUplinkResolver resolves a peer's uplink by running prog
// (bum_uplink_probe) through BPF_PROG_TEST_RUN. The program makes the same
// bpf_fib_lookup call as the data plane, with the same arguments, in this
// process's network namespace, so its answer is the data plane's: with a
// multipath route the kernel picks the next hop by hashing those inputs,
// and only asking the same way gives the same result. It takes no context:
// the helper uses it for the namespace, which BPF_PROG_TEST_RUN takes from
// the calling thread, and the AC is passed in the lookup itself.
//
// BPF_FIB_LKUP_RET_NO_NEIGH still resolves: the uplink is known and the
// control plane makes its next hop a managed neighbour.
func ProbeUplinkResolver(prog *ebpf.Program) UplinkResolver {
	return func(q UplinkQuery) (BumUplink, error) {
		if prog == nil {
			return BumUplink{}, fmt.Errorf("bum_uplink_probe is not loaded")
		}
		in := make([]byte, uplinkProbeIOLen)
		copy(in[0:IPv6AddrLen], q.Src[:])
		copy(in[IPv6AddrLen:2*IPv6AddrLen], q.Dst[:])
		binary.NativeEndian.PutUint32(in[2*IPv6AddrLen:], q.AC)

		out := make([]byte, uplinkProbeIOLen)
		ret, err := prog.Run(&ebpf.RunOptions{Data: in, DataOut: out})
		if err != nil {
			return BumUplink{}, fmt.Errorf("run the uplink probe: %w", err)
		}
		if ret != XDP_PASS {
			return BumUplink{}, fmt.Errorf("uplink probe returned action %d", ret)
		}

		fib := int32(binary.NativeEndian.Uint32(out[2*IPv6AddrLen+4:]))
		if fib == -int32(unix.ENODEV) { // the helper's answer for a device that is gone
			return BumUplink{}, fmt.Errorf("resolve an uplink for AC %d: %w", q.AC, unix.ENODEV)
		}
		if fib != unix.BPF_FIB_LKUP_RET_SUCCESS && fib != unix.BPF_FIB_LKUP_RET_NO_NEIGH {
			return BumUplink{}, fmt.Errorf("no usable route to %s (bpf_fib_lookup returned %d)", net.IP(q.Dst[:]), fib)
		}
		ifindex := binary.NativeEndian.Uint32(out[2*IPv6AddrLen:])
		if ifindex == 0 {
			return BumUplink{}, fmt.Errorf("no route to %s", net.IP(q.Dst[:]))
		}
		nexthop := make(net.IP, IPv6AddrLen)
		copy(nexthop, out[IPv6AddrLen:2*IPv6AddrLen])
		return BumUplink{Ifindex: ifindex, Nexthop: nexthop}, nil
	}
}
