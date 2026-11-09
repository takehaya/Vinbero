package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProbeGenericBroadcastCopies reports whether this kernel gives every copy
// of a generic-XDP devmap broadcast its own packet buffer before running the
// entry's egress program.
//
// Kernels without "bpf: Run generic devmap egress prog on private skb" hand
// the copies skb clones that share one buffer, so what one copy's egress
// program writes shows up in all of them. xdp-mode BUM replication writes a
// different encapsulation into each copy and cannot work there.
//
// The probe answers the question by trying it: in a fresh network namespace
// of its own it attaches a generic XDP program to one end of a veth pair
// that broadcasts every probe frame to two devmap entries on that same
// device, whose egress programs stamp a different byte into the frame. A
// few frames go in from an ordinary AF_PACKET socket on the other end and
// come back there; private buffers keep the two stamps apart. Nothing it
// creates outlives the call: the namespace belongs to a thread that exits
// with the probe, and the veth pair goes with the namespace.
func ProbeGenericBroadcastCopies(timeout time.Duration) (private bool, err error) {
	type result struct {
		private bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		// The goroutine never unlocks its thread: when it returns, the Go
		// runtime ends the thread, and with it the namespace it entered.
		runtime.LockOSThread()
		p, err := probeGenericBroadcastCopies(timeout)
		done <- result{p, err}
	}()
	r := <-done
	return r.private, r.err
}

const (
	probeEtherType   = 0x88b6 // IEEE local experimental EtherType 2
	probeFrames      = 3
	probeStampOffset = 14 // first payload byte
	probeIDOffset    = 15
	probeFrameLen    = 60
)

func probeGenericBroadcastCopies(timeout time.Duration) (bool, error) {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return false, fmt.Errorf("create a network namespace: %w", err)
	}

	// A veth pair: probe frames enter on rx (generic XDP) and its two
	// copies leave through rx again, arriving back on tx.
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vbprobe0"}, PeerName: "vbprobe1"}
	if err := netlink.LinkAdd(veth); err != nil {
		return false, fmt.Errorf("create veth pair: %w", err)
	}
	rx, err := netlink.LinkByName("vbprobe0")
	if err != nil {
		return false, err
	}
	tx, err := netlink.LinkByName("vbprobe1")
	if err != nil {
		return false, err
	}
	for _, l := range []netlink.Link{rx, tx} {
		if err := netlink.LinkSetUp(l); err != nil {
			return false, fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
		}
	}
	rxIndex, txIndex := rx.Attrs().Index, tx.Attrs().Index

	devmap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "vb_probe_dm",
		Type:       ebpf.DevMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 2,
	})
	if err != nil {
		return false, fmt.Errorf("create devmap: %w", err)
	}
	defer func() { _ = devmap.Close() }()

	for i := uint32(0); i < 2; i++ {
		prog, err := ebpf.NewProgram(probeStampSpec(byte(0xa0 + i)))
		if err != nil {
			return false, fmt.Errorf("load devmap egress program: %w", err)
		}
		defer func() { _ = prog.Close() }()
		if err := devmap.Put(i, devmapVal{Ifindex: uint32(rxIndex), ProgFD: uint32(prog.FD())}); err != nil {
			return false, fmt.Errorf("add devmap entry %d: %w", i, err)
		}
	}

	ingress, err := ebpf.NewProgram(probeBroadcastSpec(devmap))
	if err != nil {
		return false, fmt.Errorf("load XDP program: %w", err)
	}
	defer func() { _ = ingress.Close() }()
	xl, err := link.AttachXDP(link.XDPOptions{Program: ingress, Interface: rxIndex, Flags: link.XDPGenericMode})
	if err != nil {
		return false, fmt.Errorf("attach generic XDP: %w", err)
	}
	defer func() { _ = xl.Close() }()

	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(probeEtherType)))
	if err != nil {
		return false, fmt.Errorf("open receive socket: %w", err)
	}
	defer func() { _ = unix.Close(recvFD) }()
	if err := unix.Bind(recvFD, &unix.SockaddrLinklayer{Protocol: htons(probeEtherType), Ifindex: txIndex}); err != nil {
		return false, fmt.Errorf("bind receive socket: %w", err)
	}
	// Protocol 0: a send-only socket that receives nothing.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open send socket: %w", err)
	}
	defer func() { _ = unix.Close(sendFD) }()

	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	to := &unix.SockaddrLinklayer{Protocol: htons(probeEtherType), Ifindex: txIndex, Halen: 6}
	copy(to.Addr[:], bcast)
	for id := 0; id < probeFrames; id++ {
		frame := make([]byte, probeFrameLen)
		copy(frame[0:6], bcast)
		copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
		frame[12], frame[13] = byte(probeEtherType>>8), byte(probeEtherType&0xff)
		frame[probeIDOffset] = byte(id)
		if err := unix.Sendto(sendFD, frame, 0, to); err != nil {
			return false, fmt.Errorf("send probe frame: %w", err)
		}
	}

	stamps := make(map[byte][]byte, probeFrames)
	got := 0
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 256)
	for got < 2*probeFrames {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		if err := unix.SetsockoptTimeval(recvFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return false, err
		}
		n, _, err := unix.Recvfrom(recvFD, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("receive: %w", err)
		}
		if n <= probeIDOffset || buf[probeIDOffset] >= probeFrames {
			continue
		}
		id := buf[probeIDOffset]
		stamps[id] = append(stamps[id], buf[probeStampOffset])
		got++
	}
	return probeVerdict(stamps)
}

// probeVerdict decides from the stamps seen on the copies of each probe
// frame. Private buffers give the two copies of a frame different stamps;
// a shared buffer gives every copy the stamp written last. Any frame whose
// copies agree means sharing.
func probeVerdict(stamps map[byte][]byte) (bool, error) {
	compared := 0
	for _, s := range stamps {
		if len(s) < 2 {
			continue
		}
		compared++
		for _, v := range s[1:] {
			if v == s[0] {
				return false, nil
			}
		}
	}
	if compared == 0 {
		return false, fmt.Errorf("no probe frame came back as two copies (%d frames seen)", len(stamps))
	}
	return true, nil
}

// probeBroadcastSpec: broadcast probe frames to every devmap entry, drop
// anything else.
func probeBroadcastSpec(devmap *ebpf.Map) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:       "vb_probe_bcast",
		Type:       ebpf.XDP,
		AttachType: ebpf.AttachXDP,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), // ctx->data
			asm.LoadMem(asm.R3, asm.R1, 4, asm.Word), // ctx->data_end
			asm.Mov.Reg(asm.R4, asm.R2),
			asm.Add.Imm(asm.R4, probeIDOffset+1),
			asm.JGT.Reg(asm.R4, asm.R3, "drop"),
			asm.LoadMem(asm.R4, asm.R2, 12, asm.Byte),
			asm.JNE.Imm(asm.R4, probeEtherType>>8, "drop"),
			asm.LoadMem(asm.R4, asm.R2, 13, asm.Byte),
			asm.JNE.Imm(asm.R4, probeEtherType&0xff, "drop"),
			asm.LoadMapPtr(asm.R1, devmap.FD()),
			asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Imm(asm.R3, int32(unix.BPF_F_BROADCAST)),
			asm.FnRedirectMap.Call(),
			asm.Return(),
			asm.Mov.Imm(asm.R0, int32(XDP_DROP)).WithSymbol("drop"),
			asm.Return(),
		},
	}
}

// probeStampSpec: devmap egress program that writes stamp into the first
// payload byte and transmits.
func probeStampSpec(stamp byte) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:       "vb_probe_stamp",
		Type:       ebpf.XDP,
		AttachType: ebpf.AttachXDPDevMap,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
			asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),
			asm.Mov.Reg(asm.R4, asm.R2),
			asm.Add.Imm(asm.R4, probeStampOffset+1),
			asm.JGT.Reg(asm.R4, asm.R3, "out"),
			asm.StoreImm(asm.R2, probeStampOffset, int64(stamp), asm.Byte),
			asm.Mov.Imm(asm.R0, int32(XDP_PASS)).WithSymbol("out"),
			asm.Return(),
		},
	}
}

// htons returns v in network byte order, as AF_PACKET wants its protocol.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
