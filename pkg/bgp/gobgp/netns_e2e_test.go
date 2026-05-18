package gobgp_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host to network (big-endian) byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// etherTypeIPv6 is the IPv6 EtherType, used to filter captured frames.
const etherTypeIPv6 = 0x86DD

// inNetns runs fn with the calling goroutine's (already OS-locked)
// thread moved into ns, restoring it to home afterward. netns is a
// per-thread property, so the caller MUST have locked its OS thread.
func inNetns(t *testing.T, ns, home netns.NsHandle, fn func()) {
	t.Helper()
	if err := netns.Set(ns); err != nil {
		t.Fatalf("enter netns: %v", err)
	}
	// Best-effort restore: the test's top-level cleanup re-pins the host
	// namespace, and calling t.Fatalf here (mid-Goexit if fn failed)
	// would be unsafe.
	defer func() { _ = netns.Set(home) }()
	fn()
}

// TestNetnsE2E_VPNv4XdpEncapOnWire is the physical end-to-end proof for
// the GoBGP integration: a VPNv4 route learned over a real BGP session
// installs a headend entry (setupVPNv4Receive); the real XDP program is
// then attached to a veth inside a network namespace, a plain IPv4
// packet is injected on the wire, and the kernel forwards the
// SRv6-encapsulated result back out where it is captured on the wire.
//
// Path: inject (AF_PACKET, outerNs) -> vinj --veth--> vrx (XDP H.Encaps,
// XDP_PASS) -> peNs kernel forwards by IPv6 FIB -> vrx -> vinj -> capture.
//
// Requires root (BPF collection load, netns, XDP attach).
func TestNetnsE2E_VPNv4XdpEncapOnWire(t *testing.T) {
	r := setupVPNv4Receive(t)

	runtime.LockOSThread()
	hostNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	// peNs runs the XDP data plane; outerNs is the "wire" we inject on
	// and capture from. netns.New enters the new namespace, so each
	// creation is followed by a hop back to the host namespace.
	peNs, err := netns.New()
	if err != nil {
		_ = hostNs.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New peNs (needs root): %v", err)
	}
	_ = netns.Set(hostNs)
	outerNs, err := netns.New()
	if err != nil {
		_ = peNs.Close()
		_ = hostNs.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New outerNs: %v", err)
	}
	_ = netns.Set(hostNs)
	t.Cleanup(func() {
		_ = netns.Set(hostNs)
		_ = outerNs.Close()
		_ = peNs.Close()
		_ = hostNs.Close()
		runtime.UnlockOSThread()
	})

	// veth pair: vrx lands in peNs (XDP attached), vinj in outerNs.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "vrx"},
		PeerName:  "vinj",
	}); err != nil {
		t.Fatalf("LinkAdd veth: %v", err)
	}
	vrxHost, err := netlink.LinkByName("vrx")
	if err != nil {
		t.Fatalf("LinkByName vrx: %v", err)
	}
	vinjHost, err := netlink.LinkByName("vinj")
	if err != nil {
		t.Fatalf("LinkByName vinj: %v", err)
	}
	if err := netlink.LinkSetNsFd(vrxHost, int(peNs)); err != nil {
		t.Fatalf("move vrx -> peNs: %v", err)
	}
	if err := netlink.LinkSetNsFd(vinjHost, int(outerNs)); err != nil {
		t.Fatalf("move vinj -> outerNs: %v", err)
	}

	peH, err := netlink.NewHandleAt(peNs)
	if err != nil {
		t.Fatalf("NewHandleAt peNs: %v", err)
	}
	t.Cleanup(peH.Close)
	outerH, err := netlink.NewHandleAt(outerNs)
	if err != nil {
		t.Fatalf("NewHandleAt outerNs: %v", err)
	}
	t.Cleanup(outerH.Close)

	vrx, err := peH.LinkByName("vrx")
	if err != nil {
		t.Fatalf("peNs LinkByName vrx: %v", err)
	}
	vinj, err := outerH.LinkByName("vinj")
	if err != nil {
		t.Fatalf("outerNs LinkByName vinj: %v", err)
	}
	if err := peH.LinkSetUp(vrx); err != nil {
		t.Fatalf("vrx up: %v", err)
	}
	if err := outerH.LinkSetUp(vinj); err != nil {
		t.Fatalf("vinj up: %v", err)
	}

	// vrx gets an address so the SID's /64 is an on-link route: the
	// encapsulated packet (dst = SID) is forwarded back out vrx towards
	// vinj. IFA_F_NODAD skips duplicate-address detection so the
	// address is usable immediately.
	addr, err := netlink.ParseAddr("fd00:1:1:a::1/64")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	addr.Flags = unix.IFA_F_NODAD
	if err := peH.AddrAdd(vrx, addr); err != nil {
		t.Fatalf("AddrAdd vrx: %v", err)
	}

	// Enable IPv6 forwarding inside peNs (procfs is namespace-scoped).
	inNetns(t, peNs, hostNs, func() {
		if werr := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding",
			[]byte("1"), 0o644); werr != nil {
			t.Fatalf("enable IPv6 forwarding: %v", werr)
		}
	})

	// Static neighbor for the SID so the kernel builds the L2 frame
	// without NDP -- a pre-resolved neighbor avoids NO_NEIGH drops.
	sidIP := net.ParseIP(e2eServiceSID)
	if err := peH.NeighAdd(&netlink.Neigh{
		LinkIndex:    vrx.Attrs().Index,
		Family:       unix.AF_INET6,
		State:        netlink.NUD_PERMANENT,
		IP:           sidIP,
		HardwareAddr: vinj.Attrs().HardwareAddr,
	}); err != nil {
		t.Fatalf("NeighAdd SID: %v", err)
	}

	// Attach the real XDP program -- the collection the Applier just
	// populated over BGP -- to vrx in generic mode.
	var xdpLink link.Link
	inNetns(t, peNs, hostNs, func() {
		l, aerr := link.AttachXDP(link.XDPOptions{
			Program:   r.objs.VinberoMain,
			Interface: vrx.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})
		if aerr != nil {
			t.Fatalf("AttachXDP vrx: %v", aerr)
		}
		xdpLink = l
	})
	t.Cleanup(func() { _ = xdpLink.Close() })

	// AF_PACKET socket on vinj: injects the plain packet and captures
	// the encapsulated one coming back. The socket must be created
	// while the thread is in outerNs; the fd then works from any netns.
	var sockFd int
	inNetns(t, outerNs, hostNs, func() {
		fd, serr := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if serr != nil {
			t.Fatalf("AF_PACKET socket: %v", serr)
		}
		if berr := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  vinj.Attrs().Index,
		}); berr != nil {
			_ = unix.Close(fd)
			t.Fatalf("bind AF_PACKET to vinj: %v", berr)
		}
		if terr := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
			&unix.Timeval{Usec: 200_000}); terr != nil {
			_ = unix.Close(fd)
			t.Fatalf("SO_RCVTIMEO: %v", terr)
		}
		sockFd = fd
	})
	t.Cleanup(func() { _ = unix.Close(sockFd) })

	// Inject a plain IPv4 packet destined inside the BGP-advertised
	// 10.0.0.0/24, then capture the SRv6-encapsulated result. The
	// packet is re-sent each round so a slow link bring-up cannot lose
	// the only attempt.
	innerSrc := net.IPv4(192, 0, 2, 1)
	innerDst := net.IPv4(10, 0, 0, 5)
	frame := buildPlainIPv4Packet(t, innerSrc, innerDst)
	sendTo := &unix.SockaddrLinklayer{Ifindex: vinj.Attrs().Index}

	var sid, outerSrc [16]byte
	copy(sid[:], sidIP.To16())
	copy(outerSrc[:], net.ParseIP(e2eLocatorPfx).To16())

	buf := make([]byte, 2048)
	var captured []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && captured == nil {
		if err := unix.Sendto(sockFd, frame, 0, sendTo); err != nil {
			t.Fatalf("inject packet: %v", err)
		}
		for time.Now().Before(deadline) {
			n, _, rerr := unix.Recvfrom(sockFd, buf, 0)
			if rerr != nil {
				break // EAGAIN: nothing more this round, re-send
			}
			if n < ethHeaderLen+ipv6HeaderLen {
				continue
			}
			// An IPv6 ethertype whose outer destination is the service
			// SID identifies the encapsulated packet (skips the echoed
			// inject frame and IPv6 link-local NDP/MLD noise).
			if binary.BigEndian.Uint16(buf[12:14]) != etherTypeIPv6 {
				continue
			}
			if !bytes.Equal(buf[ethHeaderLen+24:ethHeaderLen+ipv6HeaderLen], sid[:]) {
				continue
			}
			captured = append([]byte(nil), buf[:n]...)
			break
		}
	}
	if captured == nil {
		t.Fatal("no SRv6-encapsulated packet captured on the wire within 10s")
	}
	verifyEncapTowardSID(t, captured, outerSrc, sid, innerSrc, innerDst)
	t.Logf("captured %d-byte SRv6-encapsulated packet on the wire", len(captured))
}
