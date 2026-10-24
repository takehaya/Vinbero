package cplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// This test-only rig follows the AF_PACKET/generic-XDP setup used by
// pkg/bgp/gobgp/netns_e2e_test.go. Each pair is created inside its own namespace;
// no host interface names, routes, forwarding settings, or pinned maps change.
type evpnPacketWire struct {
	fd, injector, ingress int
	peerMAC, peMAC        net.HardwareAddr
}

func evpnNetworkOrder(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return binary.NativeEndian.Uint16(b[:])
}

func newEVPNPacketWire(t *testing.T, program *ebpf.Program) *evpnPacketWire {
	t.Helper()
	runtime.LockOSThread()
	home, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := netns.Set(home); err != nil {
			t.Error("restore original network namespace:", err)
			// Do not return a thread in the wrong namespace to the runtime.
			_ = home.Close()
			return
		}
		_ = home.Close()
		runtime.UnlockOSThread()
	})
	makeNS := func() netns.NsHandle {
		t.Helper()
		ns, err := netns.New()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ns.Close(); err != nil {
				t.Error(err)
			}
		})
		if err := netns.Set(home); err != nil {
			t.Fatal(err)
		}
		return ns
	}
	pe, peer := makeNS(), makeNS()
	inNS := func(ns netns.NsHandle, fn func()) {
		t.Helper()
		if err := netns.Set(ns); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := netns.Set(home); err != nil {
				t.Error("restore network namespace:", err)
			}
		}()
		fn()
	}
	peHandle, err := netlink.NewHandleAt(pe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peHandle.Close)
	peerHandle, err := netlink.NewHandleAt(peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerHandle.Close)
	if err := peHandle.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "evpn-rx", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, PeerName: "evpn-wire"}); err != nil {
		t.Fatal(err)
	}
	injection, err := peHandle.LinkByName("evpn-wire")
	if err != nil {
		t.Fatal(err)
	}
	if err := peHandle.LinkSetNsFd(injection, int(peer)); err != nil {
		t.Fatal(err)
	}
	rx, err := peHandle.LinkByName("evpn-rx")
	if err != nil {
		t.Fatal(err)
	}
	injection, err = peerHandle.LinkByName("evpn-wire")
	if err != nil {
		t.Fatal(err)
	}
	if err := peerHandle.LinkSetHardwareAddr(injection, net.HardwareAddr{2, 0, 0, 0, 0, 2}); err != nil {
		t.Fatal(err)
	}
	injection, err = peerHandle.LinkByName("evpn-wire")
	if err != nil {
		t.Fatal(err)
	}
	if err := peHandle.LinkSetUp(rx); err != nil {
		t.Fatal(err)
	}
	if err := peerHandle.LinkSetUp(injection); err != nil {
		t.Fatal(err)
	}
	// Connected underlay route and permanent neighbor make the FIB path ready
	// before the single transmission; no retry traffic or external router is used.
	for _, cidr := range []string{"fd00:2::2/64", "fd00:feed::1/128"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := peHandle.AddrAdd(rx, addr); err != nil {
			t.Fatal(err)
		}
	}
	if err := peHandle.NeighAdd(&netlink.Neigh{LinkIndex: rx.Attrs().Index, Family: unix.AF_INET6, State: netlink.NUD_PERMANENT, IP: net.ParseIP("fd00:2::1"), HardwareAddr: injection.Attrs().HardwareAddr}); err != nil {
		t.Fatal(err)
	}
	inNS(pe, func() {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
		attached, err := link.AttachXDP(link.XDPOptions{Program: program, Interface: rx.Attrs().Index, Flags: link.XDPGenericMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := attached.Close(); err != nil {
				t.Error(err)
			}
		})
	})
	rig := &evpnPacketWire{fd: -1, injector: injection.Attrs().Index, ingress: rx.Attrs().Index, peerMAC: injection.Attrs().HardwareAddr, peMAC: rx.Attrs().HardwareAddr}
	inNS(peer, func() {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(evpnNetworkOrder(unix.ETH_P_ALL)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := unix.Close(fd); err != nil {
				t.Error(err)
			}
		})
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: evpnNetworkOrder(unix.ETH_P_ALL), Ifindex: rig.injector}); err != nil {
			t.Fatal(err)
		}
		rig.fd = fd
	})
	return rig
}

func (r *evpnPacketWire) check(t *testing.T, frame []byte, present bool) {
	t.Helper()
	// Distinct nonce per state excludes delayed packets from earlier states.
	marker := bytes.Index(frame, []byte("EVPN controller packet lifecycle "))
	if marker < 0 {
		t.Fatal("missing packet identity")
	}
	if err := unix.Sendto(r.fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: r.injector}); err != nil {
		t.Fatal("send single packet:", err)
	}
	const window = time.Second
	deadline := time.Now().Add(window)
	buf := make([]byte, 4096)
	matches := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		ms := int((remaining + time.Millisecond - 1) / time.Millisecond)
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if ready == 0 {
			continue
		}
		n, addr, err := unix.Recvfrom(r.fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if ll, ok := addr.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		packet := buf[:n]
		if n < 14 || binary.BigEndian.Uint16(packet[12:14]) != 0x86dd || !bytes.Contains(packet[14:], frame[marker:]) {
			continue
		}
		matches++
		if !present {
			t.Fatalf("withdrawn policy emitted identified IPv6 packet: %x", packet)
		}
		// Bytes, including the entire inner frame, are checked independently of
		// successful map reads. A wire capture does not observe the XDP action.
		evpnPacketEncapsulation(t, frame, packet)
		if !bytes.Equal(packet[:6], r.peerMAC) || !bytes.Equal(packet[6:12], r.peMAC) {
			t.Fatalf("incorrect underlay Ethernet addresses: %x", packet[:14])
		}
	}
	want := 0
	if present {
		want = 1
	}
	if matches != want {
		t.Fatalf("identified encap packets=%d want=%d after one transmission in %s", matches, want, window)
	}
	t.Logf("wire observation window=%s sent=1 identified_encap=%d", window, matches)
}
