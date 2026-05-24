package gobgp_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
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

// wireRig is a peNs(XDP data plane) <-> outerNs(injection wire) veth pair
// with the real XDP program attached to the receiving end (vrx) in generic
// mode. vrx carries an on-link address (vrxCIDR) so the encapsulated
// packet's outer destination routes back out towards the injector, and
// neighIP is pre-resolved (permanent neighbor) so the kernel builds the
// return L2 frame without NDP. The injector AF_PACKET socket (on vinj)
// both sends the plain packet and captures the encapsulated result.
type wireRig struct {
	t       *testing.T
	sockFd  int
	vinjIdx int
}

// setupWireRig builds the two-namespace veth rig, attaches prog to vrx, and
// returns a handle whose roundTrip injects/captures on the wire. All
// resources are torn down via t.Cleanup. Requires root.
func setupWireRig(t *testing.T, prog *ebpf.Program, vrxCIDR string, neighIP net.IP) *wireRig {
	t.Helper()

	runtime.LockOSThread()
	hostNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	// peNs runs the XDP data plane; outerNs is the "wire" we inject on and
	// capture from. netns.New enters the new namespace, so each creation is
	// followed by a hop back to the host namespace.
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

	// vrx gets an address so the outer-destination /64 is an on-link route:
	// the encapsulated packet is forwarded back out vrx towards vinj.
	// IFA_F_NODAD skips duplicate-address detection so it is usable at once.
	addr, err := netlink.ParseAddr(vrxCIDR)
	if err != nil {
		t.Fatalf("ParseAddr %q: %v", vrxCIDR, err)
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

	// Static neighbor for the outer destination so the kernel builds the L2
	// frame without NDP -- a pre-resolved neighbor avoids NO_NEIGH drops.
	if err := peH.NeighAdd(&netlink.Neigh{
		LinkIndex:    vrx.Attrs().Index,
		Family:       unix.AF_INET6,
		State:        netlink.NUD_PERMANENT,
		IP:           neighIP,
		HardwareAddr: vinj.Attrs().HardwareAddr,
	}); err != nil {
		t.Fatalf("NeighAdd %s: %v", neighIP, err)
	}

	// Attach the real XDP program to vrx in generic mode.
	var xdpLink link.Link
	inNetns(t, peNs, hostNs, func() {
		l, aerr := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: vrx.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})
		if aerr != nil {
			t.Fatalf("AttachXDP vrx: %v", aerr)
		}
		xdpLink = l
	})
	t.Cleanup(func() { _ = xdpLink.Close() })

	// AF_PACKET socket on vinj: injects the plain packet and captures the
	// encapsulated one coming back. The socket must be created while the
	// thread is in outerNs; the fd then works from any netns.
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

	return &wireRig{t: t, sockFd: sockFd, vinjIdx: vinj.Attrs().Index}
}

// roundTrip injects frame repeatedly and returns the first captured IPv6
// frame whose outer destination equals matchDA, failing after 10s. The
// packet is re-sent each round so a slow link bring-up cannot lose the only
// attempt; the destination filter skips the echoed inject frame and IPv6
// link-local NDP/MLD noise.
func (r *wireRig) roundTrip(frame []byte, matchDA [16]byte) []byte {
	r.t.Helper()
	sendTo := &unix.SockaddrLinklayer{Ifindex: r.vinjIdx}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := unix.Sendto(r.sockFd, frame, 0, sendTo); err != nil {
			r.t.Fatalf("inject packet: %v", err)
		}
		for time.Now().Before(deadline) {
			n, _, rerr := unix.Recvfrom(r.sockFd, buf, 0)
			if rerr != nil {
				break // EAGAIN: nothing more this round, re-send
			}
			if n < ethHeaderLen+ipv6HeaderLen {
				continue
			}
			if binary.BigEndian.Uint16(buf[12:14]) != etherTypeIPv6 {
				continue
			}
			if !bytes.Equal(buf[ethHeaderLen+24:ethHeaderLen+ipv6HeaderLen], matchDA[:]) {
				continue
			}
			return append([]byte(nil), buf[:n]...)
		}
	}
	r.t.Fatal("no matching SRv6-encapsulated packet captured on the wire within 10s")
	return nil
}

// TestNetnsE2E_VPNv4XdpEncapOnWire is the physical end-to-end proof for
// the GoBGP integration: a VPNv4 route learned over a real BGP session
// installs a headend entry (setupVPNv4Receive); the real XDP program is
// then attached to a veth inside a network namespace, a plain IPv4
// packet is injected on the wire, and the kernel forwards the
// SRv6-encapsulated result back out where it is captured on the wire.
//
// Path: inject (AF_PACKET, outerNs) -> vinj --veth--> vrx (XDP H.Encaps,
// real bpf_redirect) -> vrx -> vinj -> capture.
//
// Requires root (BPF collection load, netns, XDP attach).
func TestNetnsE2E_VPNv4XdpEncapOnWire(t *testing.T) {
	r := setupVPNv4Receive(t)

	sidIP := net.ParseIP(e2eServiceSID)
	rig := setupWireRig(t, r.objs.VinberoMain, "fd00:1:1:a::1/64", sidIP)

	var sid, outerSrc [16]byte
	copy(sid[:], sidIP.To16())
	copy(outerSrc[:], net.ParseIP(e2eLocatorPfx).To16())

	frame := buildPlainIPv4Packet(t, e2eInnerSrc, e2eInnerDst)
	captured := rig.roundTrip(frame, sid)
	verifyEncapTowardSID(t, captured, outerSrc, sid, e2eInnerSrc, e2eInnerDst)
	t.Logf("captured %d-byte SRv6-encapsulated packet on the wire", len(captured))
}

// SR Policy steering parameters for the on-wire compose test. The
// transport SID is the outer destination after composition; vrx owns its
// /64 so the redirected packet routes back out to the injector.
const (
	steerTransportSID = "fd00:1:1:7::100"
	steerVrxCIDR      = "fd00:1:1:7::1/64"
	steerPolicyID     = 42
)

// TestNetnsE2E_SteeredXdpComposeOnWire is the on-wire proof for color-based
// SR Policy steering: a headend entry stamped with a policy_id plus an
// sr_policy_map transport list is installed directly, then a plain IPv4
// packet is injected through the real XDP program. The composed packet
// must reach the wire SRv6-encapsulated toward the *transport* SID with an
// SRH carrying [service, transport] -- i.e. the compose result actually
// survives the real bpf_redirect path that BPF_PROG_TEST_RUN cannot
// exercise (it stops at XDP_PASS because its FIB lookup never resolves).
//
// Requires root (BPF collection load, netns, XDP attach).
func TestNetnsE2E_SteeredXdpComposeOnWire(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("load BPF collection (needs root): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mapOps := bpf.NewMapOperations(objs)

	serviceSID := netip.MustParseAddr(e2eServiceSID).As16()
	transportSID := netip.MustParseAddr(steerTransportSID).As16()

	// Headend entry: a single service SID, steered via policy_id. The XDP
	// program composes the transport list onto it at forwarding time.
	var segs [bpf.MaxSegments][bpf.IPv6AddrLen]uint8
	segs[0] = serviceSID
	entry := &bpf.HeadendEntry{
		Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		NumSegments: 1,
		PolicyId:    steerPolicyID,
		SrcAddr:     netip.MustParseAddr(e2eLocatorPfx).As16(),
		DstAddr:     serviceSID,
		Segments:    segs,
	}
	if err := mapOps.CreateHeadendV4(e2eVPNPrefix, entry, bpf.OwnerRPC); err != nil {
		t.Fatalf("CreateHeadendV4: %v", err)
	}
	if err := mapOps.UpsertSRPolicy(steerPolicyID, []netip.Addr{netip.MustParseAddr(steerTransportSID)}); err != nil {
		t.Fatalf("UpsertSRPolicy: %v", err)
	}

	rig := setupWireRig(t, objs.VinberoMain, steerVrxCIDR, net.ParseIP(steerTransportSID))

	frame := buildPlainIPv4Packet(t, e2eInnerSrc, e2eInnerDst)
	captured := rig.roundTrip(frame, transportSID)
	verifySteeredEncap(t, captured, netip.MustParseAddr(e2eLocatorPfx).As16(),
		transportSID, serviceSID, e2eInnerSrc, e2eInnerDst)
	t.Logf("captured %d-byte steered SRv6-encapsulated packet on the wire", len(captured))
}

// verifySteeredEncap asserts pkt is a composed H.Encaps output: outer IPv6
// (src = locator, dst = transport SID) followed by a 2-segment SRH whose
// list is [service, transport] (wire order is path-reverse), with the
// original inner IPv4 preserved.
func verifySteeredEncap(t *testing.T, pkt []byte, outerSrc, transportSID, serviceSID [16]byte, innerSrc, innerDst net.IP) {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Fatalf("encapsulated packet too short: %d bytes", len(pkt))
	}
	if v := pkt[ethHeaderLen] >> 4; v != 6 {
		t.Fatalf("outer IP version = %d, want 6 (IPv6)", v)
	}
	if got := pkt[ethHeaderLen+8 : ethHeaderLen+24]; !bytes.Equal(got, outerSrc[:]) {
		t.Errorf("outer IPv6 src = %x, want locator prefix %x", got, outerSrc)
	}
	if got := pkt[ethHeaderLen+24 : ethHeaderLen+ipv6HeaderLen]; !bytes.Equal(got, transportSID[:]) {
		t.Errorf("outer IPv6 dst = %x, want transport SID %x (steered first hop)", got, transportSID)
	}

	if nh := pkt[ethHeaderLen+6]; nh != uint8(layers.IPProtocolIPv6Routing) {
		t.Fatalf("outer IPv6 next header = %d, want 43 (SRH) for a 2-segment compose", nh)
	}
	srh := ethHeaderLen + ipv6HeaderLen
	if len(pkt) < srh+8+2*ipv6AddrLen {
		t.Fatalf("packet too short for a 2-segment SRH: %d bytes", len(pkt))
	}
	if rt := pkt[srh+2]; rt != 4 {
		t.Errorf("SRH routing type = %d, want 4 (SR)", rt)
	}
	// SRH stores segments in path-reverse order: [0] = last hop (service),
	// [1] = first hop (transport, == outer DA).
	if seg := pkt[srh+8 : srh+8+ipv6AddrLen]; !bytes.Equal(seg, serviceSID[:]) {
		t.Errorf("SRH segment[0] = %x, want service SID %x (last hop)", seg, serviceSID)
	}
	if seg := pkt[srh+8+ipv6AddrLen : srh+8+2*ipv6AddrLen]; !bytes.Equal(seg, transportSID[:]) {
		t.Errorf("SRH segment[1] = %x, want transport SID %x (first hop)", seg, transportSID)
	}

	inner := srh + (int(pkt[srh+1])+1)*8
	if len(pkt) < inner+20 {
		t.Fatalf("packet too short for inner IPv4: %d bytes", len(pkt))
	}
	if v := pkt[inner] >> 4; v != 4 {
		t.Errorf("inner IP version = %d, want 4 (original IPv4 preserved)", v)
	}
	if got := net.IP(pkt[inner+12 : inner+16]); !got.Equal(innerSrc.To4()) {
		t.Errorf("inner IPv4 src = %s, want %s", got, innerSrc)
	}
	if got := net.IP(pkt[inner+16 : inner+20]); !got.Equal(innerDst.To4()) {
		t.Errorf("inner IPv4 dst = %s, want %s", got, innerDst)
	}
}
