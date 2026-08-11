package prober

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ipv6HeaderLen = 40
	srhFixedLen   = 8
	// ICMPv6 echo header plus the 8-byte cookie payload.
	icmpv6EchoLen   = 16
	protoRouting    = 43
	protoICMPv6     = 58
	icmpv6EchoReq   = 128
	icmpv6EchoReply = 129
	srhTypeSegment  = 4
)

// rawWire sends hand-built {IPv6, SRH, ICMPv6 echo} packets on an
// IPPROTO_RAW socket -- full control over the SRH, no dependence on
// per-socket extension-header options -- and reads echo replies from an
// ICMPv6 raw socket with a kernel-side filter that passes nothing else.
type rawWire struct {
	sendFD int
	recvFD int
	src    netip.Addr
	closed atomic.Bool
}

func newRawWire(src netip.Addr) (*rawWire, error) {
	// The same global-unicast bar as probe destinations: replies must come
	// back as plain routable IPv6, which a link-local, loopback or
	// multicast source can never receive from a remote PE.
	if !probeable(src) {
		return nil, fmt.Errorf("probe source %q is not a routable IPv6 unicast address", src)
	}
	sendFD, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket: %w", err)
	}
	// A send must never wedge the probe loop (or shutdown) indefinitely.
	stv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(sendFD, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &stv); err != nil {
		_ = unix.Close(sendFD)
		return nil, fmt.Errorf("send timeout: %w", err)
	}
	recvFD, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		_ = unix.Close(sendFD)
		return nil, fmt.Errorf("recv socket: %w", err)
	}
	// Block everything but echo replies, in the kernel.
	var filt unix.ICMPv6Filter
	for i := range filt.Data {
		filt.Data[i] = ^uint32(0)
	}
	filt.Data[icmpv6EchoReply>>5] &^= 1 << (icmpv6EchoReply & 31)
	if err := unix.SetsockoptICMPv6Filter(recvFD, unix.IPPROTO_ICMPV6, unix.ICMPV6_FILTER, &filt); err != nil {
		_ = unix.Close(sendFD)
		_ = unix.Close(recvFD)
		return nil, fmt.Errorf("icmp6 filter: %w", err)
	}
	// A receive timeout lets the read loop notice close(): a raw fd blocked
	// in Recvfrom is outside the runtime netpoller, so closing the fd would
	// not reliably wake it.
	tv := unix.Timeval{Usec: 500000}
	if err := unix.SetsockoptTimeval(recvFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(sendFD)
		_ = unix.Close(recvFD)
		return nil, fmt.Errorf("recv timeout: %w", err)
	}
	return &rawWire{sendFD: sendFD, recvFD: recvFD, src: src}, nil
}

func (w *rawWire) send(t Target, token uint16, seq uint16, cookie uint64) error {
	if w.closed.Load() {
		return fmt.Errorf("prober wire is closed")
	}
	pkt, firstHop := buildEchoRequest(w.src, t, token, seq, cookie)
	sa := &unix.SockaddrInet6{Addr: firstHop.As16()}
	if err := unix.Sendto(w.sendFD, pkt, 0, sa); err != nil {
		return fmt.Errorf("sendto %s: %w", firstHop, err)
	}
	return nil
}

// recv blocks for the next echo reply and returns its identifier,
// sequence, cookie, and source address. ok is false once the socket is
// closed; transient errors are absorbed.
func (w *rawWire) recv() (token, seq uint16, cookie uint64, from netip.Addr, ok bool) {
	buf := make([]byte, 256)
	for {
		if w.closed.Load() {
			return 0, 0, 0, netip.Addr{}, false
		}
		n, sa, err := unix.Recvfrom(w.recvFD, buf, 0)
		if err != nil {
			switch err {
			case unix.EINTR, unix.EAGAIN:
				continue
			default:
				if w.closed.Load() {
					return 0, 0, 0, netip.Addr{}, false
				}
				// Unexpected but survivable; do not burn a core on a
				// persistent error.
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		// An ICMPv6 raw socket delivers the ICMPv6 header onward.
		if n < icmpv6EchoLen || buf[0] != icmpv6EchoReply {
			continue
		}
		src := netip.Addr{}
		if in6, isV6 := sa.(*unix.SockaddrInet6); isV6 {
			src = netip.AddrFrom16(in6.Addr)
		}
		return binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint64(buf[8:16]), src, true
	}
}

// close only flags the wire: the receive loop wakes on its socket
// timeout within 500ms and the send path refuses new work, so both
// loops drain without the descriptors going away under them.
func (w *rawWire) close() {
	w.closed.Store(true)
}

// release frees the descriptors. Only safe once every loop using them
// has returned.
func (w *rawWire) release() {
	_ = unix.Close(w.sendFD)
	_ = unix.Close(w.recvFD)
}

// buildEchoRequest renders the probe packet and returns it with the
// first-hop address the kernel must route it towards.
//
// With transport segments the packet is {IPv6, SRH, ICMPv6}: the IPv6
// destination is the first segment and the SRH carries the full list in
// RFC 8754 order (Segment List[0] = the final destination, the probe
// target). Without segments it degrades to a plain echo straight to the
// target. The ICMPv6 checksum's pseudo-header uses the FINAL destination,
// as RFC 8200 requires in the presence of a routing header.
func buildEchoRequest(src netip.Addr, t Target, token, seq uint16, cookie uint64) ([]byte, netip.Addr) {
	journey := append(append([]netip.Addr{}, t.Segments...), t.Dst)
	firstHop := journey[0]

	srhLen := 0
	if len(journey) > 1 {
		srhLen = srhFixedLen + 16*len(journey)
	}
	payloadLen := srhLen + icmpv6EchoLen
	pkt := make([]byte, ipv6HeaderLen+payloadLen)

	// IPv6 header.
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	nh := byte(protoICMPv6)
	if srhLen > 0 {
		nh = protoRouting
	}
	pkt[6] = nh
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], src.AsSlice())
	copy(pkt[24:40], firstHop.AsSlice())

	// SRH: Segment List[0] is the last segment, Segment List[n-1] the
	// first; Segments Left points at the next segment to visit.
	off := ipv6HeaderLen
	if srhLen > 0 {
		srh := pkt[off : off+srhLen]
		srh[0] = protoICMPv6
		srh[1] = byte((srhLen - 8) / 8)
		srh[2] = srhTypeSegment
		srh[3] = byte(len(journey) - 1) // segments left
		srh[4] = byte(len(journey) - 1) // last entry
		for i, hop := range journey {
			// journey[0] (first hop) lands at the end of the list.
			copy(srh[srhFixedLen+16*(len(journey)-1-i):], hop.AsSlice())
		}
		off += srhLen
	}

	// ICMPv6 echo request with the round's cookie as payload.
	echo := pkt[off:]
	echo[0] = icmpv6EchoReq
	binary.BigEndian.PutUint16(echo[4:6], token)
	binary.BigEndian.PutUint16(echo[6:8], seq)
	binary.BigEndian.PutUint64(echo[8:16], cookie)
	binary.BigEndian.PutUint16(echo[2:4], icmpv6Checksum(src, t.Dst, echo))

	return pkt, firstHop
}

// icmpv6Checksum computes the ICMPv6 checksum over the pseudo-header
// {src, finalDst, len, next-header} and the message.
func icmpv6Checksum(src, dst netip.Addr, msg []byte) uint16 {
	var sum uint32
	add16 := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add16(s[:])
	add16(d[:])
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(msg)))
	add16(ln[:])
	add16([]byte{0, 0, 0, protoICMPv6})
	add16(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
