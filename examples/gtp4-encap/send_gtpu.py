#!/usr/bin/env python3
"""Send GTP-U/IPv4 test packets using scapy.

Usage:
  sudo ip netns exec gtp4-host1 python3 send_gtpu.py [--qfi QFI] [--teid TEID] [--count N]

Sends GTP-U/IPv4 packets from host1 to router1's trigger prefix (172.0.2.0/24).
Router1 running H.M.GTP4.D should convert these to SRv6.
"""
import argparse
import sys

try:
    from scapy.all import IP, UDP, ICMP, send, conf
    from scapy.contrib.gtp import GTPHeader, GTPPDUSessionContainer
except ImportError:
    print("ERROR: scapy is required. Install with: pip3 install scapy")
    sys.exit(1)

conf.verb = 0  # suppress scapy output


def build_gtpu_packet(outer_dst, teid, qfi, inner_src, inner_dst):
    """Build a GTP-U/IPv4 packet with optional PDU Session Container."""
    outer = IP(dst=outer_dst) / UDP(sport=2152, dport=2152)

    if qfi > 0:
        gtp = GTPHeader(teid=teid, E=1, next_ex=0x85) / \
              GTPPDUSessionContainer(type=0, QFI=qfi)
    else:
        gtp = GTPHeader(teid=teid)

    inner = IP(src=inner_src, dst=inner_dst) / ICMP(id=0x1234, seq=1) / (b"A" * 32)

    return outer / gtp / inner


def main():
    parser = argparse.ArgumentParser(description="Send GTP-U test packets")
    parser.add_argument("--outer-dst", default="172.0.2.100",
                        help="Outer IPv4 destination (must match trigger prefix)")
    parser.add_argument("--teid", type=lambda x: int(x, 0), default=0x12345678,
                        help="GTP-U TEID (hex or decimal)")
    parser.add_argument("--qfi", type=int, default=9,
                        help="QoS Flow Identifier (0 = no PSC extension)")
    parser.add_argument("--inner-src", default="10.0.0.1",
                        help="Inner IPv4 source")
    parser.add_argument("--inner-dst", default="10.0.0.2",
                        help="Inner IPv4 destination")
    parser.add_argument("--count", type=int, default=3,
                        help="Number of packets to send")
    args = parser.parse_args()

    pkt = build_gtpu_packet(args.outer_dst, args.teid, args.qfi,
                            args.inner_src, args.inner_dst)

    print(f"Sending {args.count} GTP-U packets:")
    print(f"  Outer dst: {args.outer_dst}")
    print(f"  TEID: 0x{args.teid:08X}")
    print(f"  QFI: {args.qfi} ({'with PSC' if args.qfi > 0 else 'no PSC (4G mode)'})")
    print(f"  Inner: {args.inner_src} -> {args.inner_dst}")
    print()

    pkt.show2()
    print()

    send(pkt, count=args.count)
    print(f"Sent {args.count} packets.")


if __name__ == "__main__":
    main()
