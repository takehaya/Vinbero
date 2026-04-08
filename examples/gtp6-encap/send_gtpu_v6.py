#!/usr/bin/env python3
"""Send GTP-U/IPv6 test packets using scapy.

Usage:
  sudo ip netns exec gtp6-host1 python3 send_gtpu_v6.py [--qfi QFI] [--teid TEID]

Sends a plain IPv6/UDP/GTP-U packet to the specified destination SID.
Note: This sends a direct GTP-U/IPv6 packet WITHOUT an SRH. For full SRv6+GTP-U
testing with SRH, an SRH-aware packet generator is needed.
"""
import argparse
import sys

try:
    from scapy.all import IPv6, UDP, ICMPv6EchoRequest, send, conf, raw
    from scapy.contrib.gtp import GTPHeader, GTPPDUSessionContainer
    from scapy.layers.inet6 import IPv6ExtHdrRouting
except ImportError:
    print("ERROR: scapy is required. Install with: pip3 install scapy")
    sys.exit(1)

conf.verb = 0


def main():
    parser = argparse.ArgumentParser(description="Send GTP-U/IPv6 test packets")
    parser.add_argument("--src", default="fd00:1::1")
    parser.add_argument("--dst", default="fc00:1::1", help="SID of End.M.GTP6.D")
    parser.add_argument("--teid", type=lambda x: int(x, 0), default=0xAABBCCDD)
    parser.add_argument("--qfi", type=int, default=5)
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()

    # Build inner packet
    inner = IPv6(src="fd00:10::1", dst="fd00:10::2") / ICMPv6EchoRequest() / (b"B" * 32)

    # Build GTP-U
    if args.qfi > 0:
        gtp = GTPHeader(teid=args.teid, E=1, next_ex=0x85) / \
              GTPPDUSessionContainer(type=0, QFI=args.qfi)
    else:
        gtp = GTPHeader(teid=args.teid)

    # Build outer IPv6 + SRH + UDP + GTP-U
    # Note: SRH with segments is complex in scapy. Use plain IPv6 + UDP for simplicity.
    pkt = IPv6(src=args.src, dst=args.dst) / \
          UDP(sport=2152, dport=2152) / gtp / raw(inner)

    print(f"Sending {args.count} GTP-U/IPv6 packets:")
    print(f"  Dst SID: {args.dst}")
    print(f"  TEID: 0x{args.teid:08X}, QFI: {args.qfi}")
    print()

    send(pkt, count=args.count)
    print(f"Sent {args.count} packets.")


if __name__ == "__main__":
    main()
