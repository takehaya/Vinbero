#!/usr/bin/env python3
"""Send a GTP-U/IPv6 packet to an H.M.GTP6.D trigger prefix, using scapy.

Usage:
  sudo ip netns exec gtp6-host1 python3 send_gtpu_v6.py \
      [--dst OUTER_DST] [--teid TEID] [--qfi QFI] [--count N]

H.M.GTP6.D is the IPv6 counterpart of H.M.GTP4.D: a headend that intercepts a
raw GTP-U/IPv6 tunnel by its outer IPv6 destination and rewrites it into SRv6.
So this sends a plain IPv6/UDP/GTP-U packet (no SRH) whose outer IPv6 dst falls
in the H.M.GTP6.D trigger prefix; router1 converts it to SRv6 toward the
End.M.GTP6.E SID.
"""
import argparse
import sys

try:
    from scapy.all import IPv6, UDP, ICMPv6EchoRequest, send, conf, raw
    from scapy.contrib.gtp import GTPHeader, GTPPDUSessionContainer
except ImportError:
    print("ERROR: scapy is required. Install with: apt-get install -y python3-scapy")
    sys.exit(1)

conf.verb = 0


def main():
    parser = argparse.ArgumentParser(description="Send GTP-U/IPv6 test packets")
    parser.add_argument("--src", default="fc00:10::1", help="outer IPv6 source (gNB)")
    parser.add_argument("--dst", default="2001:db8:caf::1",
                        help="outer IPv6 dst in the H.M.GTP6.D trigger prefix")
    parser.add_argument("--teid", type=lambda x: int(x, 0), default=0xAABBCCDD)
    parser.add_argument("--qfi", type=int, default=5)
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()

    # Inner user packet carried inside GTP-U.
    inner = IPv6(src="fd00:10::1", dst="fd00:10::2") / ICMPv6EchoRequest() / (b"B" * 32)

    # GTP-U. gtp_type=0xFF marks a G-PDU (user data); gtpu_parse rejects anything
    # else and scapy defaults the field to 0, so it must be set explicitly.
    if args.qfi > 0:
        gtp = GTPHeader(teid=args.teid, gtp_type=0xFF, E=1, next_ex=0x85) / \
              GTPPDUSessionContainer(type=0, QFI=args.qfi)
    else:
        gtp = GTPHeader(teid=args.teid, gtp_type=0xFF)

    pkt = IPv6(src=args.src, dst=args.dst) / \
        UDP(sport=2152, dport=2152) / gtp / raw(inner)

    print(f"Sending {args.count} GTP-U/IPv6 packets:")
    print(f"  Outer dst: {args.dst}")
    print(f"  TEID: 0x{args.teid:08X}, QFI: {args.qfi}")
    print()

    send(pkt, count=args.count)
    print(f"Sent {args.count} packets.")


if __name__ == "__main__":
    main()
