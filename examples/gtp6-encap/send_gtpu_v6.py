#!/usr/bin/env python3
"""Send an SRv6 packet carrying GTP-U to an End.M.GTP6.D SID, using scapy.

Usage:
  sudo ip netns exec gtp6-host1 python3 send_gtpu_v6.py \
      [--sid SID] [--next-seg SID] [--teid TEID] [--qfi QFI] [--count N]

Vinbero's End.M.GTP6.D processes the GTP-U tunnel carried *inside* an SRv6
packet, not a bare GTP-U/IPv6 tunnel. The on-the-wire shape it expects is:

  [IPv6(DA=sid)][SRH(nh=UDP, SL=1, segs=[next_seg, sid])][UDP:2152][GTP-U][inner]

so this builds exactly that. End.M.GTP6.D strips the UDP+GTP-U, advances the
SRH (SL->0, DA->next_seg with Args.Mob.Session encoded), and forwards the inner
packet over SRv6 toward next_seg (the End.M.GTP6.E SID).
"""
import argparse
import sys

try:
    from scapy.all import IPv6, UDP, IP, ICMP, send, conf, raw
    from scapy.contrib.gtp import GTPHeader, GTPPDUSessionContainer
    from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting
except ImportError:
    print("ERROR: scapy is required. Install with: apt-get install -y python3-scapy")
    sys.exit(1)

conf.verb = 0


def main():
    parser = argparse.ArgumentParser(description="Send SRv6-carried GTP-U test packets")
    parser.add_argument("--src", default="fc00:10::1")
    parser.add_argument("--sid", "--dst", dest="sid", default="fc00:1::1",
                        help="active SID = End.M.GTP6.D SID (IPv6 DA)")
    parser.add_argument("--next-seg", default="fc00:3::3",
                        help="next segment = End.M.GTP6.E SID")
    parser.add_argument("--teid", type=lambda x: int(x, 0), default=0xAABBCCDD)
    parser.add_argument("--qfi", type=int, default=5)
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()

    # Inner user packet carried inside GTP-U.
    inner = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(id=0x1234, seq=1) / (b"B" * 32)

    # GTP-U. gtp_type=0xFF marks a G-PDU (user data); gtpu_parse rejects anything
    # else and scapy defaults the field to 0, so it must be set explicitly.
    if args.qfi > 0:
        gtp = GTPHeader(teid=args.teid, gtp_type=0xFF, E=1, next_ex=0x85) / \
              GTPPDUSessionContainer(type=0, QFI=args.qfi)
    else:
        gtp = GTPHeader(teid=args.teid, gtp_type=0xFF)

    # SRH: segments [next_seg, sid] with segments_left=1, so the active segment
    # (the IPv6 DA) is sid; after End.M.GTP6.D it advances to next_seg. nh=17
    # (UDP) is set explicitly -- End.M.GTP6.D early-returns unless the SRH next
    # header is UDP, so do not rely on scapy's autocompletion of it.
    srh = IPv6ExtHdrSegmentRouting(addresses=[args.next_seg, args.sid],
                                   segleft=1, lastentry=1, nh=17)

    pkt = IPv6(src=args.src, dst=args.sid) / srh / \
        UDP(sport=2152, dport=2152) / gtp / raw(inner)

    print(f"Sending {args.count} SRv6+GTP-U packets:")
    print(f"  Active SID (DA): {args.sid}  ->  next segment: {args.next_seg}")
    print(f"  TEID: 0x{args.teid:08X}, QFI: {args.qfi}")
    print()

    send(pkt, count=args.count)
    print(f"Sent {args.count} packets.")


if __name__ == "__main__":
    main()
