#!/usr/bin/env python3
"""Send GTP-U/IPv4 (G-PDU) uplink packets from the emulated gNB.

Standard-library only (no scapy), so it runs in a bare alpine container. The
outer IPv4/UDP is built by the kernel via a UDP socket bound to port 2152; the
GTP-U header and the inner IPv4/ICMP packet are constructed by hand.

  gNB -> <n3-endpoint>:2152  GTP-U(TEID) [ inner: <inner-src> -> <inner-dst> ICMP ]

The MUP access gateway's H.M.GTP4.D_TEID gate + F-TEID entry transform this into
SRv6 toward the direct segment; End.DT4 on the data gateway decaps it to the DN.
"""
import argparse
import socket
import struct


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_inner_ipv4_icmp(src: str, dst: str, payload: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + payload  # echo request
    icmp = struct.pack("!BBHHH", 8, 0, checksum(icmp), 0x1234, 1) + payload

    total_len = 20 + len(icmp)
    ihl_ver, tos, ident, flags_frag, ttl, proto = 0x45, 0, 0, 0, 64, 1
    hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, total_len, ident,
                      flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, total_len, ident,
                      flags_frag, ttl, proto, checksum(hdr),
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + icmp


def build_gtpu(teid: int, inner: bytes) -> bytes:
    # flags: version=1 (0x20) | PT=1 (0x10) = 0x30; no optional/extension header.
    # msg type 0xFF = G-PDU; length covers everything after the 8-byte header.
    return struct.pack("!BBHI", 0x30, 0xFF, len(inner), teid) + inner


def main():
    p = argparse.ArgumentParser(description="Send GTP-U/IPv4 uplink test packets")
    p.add_argument("--n3-endpoint", default="172.16.0.254",
                   help="N3/UPF outer IPv4 destination (the access gateway)")
    p.add_argument("--teid", type=lambda x: int(x, 0), default=0x100,
                   help="GTP-U TEID (hex or decimal)")
    p.add_argument("--inner-src", default="10.1.0.1", help="UE IP (inner src)")
    p.add_argument("--inner-dst", default="10.0.0.1", help="DN IP (inner dst)")
    p.add_argument("--count", type=int, default=3)
    args = p.parse_args()

    inner = build_inner_ipv4_icmp(args.inner_src, args.inner_dst, b"MUP-UPLINK" + b"A" * 22)
    pkt = build_gtpu(args.teid, inner)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 2152))  # GTP-U source port 2152
    print("Sending %d GTP-U packets: dst=%s:2152 TEID=0x%08X inner %s->%s" %
          (args.count, args.n3_endpoint, args.teid, args.inner_src, args.inner_dst))
    for _ in range(args.count):
        s.sendto(pkt, (args.n3_endpoint, 2152))
    s.close()
    print("done")


if __name__ == "__main__":
    main()
