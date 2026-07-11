#!/usr/bin/env python3
"""TRex stream driver for the Vinbero SRv6 dataplane benchmark.

Runs on the TRex host (lab-kiba-ocxma-trex-01). Transmits on port 0
toward the DUT ingress NIC and counts what the DUT forwards back into
port 1, so a single invocation yields offered load, forwarded load,
and loss for one cell.

Usage:
  vinbero_streams.py --scenario <name> --duration <sec> [--size N]
                     [--pps TOTAL] [--peers N]

Scenarios (ingress frame the DUT sees):
  encaps-v4   Ether/IPv4(dst 10.99.0.0/24)/UDP      -> T.Encaps v4 headend
  ecmp        same frames as encaps-v4              -> ECMP path-group headend
  end         Ether/IPv6(dst fc00:a::1)/SRH(SL=1)   -> End transit
  end-dt4     Ether/IPv6(dst fc00:a::d4)/SRH(SL=0)/IPv4(dst 10.98.0.0/24)/UDP
                                                    -> End.DT4 decap
  l2-unicast  Ether(unicast)/Dot1Q(100)/IPv4/UDP    -> H.Encaps.L2 (XDP path)
  bum         Ether(broadcast)/Dot1Q(100)/IPv4/UDP  -> BUM flood (TC path)

--size is the ingress wire frame length in bytes (without FCS); frames
are padded with zero payload up to it. Each scenario has a minimum
below which the value is clamped up.

Flow spread: NO STLScVmRaw randomization. TRex's field-engine VM
re-parses the frame, fails on the SRH (routing type 4), and silently
truncates it. Every scenario instead emits N_FLOWS static streams with
distinct source addresses/MACs, which spreads RSS on the DUT. SRH is
raw bytes; all packets go in via pkt_buffer.

Output: one JSON line with tx (port 0) and rx (port 1) counters plus
loss. For the bum scenario pass --peers so the expected amplification
factor is recorded alongside.
"""
import argparse
import json
import socket
import struct
import sys
import time

sys.path.insert(
    0, "/opt/trex/v3.08/scripts/automation/trex_control_plane/interactive")
from trex.stl.api import (  # noqa: E402
    Dot1Q, Ether, IP, IPv6, STLClient, STLPktBuilder, STLStream, STLTXCont,
    UDP)

SRC_MAC = "40:a6:b7:82:cd:d8"   # TRex port 0
DST_MAC = "40:a6:b7:95:a2:d0"   # DUT enp138s0f0

SID_END = "fc00:a::1"
SID_DT4 = "fc00:a::d4"
SEG_REMOTE = "fd00:c::1"
VLAN_ID = 100

N_FLOWS = 32


def ip6(a):
    return socket.inet_pton(socket.AF_INET6, a)


def srh_bytes(segs, segments_left, nh):
    # RFC 8754 SRH: nh, hdr_ext_len (8B units excl. first 8), routing
    # type 4, segments_left, last_entry, flags, tag, then 16B segments.
    body = b"".join(ip6(s) for s in segs)
    return struct.pack("!BBBBBBH", nh, len(body) // 8, 4, segments_left,
                       len(segs) - 1, 0, 0) + body


def pad(frame, size):
    return frame + b"\x00" * (size - len(frame)) if size > len(frame) else frame


def frame(scenario, i, size):
    src4 = "10.%d.0.%d" % (8 + i % 200, 2 + i // 200)
    if scenario in ("encaps-v4", "ecmp"):
        return pad(bytes(
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=src4, dst="10.99.0.%d" % (1 + i % 250))
            / UDP(sport=12345 + i, dport=9)), size)
    if scenario == "end":
        # DA = local End SID, SL=1 -> after End the DA becomes SEG_REMOTE
        # and the packet is routed out the egress port.
        udp = bytes(UDP(sport=12345 + i, dport=9))
        srh = srh_bytes([SEG_REMOTE, SID_END], segments_left=1, nh=17)
        inner_len = max(size - 14 - 40 - len(srh) - len(udp), 0)
        payload = b"\x00" * inner_len
        hdr = bytes(Ether(src=SRC_MAC, dst=DST_MAC)
                    / IPv6(src="2001:db8::%x:2" % i, dst=SID_END, nh=43,
                           plen=len(srh) + len(udp) + inner_len))
        return hdr + srh + udp + payload
    if scenario == "end-dt4":
        # DA = local End.DT4 SID, SL=0 -> decap, inner IPv4 is looked up
        # in the VRF table and routed out the egress port.
        srh = srh_bytes([SID_DT4], segments_left=0, nh=4)
        pad_len = max(size - 14 - 40 - len(srh) - 20 - 8, 0)
        inner = bytes(IP(src=src4, dst="10.98.0.%d" % (1 + i % 250))
                      / UDP(sport=12345 + i, dport=9)
                      / (b"\x00" * pad_len))
        hdr = bytes(Ether(src=SRC_MAC, dst=DST_MAC)
                    / IPv6(src="2001:db8::%x:2" % i, dst=SID_DT4, nh=43,
                           plen=len(srh) + len(inner)))
        return hdr + srh + inner
    if scenario in ("l2-unicast", "bum"):
        dst = "02:aa:00:00:00:01" if scenario == "l2-unicast" \
            else "ff:ff:ff:ff:ff:ff"
        return pad(bytes(
            Ether(src="02:bb:00:00:%02x:%02x" % (i >> 8, i & 0xFF), dst=dst)
            / Dot1Q(vlan=VLAN_ID)
            / IP(src=src4, dst="10.97.0.1")
            / UDP(sport=12345 + i, dport=9)), size)
    raise ValueError("unknown scenario: %s" % scenario)


def build_streams(scenario, size, per_stream_pps, flows):
    return [
        STLStream(packet=STLPktBuilder(pkt_buffer=frame(scenario, i, size)),
                  mode=STLTXCont(pps=per_stream_pps))
        for i in range(flows)
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["encaps-v4", "ecmp", "end", "end-dt4",
                             "l2-unicast", "bum"])
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--size", type=int, default=64,
                    help="ingress wire frame length in bytes (clamped up "
                         "to the scenario minimum)")
    ap.add_argument("--pps", type=float, default=0,
                    help="total offered pps across all flows; 0 (default) "
                         "offers 100%% of line rate")
    ap.add_argument("--flows", type=int, default=N_FLOWS,
                    help="number of static streams; more flows engage "
                         "more RSS queues (and DUT cores)")
    ap.add_argument("--peers", type=int, default=1,
                    help="bum only: configured bd peer count, recorded as "
                         "the expected amplification factor")
    args = ap.parse_args()

    c = STLClient(server="127.0.0.1")
    c.connect()
    c.acquire(ports=[0, 1], force=True)
    c.reset(ports=[0, 1])
    # mult scales the stream pps: "100%" normalizes the total to line
    # rate (ignoring the per-stream pps), while "1" honors --pps as-is.
    per_stream = (args.pps or 1e6) / args.flows
    mult = "1" if args.pps else "100%"
    c.add_streams(build_streams(args.scenario, args.size, per_stream,
                                args.flows),
                  ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult=mult)
    time.sleep(args.duration)
    c.stop(ports=[0])
    # Let in-flight frames drain into port 1 before the final read.
    time.sleep(1)
    stats = c.get_stats()
    tx = stats[0]
    rx = stats[1]

    def unwrap(v):
        # The port counters come from 32-bit hardware registers; when
        # the raw counter crosses 2^32 during the run the delta against
        # the clear_stats reference goes negative by exactly 2^32. A
        # 30s run at 100G wraps at most once, so one correction is exact.
        return v + 2**32 if v < 0 else v

    opackets = unwrap(tx.get("opackets", 0))
    ipackets = unwrap(rx.get("ipackets", 0))
    expected = opackets * (args.peers if args.scenario == "bum" else 1)
    print(json.dumps({
        "scenario":     args.scenario,
        "size":         args.size,
        "duration_s":   args.duration,
        "peers":        args.peers,
        "flows":        args.flows,
        "tx_opackets":  opackets,
        "tx_oerrors":   tx.get("oerrors", 0),
        "rx_ipackets":  ipackets,
        "rx_ibytes":    rx.get("ibytes", 0),
        "tx_mpps":      round(opackets / args.duration / 1e6, 3),
        "rx_mpps":      round(ipackets / args.duration / 1e6, 3),
        "tx_gbps":      round(tx.get("tx_bps", 0) / 1e9, 3),
        "loss_pct":     round((1.0 - ipackets / expected) * 100.0, 4)
                        if expected else 0.0,
    }))
    c.release(ports=[0, 1])
    c.disconnect()


if __name__ == "__main__":
    main()
