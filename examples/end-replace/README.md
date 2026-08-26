# end-replace — End with REPLACE-CSID

*(日本語: [README.ja.md](./README.ja.md))*

Exercises End with the REPLACE-CSID flavor (RFC 9800 Sec.4.2): packed
C-SID containers live in the SRH segment list, the DA's low Argument
bits carry the container index, and each endpoint replaces only the
C-SID part of the DA while walking the container.

There is no Linux oracle phase: seg6local implements only the
NEXT-C-SID flavor. Instead the C-SID sequence ping-pongs between two
Vinbero nodes, and the test asserts both delivery and the r2 -> r3
link's TX packet counter: delivery alone could not rule out a broken
index that jumps straight to the terminal C-SID, so the counter pins
the two crossings per echo.

See [`docs/design/ja/usid.md`](../../docs/design/ja/usid.md) for the design.

## Topology

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

C-SID plan (48-bit block fd00:aabb:ccdd, 32-bit C-SIDs, K=4):

- router2 (Vinbero): End(REP) at C-SIDs b2b2:1 and b2b2:2 (/80)
- router3 (Vinbero): End(REP) at C-SID b3b3:1 (/80)
- router3 (Linux): terminal End.DX4 at C-SID b3b3:d — the last C-SID of
  a REPLACE sequence can be any behavior, and it matches the block+C-SID
  /80 because the DA's argument bits vary

The sequence [b2b2:1 (DA), b3b3:1, b2b2:2, b3b3:d] packs into one
container (`0:0:b3b3:d:b2b2:2:b3b3:1`), so the packet crosses
r2 → r3 → r2 → r3 and exercises the container cross (Index 0 → K-1) at
router2 and two in-container replacements.

## Requirements

- iproute2 with seg6 encap support (the containers are ordinary segment
  list entries from the headend's point of view)

## Usage

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## What is verified

1. The forward ping is delivered and the r2 -> r3 TX counter grows by
   two crossings per echo, which together pin all four walk steps: a
   broken index that skipped the b2b2:2 step would still deliver but
   cross the link only once
2. The return direction works as a native baseline
