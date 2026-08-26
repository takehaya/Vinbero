# end-lbs — End.LBS (Locator-Block Swap)

*(日本語: [README.ja.md](./README.ja.md))*

Exercises End.LBS (RFC 9800 Sec.7.1): at a routing-domain boundary the
remaining C-SID sequence is re-homed from one locator block to another.
The behavior runs in the uN slot with the target block as a SID property
(`--target-block`); the shift composes the new DA on the target block
instead of in place.

There is no Linux oracle phase: seg6local implements neither End.LBS nor
the compressed-SID flavors it builds on. The proof is structural: block
A is blackholed past the boundary node, so only a swapped DA can reach
the terminal, which exists only in block B.

## Topology

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

- Block A is fd00:aaaa/32 (r1 side, blackholed past r2); block B is
  fd77:7777:7777/48 (r3 side)
- router1 pushes the single container fd00:aaaa:b002:d004:: with
  H.Encaps.Red and terminates the return direction on fc00:1::1
- router2 (Vinbero) holds End.LBS at fd00:aaaa:b002::/48 with target
  block fd77:7777:7777::/48: the argument (d004...) is copied onto the
  target block, producing fd77:7777:7777:d004::
- router3 terminates fd77:7777:7777:d004::/128 with Linux End.DX4

## Usage

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## What is verified

1. The forward ping is delivered through the block swap. A plain uN
   shift would produce the block-A DA fd00:aaaa:d004:: and die in
   router2's blackhole, so delivery pins the swap itself
2. The return direction works as a native baseline

End.XLBS and the REPLACE-CSID variants share the same aux property and
are covered by the data-plane unit tests (`pkg/bpf/xdp_lbs_test.go`).
