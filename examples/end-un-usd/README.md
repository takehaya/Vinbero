# end-un-usd — uN + USD (no-SRH decap)

*(日本語: [README.ja.md](./README.ja.md))*

Exercises the USD flavor on a uN (RFC 9800, F3216) at the end of a no-SRH
container. H.Encaps.Red with a single container emits no SRH, so the
classic USD handling (SRH present, SL=0) never applies; when such a
packet's DA is the bare uN SID and the entry carries the USD flavor,
Vinbero strips the outer IPv6 and forwards the inner packet.

There is no Linux oracle phase: the kernel's seg6local End rejects
"flavors usd" (only PSP and NEXT-C-SID are implemented), so there is
nothing native to compare against. Delivery itself is the proof: without
USD the still-encapsulated packet is handed to the kernel and never
reaches the destination.

See [`docs/design/ja/usid.md`](../../docs/design/ja/usid.md) for the design.

## Topology

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

- router1 pushes the single-uSID container fd00:aaaa:b003:: with
  H.Encaps.Red (bare uN SID, no SRH, IPIP payload), and terminates the
  return direction on fc00:1::1 (End.DX4)
- router2 is plain IPv6 transit
- router3 is the uN with the USD flavor (Vinbero, fd00:aaaa:b003::/48):
  the outer IPv6 is stripped and the inner IPv4 is forwarded to host2

## Requirements

- iproute2 6.0 or later (encap.red)

## Usage

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## What is verified

1. The bare-SID, no-SRH packet is decapped at router3 and the inner IPv4
   reaches host2
2. The return direction works as a native baseline

PSP and USP have no no-SRH counterpart -- there is no SRH to pop -- so USD
is the only flavor with dedicated handling on this path. With an SRH
present, all three flavors already apply through the classic End
fall-through (see `examples/end-un/`).
