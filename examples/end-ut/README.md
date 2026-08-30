# end-ut — uT (End.T with NEXT-C-SID)

*(日本語: [README.ja.md](./README.ja.md))*

Exercises uT, the NEXT-C-SID flavor of End.T (RFC 9800 Sec.4.1.3, F3216):
the same 16-bit shift as uN, but the forwarding lookup after the shift
runs in the VRF table bound to the SID instead of the default FIB.

There is no Linux oracle phase: seg6local's next-csid flavor exists for
End and End.X only, so there is nothing native to compare uT against.
Instead the test proves the VRF binding directly -- the main table
blackholes the shifted destination, so a delivered ping is only possible
through table 100.

See [`docs/design/ja/usid.md`](../../docs/design/ja/usid.md) for the design.

## Topology

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
```

- router1 pushes the forward container fd00:aaaa:b002:b003:d004:: with
  H.Encaps.Red -- a single container emits no SRH, so router2's uT runs on
  the no-SRH dispatch path -- and terminates the return direction on
  fc00:1::1 (End.DX4)
- router2 is the uT (Vinbero, fd00:aaaa:b002::/48, vrf100). Table 100
  holds the only route towards fd00:aaaa:b003::/48; the main table
  blackholes it
- router3 terminates the forward direction on fd00:aaaa:b003:d004::/128
  (Linux End.DX4) and pushes the return container

## Requirements

- Linux kernel with VRF support
- iproute2 6.0 or later (encap.red)

## Usage

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## What is verified

1. The no-SRH container is shifted at router2 and forwarded via table
   100. The main-table blackhole guarantees the VRF table was consulted:
   plain uN behavior (default FIB) would drop the packet
2. The return direction works as a native baseline

uT is fail-closed on NO_NEIGH, unlike uN: the kernel cannot repeat a
VRF-scoped lookup for a packet that arrived on a non-VRF interface, so
setup.sh and test.sh pre-resolve NDP before sending traffic.
