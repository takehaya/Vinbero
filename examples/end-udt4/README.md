# end-udt4 — uDT4 (End.DT4 as the last uSID)

*(日本語: [README.ja.md](./README.ja.md))*

Exercises uDT4: End.DT4 placed as the last uSID of a NEXT-C-SID container
(RFC 9800, F3216). There is no dedicated uDT4 action in Vinbero -- the
existing END_DT4 registered at the zero-padded /128
(fd00:aaaa:b003:d004::) wins the LPM over the uN /48 on the same node.
This example is the end-to-end proof of that property, first against the
Linux kernel oracle and then with Vinbero XDP.

See [`docs/design/ja/usid.md`](../../docs/design/ja/usid.md) for the design.

## Topology

```mermaid
graph LR
    host1 --- router1
    router1 --- router2
    router2 --- router3
    router3 --- host2
    router3 -.vrf100.- host2
```

- router1 pushes the forward container with Linux seg6 encap, and
  terminates the return direction on fc00:1::1 (End.DX4)
- router2 is plain IPv6 transit
- router3 holds both the uN /48 (fd00:aaaa:b003::/48) and the uDT4 /128
  (fd00:aaaa:b003:d004::, End.DT4 into vrf100). Phase 1 serves both from
  Linux seg6local, phase 2 from Vinbero

## Requirements

- Linux kernel 6.1 or later (seg6local next-csid flavor, VRF)
- iproute2 6.0 or later

## Usage

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## What is verified

1. Linux oracle: with both the /48 and the /128 installed, the container
   fd00:aaaa:b003:d004:: is delivered into vrf100 -- the zero-padded /128
   wins the longest-prefix match over the uN /48
2. Vinbero: the native routes are removed, END_UN (/48) and END_DT4
   (/128, vrf100) are registered through the API, and the same container
   is delivered again
3. Vinbero only: the two-uSID container fd00:aaaa:b003:b003:d004::. The
   uN shifts once and the shifted DA lands on this node's own uDT4 /128.
   Vinbero re-dispatches that hand-off inside the XDP loop; Linux
   seg6local cannot forward a shifted DA back into its own local SID, so
   the oracle phase never sees this container

## Notes

uDT6 and uDT46 differ from this example only in the inner address family,
and uDX4/uDX6 only in using a configured nexthop instead of a VRF table:
all of them are the existing End.* behaviors registered at a zero-padded
/128, exactly like the END_DT4 here.
