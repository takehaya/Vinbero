# FRR ⇄ Vinbero — BGP SRv6 L3VPN interop (containerlab)

A [containerlab](https://containerlab.dev/) lab that peers **Vinbero**
with **FRRouting** — an independent, mature BGP implementation — and
verifies they exchange SRv6 L3VPN service routes (VPNv4 / VPNv6 carrying
RFC 9252 SRv6 Service TLVs) **in both directions**.

The point of this example is *protocol* interop: proving Vinbero's
RFC 9252 SRv6 Service TLV **encode** and **decode** are wire-compatible
with a different implementation. Data-plane SRv6 encapsulation itself is
already covered by the netns end-to-end test
(`TestNetnsE2E_VPNv4XdpEncapOnWire`), so it is only an optional stretch
goal here.

## Topology

```
   ce (host)            vinbero (PE, under test)        frr (remote PE, RFC impl)
 +---------+  veth     +----------------------+  veth  +---------------------+
 | traffic |<--------->| eth2          eth1   |<------>| eth1   bgpd (FRR)   |
 | source  |  eth1     |   vinberod --bgp     |  BGP   | SRv6 locator +      |
 +---------+           |   in-proc speaker    | VPNv4/6| VPNv4/VPNv6 export  |
                       +----------------------+        +---------------------+
```

| Node      | AS     | Role                                                    |
|-----------|--------|---------------------------------------------------------|
| `vinbero` | 65100  | PE under test. `vinberod --bgp-enabled`, XDP data plane.|
| `frr`     | 65200  | Remote PE. FRR 10.2.1, SRv6 locator + VPN export.       |
| `ce`      | —      | Plaintext traffic source (data-plane stretch goal only).|

The BGP session runs over the IPv6 link `2001:db8:ff::/64`.

* Vinbero locator block: `fd00:100::/48` (encap source for learned routes)
* FRR locator block: `fd00:200::/64` (its VPN service SIDs)

## Layout

```
examples/frr-interop-clab/
├── README.md
├── Dockerfile          # vinberod runtime image (multi-stage, example-local)
├── clab.yml            # containerlab topology
├── Makefile            # build / deploy / test / destroy
├── test.sh             # bidirectional route-exchange assertions
├── frr/
│   ├── Dockerfile      # FRR image (quay.io/frrouting/frr:10.2.1 pinned)
│   ├── daemons         # zebra + bgpd
│   ├── frr.conf        # SRv6 locator + VPNv4/VPNv6 export
│   └── start.sh        # creates the customer VRF, starts FRR
└── vinbero/
    ├── vinbero.yml     # bgp: section — peer = frr, families = vpnv4/vpnv6
    └── start.sh        # starts vinberod, registers the SRv6 source locator
```

This lab is intentionally independent of the netns shell examples
(`examples/common/`, `examples/run_all.sh`): it needs Docker, privileged
containers and the `containerlab` binary, which the netns examples do
not.

## Prerequisites

* Docker
* [containerlab](https://containerlab.dev/install/)
* `sudo` (containerlab needs it)
* `python3` (test.sh parses vtysh JSON)

The Vinbero runtime image is built straight from the repo — the BPF
objects are committed under `pkg/bpf/` and embedded via `go:embed`, so
no `make bpf-gen` is required.

## Run

```bash
make build      # build the vinberod + FRR images
make deploy     # bring the 3-node topology up
make test       # assert bidirectional SRv6 L3VPN interop
make destroy    # tear the lab down

make all        # build + deploy + test + destroy in one shot
```

`make status` / `make logs` dump BGP and daemon state for debugging.

## What `test.sh` verifies

1. **BGP session ESTABLISHED** — on the FRR side (`show bgp summary
   json`) and confirmed on the Vinbero side from the daemon log.
2. **FRR → Vinbero (decode)** — FRR exports its customer VRF prefixes
   (`10.200.0.0/24`, `fd00:c200::/64`) as VPNv4 / VPNv6 routes with an
   SRv6 service SID. Vinbero decodes the SRv6 Service TLV and installs
   the routes into its `headend_v4` / `headend_v6` maps; `vbctl headend-*
   list` shows the SID as the encap segment list.
3. **Vinbero → FRR (encode)** — `vbctl bgp advertise-vpn` advertises
   VPNv4 / VPNv6 routes (`10.100.0.0/24`, `fd00:c100::/64`) with explicit
   SRv6 SIDs. They appear in FRR's VPN RIB (`show bgp ipv4/ipv6 vpn`)
   with the SRv6 SID intact (`Remote SID: …`).

A passing run prints `RESULT: 9 passed, 0 failed`.

## Expected output (excerpt)

```
[2] FRR -> Vinbero  (SRv6 Service TLV decode)
  PASS: FRR VPNv4 route 10.200.0.0/24 installed in Vinbero headend-v4 map
      TRIGGER PREFIX  MODE      SRC ADDR    SEGMENTS
      10.200.0.0/24   H_ENCAPS  fd00:100::  fd00:200::
  PASS: SRv6 service SID matches end-to-end: FRR=fd00:200::  Vinbero=fd00:200::

[3] Vinbero -> FRR  (SRv6 Service TLV encode)
  PASS: FRR RIB has 10.100.0.0/24 with SRv6 SID fd00:100:0:1::
```

## Notes

* **FRR version is pinned** (`quay.io/frrouting/frr:10.2.1`). FRR's SRv6
  L3VPN syntax is version-sensitive; `frr/frr.conf` follows the
  structure of the upstream `bgp_srv6l3vpn_over_ipv6` topotest — the
  SRv6 locator is attached to the *default* BGP instance and each VRF
  instance carries `sid vpn export <index>` per address-family. Bump the
  tag only together with a `frr.conf` review.
* The customer VRF (`vrf-cust`) and its dummy port are created by
  `frr/start.sh` **before** FRR loads its config — zebra binds to
  existing devices, it does not create the VRF master itself.
* Vinbero's BGP applier needs the SRv6 *source locator* registered
  before learned VPN routes can become headend entries;
  `vinbero/start.sh` does this with `vbctl locator create` right after
  the daemon comes up.
* XDP attaches in **generic** mode — containerlab veth links do not
  support native XDP.
