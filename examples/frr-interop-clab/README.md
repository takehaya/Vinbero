# FRR ⇄ Vinbero — BGP SRv6 L3VPN interop (containerlab)

A [containerlab](https://containerlab.dev/) lab that peers **Vinbero**
with **FRRouting** — an independent, mature BGP implementation — and
verifies a complete SRv6 L3VPN: both the **control plane** (VPNv4 /
VPNv6 routes carrying RFC 9252 SRv6 Service TLVs, exchanged both ways)
and the **data plane** (a real `ping` between a customer host and FRR's
customer, riding the SRv6 L3VPN end to end).

The lab proves two things:

* **Protocol interop** — Vinbero's RFC 9252 SRv6 Service TLV **encode**
  and **decode** are wire-compatible with a different implementation.
* **Data-plane interop** — Vinbero's XDP **H.Encaps** and **End.DT4**
  decap interoperate with FRR's native `seg6` dataplane, so customer
  traffic actually flows over the L3VPN in both directions.

## Topology

```
   ce (host)            vinbero (PE, under test)        frr (remote PE, RFC impl)
 +---------+  veth     +----------------------+  veth  +---------------------+
 | traffic |<--------->| eth2          eth1   |<------>| eth1   bgpd (FRR)   |
 | source  |  eth1     |   vinberod --bgp     |  BGP   | SRv6 locator +      |
 +---------+           |   in-proc speaker    | VPNv4/6| VPNv4/VPNv6 export  |
                       +----------------------+        +---------------------+
```

| Node      | AS     | Role                                                       |
|-----------|--------|------------------------------------------------------------|
| `vinbero` | 65100  | PE under test. `vinberod --bgp-enabled`, XDP on eth1+eth2. |
| `frr`     | 65200  | Remote PE. FRR 10.2.1, SRv6 locator + VPN export.          |
| `ce`      | —      | Customer host. Plaintext IPv4 source/sink for the L3VPN.   |

The BGP session runs over the IPv6 link `2001:db8:ff::/64`.

* Vinbero locator block: `fd00:100::/48` (encap source for learned routes)
* FRR locator block: `fd00:200::/64` (its VPN service SIDs)
* CE customer subnet: `10.0.0.0/24` (CE host `10.0.0.10`)
* FRR customer subnet: `10.200.0.0/24` (FRR `cust0` `10.200.0.1`, in `vrf-cust`)

## Data-plane path

Both PEs are full SRv6 L3VPN PEs: each H.Encaps plaintext customer
traffic and runs a decap endpoint for the return direction. The CE and
FRR's customer reach each other purely over the `2001:db8:ff::/64`
underlay — every customer packet rides SRv6.

```
CE -> FRR direction:
  CE 10.0.0.10 --IPv4--> vinbero eth2
    vinbero XDP H.Encaps -> outer IPv6 dst = FRR service SID (fd00:200::)
    kernel forwards out eth1 --SRv6--> frr eth1
    frr seg6 End.DT4 decaps into vrf-cust -> cust0 10.200.0.1

FRR -> CE direction (return):
  frr cust0 10.200.0.1 --IPv4--> vrf-cust
    frr H.Encaps -> outer IPv6 dst = Vinbero service SID (fd00:100:0:1::)
    --SRv6--> vinbero eth1
    vinbero XDP End.DT4 decaps, FIB lookup in vrf-cust table 100 -> eth2
    --IPv4--> CE 10.0.0.10
```

Control-plane glue that makes the data plane work:

* Vinbero attaches XDP to **both** eth1 (End.DT4 decap of return
  traffic) and eth2 (H.Encaps of CE traffic), registers an `END_DT4`
  SID function at `fd00:100:0:1::`, and advertises the CE subnet
  `10.0.0.0/24` with `vbctl bgp advertise-vpn` (RT `65000:200`, so FRR's
  `vrf-cust` imports it).
* FRR auto-installs an `End.DT4` `seg6local` route for the SID it
  advertises. A static `End.DT4` localsid for the bare locator
  `fd00:200::` is also added because RFC 9252 SID-structure
  transposition means the SID *on the wire* is the bare locator, not
  FRR's transposed full SID.
* FRR carries Vinbero's locator block `fd00:100::/48` as a connected
  prefix so its BGP SRv6 nexthop validation accepts the route, plus a
  more-specific `/128` route so the encapsulated return traffic is
  forwarded to Vinbero rather than NDP-resolved on-link.

## Layout

```
examples/frr-interop-clab/
├── README.md
├── Dockerfile          # vinberod runtime image (multi-stage, example-local)
├── clab.yml            # containerlab topology
├── Makefile            # build / deploy / test / destroy
├── test.sh             # control-plane + data-plane assertions
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
4. **Data plane (bidirectional ping)** — a real `ping` succeeds both
   ways between the CE host (`10.0.0.10`) and FRR's customer
   (`10.200.0.1` in `vrf-cust`), proving Vinbero's XDP H.Encaps /
   End.DT4 decap interoperate with FRR's `seg6` dataplane over the
   SRv6 L3VPN.

A passing run prints `RESULT: 11 passed, 0 failed`.

## Expected output (excerpt)

```
[2] FRR -> Vinbero  (SRv6 Service TLV decode)
  PASS: FRR VPNv4 route 10.200.0.0/24 installed in Vinbero headend-v4 map
      TRIGGER PREFIX  MODE      SRC ADDR    SEGMENTS
      10.200.0.0/24   H_ENCAPS  fd00:100::  fd00:200::
  PASS: SRv6 service SID matches end-to-end: FRR=fd00:200::  Vinbero=fd00:200::

[3] Vinbero -> FRR  (SRv6 Service TLV encode)
  PASS: FRR RIB has 10.100.0.0/24 with SRv6 SID fd00:100:0:1::

[4] Data plane  (SRv6 L3VPN ping, both directions)
  PASS: CE (10.0.0.10) -> FRR customer (10.200.0.1) ping over SRv6 L3VPN
      3 packets transmitted, 3 packets received, 0% packet loss
  PASS: FRR customer (10.200.0.1) -> CE (10.0.0.10) ping over SRv6 L3VPN
      3 packets transmitted, 3 packets received, 0% packet loss
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
* **SID-structure transposition.** FRR advertises its VPNv4 service SID
  with an RFC 9252 SID-structure sub-sub-TLV: the function bits are
  carried transposed in the MPLS label, so the SID *on the wire* is the
  bare locator `fd00:200::` while FRR's own `seg6local` localsid sits at
  the transposed full SID `fd00:200:0:0:1::`. Vinbero decodes (and
  encaps towards) the on-wire SID as-is, so `frr/start.sh` adds an extra
  static `End.DT4` localsid for `fd00:200::` to decap what Vinbero sends.
* **FRR SRv6 nexthop validation.** FRR will not install a VPN route
  whose service SID resolves only via a gateway (`show bgp nexthop`
  reports `Must be Connected`). `frr/start.sh` therefore carries
  Vinbero's locator block `fd00:100::/48` as a connected prefix on
  `eth1`, plus a more-specific `/128` route so the encapsulated return
  traffic is still forwarded to Vinbero.
* The return-path `End.DT4` localsid on FRR uses `vrftable`, which the
  kernel only accepts with `net.vrf.strict_mode=1` — set in
  `frr/start.sh`.
