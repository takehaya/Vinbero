# FRR ⇄ Vinbero — BGP SRv6 L3VPN interop (containerlab)

A [containerlab](https://containerlab.dev/) lab that builds a textbook
**2-site SRv6 L3VPN** and peers **Vinbero** with **FRRouting** — an
independent, mature BGP implementation — as the two provider-edge
routers. It verifies a complete SRv6 L3VPN: both the **control plane**
(VPNv4 / VPNv6 routes carrying RFC 9252 SRv6 Service TLVs, exchanged
both ways over iBGP) and the **data plane** (a real `ping` between two
customer hosts, riding the SRv6 L3VPN end to end through both PEs and a
provider core).

The lab proves two things:

* **Protocol interop** — Vinbero's RFC 9252 SRv6 Service TLV **encode**
  and **decode** are wire-compatible with a different implementation,
  including the §4 SID-structure **transposition**.
* **Data-plane interop** — Vinbero's XDP **H.Encaps** and **End.DT4**
  decap interoperate with FRR's native `seg6` dataplane, so customer
  traffic actually flows over the L3VPN in both directions.

## Topology

```
 ce-tokyo --- pe-tokyo ===== core ===== pe-osaka --- ce-osaka
10.1.0.0/24  (Vinbero PE)  (IPv6 core)  (FRR PE)   10.2.0.0/24
```

| Node       | Role                                                              |
|------------|-------------------------------------------------------------------|
| `ce-tokyo` | Customer host, subnet `10.1.0.0/24`, host `10.1.0.10`.            |
| `pe-tokyo` | The Vinbero PE under test. `vinberod --bgp-enabled`, XDP.        |
| `core`     | Provider backbone — a plain IPv6 router, static routes, no IGP.  |
| `pe-osaka` | The FRR PE (interop peer). FRR 10.2.1, SRv6 locator + VPN export.|
| `ce-osaka` | Customer host, subnet `10.2.0.0/24`, host `10.2.0.10`.           |

### BGP design — iBGP within one provider AS

Both PEs are in **one provider AS (65100)** and run **iBGP** (VPNv4 +
VPNv6), peering on their **loopbacks** (`2001:db8:ff::1` /
`2001:db8:ff::2`). This is the textbook SRv6 L3VPN model: the PEs of a
single provider domain peer iBGP. iBGP is naturally multi-hop, so the
session crosses the core with **no `ebgp-multihop` knob**.

`core` is **not in BGP** — it only routes the IPv6 underlay so the two
PE loopbacks (and the SRv6 locator blocks) are mutually reachable. The
underlay uses **static routes, no IGP**, so there is no convergence race
that could make the data-plane test flaky.

### Addressing

* Underlay links: `2001:db8:1::/64` (pe-tokyo↔core),
  `2001:db8:2::/64` (core↔pe-osaka).
* PE loopbacks: `2001:db8:ff::1` (pe-tokyo), `2001:db8:ff::2` (pe-osaka).
* Vinbero SRv6 locator block: `fd00:100::/48`.
* FRR SRv6 locator block: `fd00:200::/48`.
* Customer subnets: `10.1.0.0/24` (Tokyo), `10.2.0.0/24` (Osaka), both
  in a single L3VPN / VRF so the two customers reach each other.

## Data-plane path

Both PEs are full SRv6 L3VPN PEs: each H.Encaps plaintext customer
traffic towards the far PE's service SID and runs an End.DT4 decap
endpoint for the return direction. The core forwards purely by the
**outer IPv6 header**.

```
ce-tokyo -> ce-osaka direction:
  ce-tokyo 10.1.0.10 --IPv4--> pe-tokyo eth2
    Vinbero XDP H.Encaps -> outer IPv6 dst = FRR service SID (fd00:200:0:1::)
    kernel forwards out eth1 --SRv6--> core --> pe-osaka
    FRR seg6 End.DT4 decaps into vrf-cust -> eth1 -> ce-osaka 10.2.0.10

ce-osaka -> ce-tokyo direction (return):
  ce-osaka 10.2.0.10 --IPv4--> pe-osaka eth1 (vrf-cust)
    FRR H.Encaps -> outer IPv6 dst = Vinbero service SID (fd00:100:0:1::)
    --SRv6--> core --> pe-tokyo eth1
    Vinbero XDP End.DT4 decaps, FIB lookup in vrf-cust table 100 -> eth2
    --IPv4--> ce-tokyo 10.1.0.10
```

Control-plane glue that makes the data plane work:

* Vinbero attaches XDP to **both** eth1 (End.DT4 decap of return
  traffic) and eth2 (H.Encaps of CE traffic), registers an `END_DT4`
  SID function at `fd00:100:0:1::`, and advertises the Tokyo subnet
  `10.1.0.0/24` with `vbctl bgp advertise-vpn` (RT `65000:200`, so FRR's
  `vrf-cust` imports it).
* FRR auto-installs an `End.DT4` `seg6local` route for the SID it
  advertises. Vinbero reconstructs that full SID from the bare on-wire
  locator by applying RFC 9252 §4 transposition (the function bits
  travel in the VPN label), so it encapsulates straight to FRR's real
  localsid — no lab-side workaround is needed.
* FRR carries Vinbero's locator block `fd00:100::/48` as a connected
  prefix so its BGP SRv6 nexthop validation accepts the route, plus a
  more-specific `/128` route so the encapsulated return traffic is
  forwarded onward to the core rather than NDP-resolved on-link.

## Layout

```
examples/frr-interop-clab/
├── README.md
├── Dockerfile          # vinberod runtime image (multi-stage, example-local)
├── clab.yml            # containerlab 5-node topology
├── Makefile            # build / deploy / test / destroy
├── test.sh             # control-plane + data-plane assertions (readiness-gated)
├── core/
│   └── start.sh        # plain IPv6 router, static underlay routes
├── frr/
│   ├── Dockerfile      # FRR image (quay.io/frrouting/frr:10.2.1 pinned)
│   ├── daemons         # zebra + bgpd
│   ├── frr.conf        # SRv6 locator + VPNv4/VPNv6 export + iBGP
│   └── start.sh        # creates the customer VRF, starts FRR
└── vinbero/
    ├── vinbero.yml     # bgp: section — iBGP peer = pe-osaka loopback
    └── start.sh        # starts vinberod, registers locator, advertises VPN
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
make deploy     # bring the 5-node topology up
make test       # assert bidirectional SRv6 L3VPN interop + ping
make destroy    # tear the lab down

make all        # build + deploy + test + destroy in one shot
```

`make status` / `make logs` dump BGP and daemon state for debugging.

## What `test.sh` verifies

1. **iBGP session ESTABLISHED** — on the FRR side (`show bgp summary
   json`) and confirmed on the Vinbero side from the daemon log.
2. **FRR → Vinbero (decode)** — FRR exports the `ce-osaka` subnet
   (`10.2.0.0/24`) as a VPNv4 route with an SRv6 service SID. Vinbero
   decodes the SRv6 Service TLV, applies the RFC 9252 §4 transposition,
   and installs the route into its `headend_v4` map with the full SID
   as the encap segment list.
3. **Vinbero → FRR (encode)** — `vbctl bgp advertise-vpn` advertises the
   `ce-tokyo` subnet (`10.1.0.0/24`) with an explicit SRv6 SID. It
   reaches FRR's VPN RIB (`Remote SID: …`) and FRR installs it into
   `vrf-cust` as an `encap seg6` route.
4. **Data plane (bidirectional ping)** — a real `ping` succeeds both
   ways between `ce-tokyo` (`10.1.0.10`) and `ce-osaka` (`10.2.0.10`),
   proving Vinbero's XDP H.Encaps / End.DT4 decap interoperate with
   FRR's `seg6` dataplane over the SRv6 L3VPN.

A passing run prints `RESULT: 8 passed, 0 failed`.

## Data-plane readiness gating

The SRv6 L3VPN data plane settles **asynchronously**: XDP attach, BGP
convergence, FRR's auto-installed `seg6` localsid and underlay NDP all
come up on their own clocks. To keep the data-plane test deterministic,
section 4 of `test.sh` does **not** ping until it has gated on every
precondition:

* both iBGP sessions `Established`;
* the learned VPN routes installed on both PEs (Vinbero `headend_v4`
  map + FRR `vrf-cust` kernel FIB);
* the decap endpoints present (Vinbero `END_DT4` SID function + FRR's
  `seg6local` localsid);
* the PE loopbacks mutually reachable through the core, and the
  customer-side ARP warmed.

Only once all gates pass does it `ping`, with a generous retry. A slow
data-plane settle therefore cannot produce a spurious `FAIL`.

## Notes

* **FRR version is pinned** (`quay.io/frrouting/frr:10.2.1`). FRR's SRv6
  L3VPN syntax is version-sensitive; `frr/frr.conf` follows the
  structure of the upstream `bgp_srv6l3vpn_over_ipv6` topotest — the
  SRv6 locator is attached to the *default* BGP instance and each VRF
  instance carries `sid vpn export <index>` per address-family. Bump the
  tag only together with a `frr.conf` review.
* The customer VRF (`vrf-cust`) is created by each PE's `start.sh`
  **before** the routing daemon loads its config — zebra / vinberod
  bind to existing devices, they do not create the VRF master.
* Vinbero's BGP applier needs the SRv6 *source locator* registered
  before learned VPN routes can become headend entries;
  `vinbero/start.sh` does this with `vbctl locator create` right after
  the daemon comes up.
* XDP attaches in **generic** mode — containerlab veth links do not
  support native XDP.
* **Loopback-sourced iBGP.** The session peers loopback-to-loopback.
  GoBGP sets no explicit `Transport.LocalAddress`, so `vinbero/start.sh`
  adds the static route to the peer loopback with a `src` hint, forcing
  the kernel to source the iBGP TCP connection from the loopback. FRR
  uses `neighbor … update-source lo` for the same effect.
* **SID-structure transposition.** FRR advertises its VPNv4 service SID
  with an RFC 9252 SID-structure sub-sub-TLV: the function bits are
  carried transposed in the MPLS label, so the SID *on the wire* is the
  bare locator `fd00:200::` while FRR's `seg6local` localsid sits at the
  transposed full SID `fd00:200:0:1::`. Vinbero's decoder
  (`pkg/bgp/gobgp/decode.go`) folds the label bits back per RFC 9252 §4
  and reconstructs the full SID. `test.sh` step 2 asserts it.
* **FRR SRv6 nexthop validation.** FRR will not install a VPN route
  whose service SID resolves only via a gateway (`show bgp nexthop`
  reports `Must be Connected`). `frr/start.sh` therefore carries
  Vinbero's locator block `fd00:100::/48` as a connected prefix on
  `eth2`, plus a more-specific `/128` route so the encapsulated return
  traffic is still forwarded onward to the core.
* The return-path `End.DT4` localsid on FRR uses `vrftable`, which the
  kernel only accepts with `net.vrf.strict_mode=1` — set in
  `frr/start.sh`.
