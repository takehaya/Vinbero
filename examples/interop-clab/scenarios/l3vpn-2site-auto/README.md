# l3vpn-2site-auto — auto-advertise SRv6 L3VPN interop (Vinbero ⇄ FRR)

The auto-advertise variant of [l3vpn-2site](../l3vpn-2site/). The topology,
addressing, and FRR PE are identical; the only difference is how the Vinbero PE
originates its customer route.

In `l3vpn-2site`, Vinbero advertises `10.1.0.0/24` with explicit
`vbctl sid create` + `vbctl bgp advertise-vpn` calls. Here, Vinbero advertises
it **automatically from config**: `bgp.global.auto_advertise: true` plus a
`vrf_bindings` entry with `redistribute: [static]`. The exporter
(`pkg/bgp/export`) mints the End.DT4/DT6 service SID from `LOC1` and advertises
the VRF-local prefix on its own — no `vbctl` call, the receive-direction mirror
of `pkg/bgp/apply`.

## What differs from l3vpn-2site

- **vinbero/vinbero.yml**: `bgp.locators` declares `LOC1` statically (the
  exporter resolves a binding's `default_locator` at startup, before any RPC);
  `bgp.global.auto_advertise: true`; `bgp.global.next_hop` is the PE loopback
  (the BGP next hop must be a normal node address — a locator base is a
  subnet-router anycast address that a receiving PE treats as local, breaking
  forwarding); `vrf_bindings` carries `rd` / `import_rts` / `export_rts` /
  `default_locator` / `redistribute`.
- **vinbero/start.sh**: no `vbctl sid create` / `bgp advertise-vpn`. The
  customer route is added with `proto static` so the `redistribute: [static]`
  allowlist forwards it (a bare `ip route` is `RTPROT_BOOT`, excluded to avoid
  leaking casual routes into the VPN).
- **frr/start.sh**: the /128 glue route targets the auto-minted SID
  `fd00:100:0:10::` (function `0x10`, the first auto-allocated End.DT4) instead
  of the manual `fd00:100:0:1::`.

The advertised SID is dynamic, so `test.sh` discovers Vinbero's End.DT4 SID
rather than hard-coding it.

## Run

Needs Docker, `containerlab`, and `sudo`. From `examples/interop-clab/`:

```bash
make all SCENARIO=l3vpn-2site-auto
```

## What test.sh checks

The same four things as `l3vpn-2site` — iBGP Established, FRR → Vinbero SRv6
Service TLV decode (with RFC 9252 §4 transposition), Vinbero → FRR encode, and a
bidirectional `ping` between `ce-tokyo` and `ce-osaka` over the SRv6 L3VPN —
except the Vinbero → FRR route is originated by the auto-advertise exporter with
no operator RPC.
