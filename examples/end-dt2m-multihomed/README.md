# End.DT2M Multihomed Playground

Validates RFC 9252 split-horizon filtering and static DF election on a
5-namespace topology where **host1 dual-homes to PE1 and PE2** via a shared
Linux bridge. Implements the scenario documented in
[`docs/dev/end_dt2m_multihomed_topology.md`](../../docs/dev/end_dt2m_multihomed_topology.md).

## Topology

```
host1 (172.16.100.1, VLAN 100)
   │ shared CE (ES-1)
   │    ┌─── mh-pe1 (fc00:1::1, local_attached ES-1)
   │────┤
   │    └─── mh-pe2 (fc00:2::2, local_attached ES-1)
   │
   │                  ↓ SRv6
   │               mh-p (fc00:99::1, End transit)
   │                  ↓
   └──────────── mh-pe3 (fc00:3::3) ── host2 (172.16.100.2)
```

Both PE1 and PE2 attach to host1 via `mh-h1-br` inside `mh-host1`, producing
two veth legs. Without split-horizon, a broadcast from host1 loops back via
the other PE; with RFC 9252 split-horizon + DF election the broadcast fans
out correctly.

## Quick start (requires sudo)

```bash
sudo ./setup.sh
# (wait for vinberod to be ready on each PE)
sudo ./test.sh
sudo ./teardown.sh
```

## What the test verifies

1. **Split-horizon (Phase C)**: `host1 → broadcast → PE1` is NOT re-flooded
   back to host1 via PE2. Assert `SPLIT_HORIZON_TX > 0` on PE1 and
   `SPLIT_HORIZON_RX` on PE2 (fail-safe path).
2. **DF election (Phase D)**:
   - Initially DF=PE1 → `vbctl es df-set --esi ES-1 --pe fc00:1::1` on both
     PEs (so they agree on who the DF is).
   - Remote `PE3 → BUM → host1` should reach host1 only via PE1 (PE2 drops
     with `NON_DF_DROP`).
   - Swap DF to PE2: `vbctl es df-set --esi ES-1 --pe fc00:2::2` → delivery
     now comes via PE2.

## Status

**DATA PLANE** (eBPF logic): fully covered by `pkg/bpf/split_horizon_test.go`
with BPF_PROG_TEST_RUN assertions. See:
- `TestXDPProgEndDT2MSplitHorizonRX` (Phase C RX drop)
- `TestXDPProgEndDT2MNonDFDrop` (Phase D DF gate)
- `TestBdPeerReverseEsi` (ESI propagation into bd_peer_reverse_map)

**CONTROL PLANE API** (Connect RPC): exercised by `smoke_api.sh` in this
directory, which brings up a single vinberod instance (no dataplane traffic)
and round-trips `es create / list / df-set / df-clear / delete` plus
`bd-peer create --esi`.

**FULL E2E TOPOLOGY**: `setup.sh` / `test.sh` in this directory bring up
the 5-namespace shared-CE topology. The BPF code has been validated via the
unit tests above; running the topology end-to-end is still useful for
verifying Linux bridge interactions (veth tx-vlan offload, ARP duplicates,
MAC Pinning). Start with `smoke_api.sh` first, then attempt `setup.sh` +
`test.sh` once the API smoke is green.

## Files

| File | Purpose |
|---|---|
| `README.md` | This document |
| `smoke_api.sh` | Quick API exercise (1 PE, no dataplane); runs in <10s |
| `setup.sh` | 5-namespace topology including shared-CE bridge |
| `teardown.sh` | Remove namespaces / veths |
| `test.sh` | End-to-end test with pcap + stats assertions |
| `vinbero_pe1.yaml` | PE1 config (ES-1 local_attached) |
| `vinbero_pe2.yaml` | PE2 config (ES-1 local_attached) |
| `vinbero_p.yaml` | Transit router config (End) |
| `vinbero_pe3.yaml` | Egress PE config (single-homed) |
