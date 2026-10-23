# Same-controller native/WASM measurements

`make bench-cplane-build` builds the daemon, probe/speaker tools, fresh standard-Go writing/observation WASM artifacts, and an encoded-call benchmark executable.
The daemon statically links the same `sdk/go/cplane/mupcontroller` source used by those WASM entrypoints.
Native execution is enabled by default; the measurement driver also sets `settings.cplane_plugins.native_enabled: true` explicitly in its private configuration.

## Encoded calls

From the repository root, run each mode separately:

```sh
cd pkg/cplane/native
VINBERO_CPLANE_BACKEND=native ../../../out/bench/cplane-runtime.test \
  -test.run '^$' -test.bench '^BenchmarkCompositionEncodedUpdates$' -test.benchtime=10000x
VINBERO_CPLANE_BACKEND=wasm ../../../out/bench/cplane-runtime.test \
  -test.run '^$' -test.bench '^BenchmarkCompositionEncodedUpdates$' -test.benchtime=10000x
```

Each call changes the service SID of one ISD joined with a fixed ST1.
Input event bytes, controller code, output encoding and SDK transaction transport are shared.
The host sink checks that every timed update committed a real declaration and that the final output contains one forwarding headend.
Queueing, host authorization and real BPF operations are excluded from this instrument.
`init-ns` separately measures constructor/compile/instantiate/configure work; it excludes process startup, reading the module, replay and warmup.
Go runs an untimed one-iteration pilot before the fixed iteration count, so this initialization is for a fresh instance after that harness pilot, not a cold process.
`B/op` and `allocs/op` count Go host allocations, which can include allocation of backing storage when WASM linear memory grows.
They do not count guest allocations one for one and do not measure total or peak memory.

## BGP-to-packet convergence

Run from the repository root after loading the usual namespace/VRF dependencies:

```sh
sudo MODE=composition-native RATE=10000 WORK=/tmp/rq1-mup-native-new \
  ./bench/rq1/topo/run_bgp.sh 1
sudo MODE=composition-wasm RATE=10000 WORK=/tmp/rq1-mup-wasm-new \
  ./bench/rq1/topo/run_bgp.sh 1
```

Each new WORK directory must have trusted root-owned parents.
The driver snapshots executable code and instruments, owns fresh namespaces and cleans up only its own processes/resources.
Receiver and sender readiness precede scheduling the capture window.
Every trial checks initial/final forwarding and plugin state, plus packets on the initial path before the change.

Both modes receive the same MUP ST1 and ISD, then update the ISD service SID.
The measured interval starts immediately before the speaker's ISD advertise API call and ends at the first packet on the new path.
Both modes use the same worker, input policy, scopes, PluginOps and headend maps.
The endpoints use kernel End.DT4 as a **synthetic sink** for the generated argument SIDs.
This isolates control-plane/path-switch behavior; it does not verify a remote End.M.GTP4.E implementation or GTP/UPF interoperability.
Startup, initial convergence and module compilation are outside this interval.

The original `builtin`, `cplane` and `relay` modes remain available.
They have different implementations and must not stand in for this same-controller comparison.
Repeated trials should freeze source/toolchains/binary hashes, balance mode order, retain failures, record achieved probe rate and host load, and avoid concurrent measurement jobs.
Shared-host CI smoke timings are functional checks, not performance regression thresholds.

## Supported controller input profiles

`BenchmarkCompositionBehaviorUpdates` compares the existing shared controller with
`VINBERO_CPLANE_CASE` set to one of these values:

| Case | Input and output |
| --- | --- |
| `downlink-gtp4-v4` | IPv4 ST1 + IPv4 ISD; IPv4 H.Encaps trigger with a GTP4 argument SID |
| `downlink-gtp4-v6` | IPv6 ST1 + IPv4 ISD; IPv6 H.Encaps trigger with a GTP4 argument SID |
| `uplink-dt4` | IPv4 ST2 + DSD advertising End.DT4; GTP4 uplink declaration |
| `uplink-dt6` | IPv4 ST2 + DSD advertising End.DT6; GTP4 uplink declaration |
| `uplink-dt46` | IPv4 ST2 + DSD advertising End.DT46; GTP4 uplink declaration |

For example, after `make bench-cplane-build`, run from `pkg/cplane/native`:

```sh
VINBERO_CPLANE_BACKEND=native VINBERO_CPLANE_CASE=uplink-dt6 \
  ../../../out/bench/cplane-runtime.test -test.run '^$' \
  -test.bench '^BenchmarkCompositionBehaviorUpdates$' -test.benchtime=1000x
```

Use `VINBERO_CPLANE_BACKEND=wasm` with the same case for the WASM arm.
Both A and B outputs are checked before timing; the commit count and final expected
output are checked afterward.
`VINBERO_CPLANE_TRACE_DIR` preserves config, replay, both updates and final output
for byte comparison between arms.

These are control-plane input profiles, not measurements of endpoint instructions.
The three uplink profiles emit the same declaration schema and do not execute
End.DT4/6/46 packet decapsulation or the host's endpoint headend gate.
IPv6 payload in the downlink profile still uses a GTP4 transport endpoint.
GTP6 and ST2+ISD are unsupported by this controller.
EVPN has SDK builders but no shared native/WASM controller in this comparison.
The existing packet-convergence fixture covers only the IPv4 downlink profile.

## Scale and cost boundaries

`BenchmarkCompositionScale` holds N IPv4 ST1 routes and one shared IPv4 ISD.
Set `VINBERO_CPLANE_SESSIONS` to N, `VINBERO_CPLANE_CHANGE` to `st1` (change
TEIDs in a fixed session set) or `isd` (change the shared service SID), and
`VINBERO_CPLANE_BATCH` to the number of ST1 updates per call (ISD requires 1).
`VINBERO_CPLANE_STAGE` selects `core`, `native`, `wasm`, `decode`, or `encode`.
The first three measure typed controller execution, the native encoded adapter,
and the WASM encoded adapter respectively; all use the same semantic fixture.
Core still decodes GoBGP NLRI and attributes inside the View.
`decode` measures SDK event-envelope decoding with structural checks, and
`encode` measures SDK desired-set encoding/transport from prebuilt typed outputs.
These independent diagnostics are not an additive time breakdown.

Run `make bench-cplane-build` first, then from `pkg/cplane/native`, for example:

```sh
VINBERO_CPLANE_SESSIONS=512 VINBERO_CPLANE_CHANGE=st1 \
VINBERO_CPLANE_BATCH=1 VINBERO_CPLANE_STAGE=wasm \
  ../../../out/bench/cplane-runtime.test -test.run '^$' \
  -test.bench '^BenchmarkCompositionScale$' -test.benchtime=20x
```

A/B output values and counts are checked outside timing, as are total commits and
final expected output; `VINBERO_CPLANE_TRACE_DIR` saves inputs and final output.
All non-decode stages must produce identical bytes for equal iteration counts.
The sink is in memory: no manager queue, authorization, BGP transport or real BPF
is included, and changing batch width does not measure an offered arrival rate.
Keep resource limits fixed and report failed cases rather than reducing N or
raising limits after seeing results.

## Concurrent MUP update source

`make bench-rq1-build` also builds `out/bench/rq1mupload` for a persistent
BGP session with 64 or 512 IPv4 ST1 routes, one fixed ISD, and an independently
scheduled VPNv4 sentinel route carrying custom behavior `0xfe01`.
Run it inside a prepared speaker namespace, for example:

```sh
ip netns exec "$speaker_ns" out/bench/rq1mupload \
  -neighbor fd00:12::1 -next-hop fd00:12::2 -sessions 64 \
  -rate 50 -duration 10s -start-file "$work/start-at" \
  -log "$work/events.jsonl" -expected "$work/expected.json" \
  -stop-file "$work/stop"
```

After the initial `ready` message, gate the receiver's complete forwarding maps
before atomically publishing a future Unix nanosecond timestamp in `start-at`.
Use `-burst 512` instead of `-rate` for the immediate burst profile.
The sentinel remains active for three seconds in that profile.
Late rate slots are recorded as skipped and are not replayed as catch-up bursts.
Each successful update alternates between two TEIDs distinct from the initial
value, with an independent version counter for every prefix.

The JSONL records planned times, API call bounds, versions, errors and skips.
`expected.json` records the final speaker-accepted state; it is not a receiver
RIB export, and `complete: true` does not imply zero skipped slots.
The BGP session remains alive until the driver creates `stop`, allowing final
map and packet checks before withdrawal.
All event times describe the source API boundary; they do not establish the
receiver's enqueue rate or prove that every intermediate version was applied.
