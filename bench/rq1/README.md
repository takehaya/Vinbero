# Same-controller native/WASM measurements

`make bench-cplane-build` builds the daemon, probe/speaker tools, fresh standard-Go writing/observation WASM artifacts, and an encoded-call benchmark executable.
The daemon statically links the same `sdk/go/cplane/mupcontroller` source used by those WASM entrypoints.
Native execution requires `settings.cplane_plugins.native_enabled: true`; the measurement driver enables this in its private configuration.

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
`B/op` and `allocs/op` describe Go host allocations and exclude the WASM linear heap, so they are not total-memory comparisons.

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
