# Go control-plane plugin SDK

`github.com/takehaya/vinbero/sdk/go/cplane` supplies typed events and desired
sets, and a view of BGP prefix routes. The `guest` subpackage supplies Go
WASM entry points and host calls. Both use the daemon's existing ABI version 1.

The SDK is part of the Vinbero Go module. Use a module dependency pinned to a
revision containing it, or a local `replace` as in
[the custom-behavior example](../../examples/cplane-custom-behavior/go.mod).
The base SDK and guest packages do not use the generated protobuf runtime or reflection.

## Registering callbacks

Import `cplane` and `cplane/guest` from the paths above, then register handlers
from `init`. `main` is empty: the daemon initializes the reactor and invokes the
callbacks. For example, an observation-only plugin can report route events:

```go
package main

import (
    "github.com/takehaya/vinbero/sdk/go/cplane"
    "github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
    guest.Register(guest.Handlers{
        Events: func(events []cplane.Event) []cplane.EventResult {
            for _, ev := range events {
                if ev.Kind == cplane.EventRoute {
                    guest.Log(cplane.LogInfo, ev.Route.Prefix)
                }
            }
            return nil
        },
    })
}

func main() {}
```

`Configure func([]byte) error` receives the plugin's opaque configuration;
copy any bytes retained after it returns. `Events` receives owned event data
and can return per-event `Quarantine` results with a reason. Nil results mean
all events were handled. `Tick func(int64)` receives monotonic nanoseconds;
`guest.NowMonotonic` uses the same clock. Callbacks run serially. Register with
`--tick-ms 1000` (or set `TickInterval` through the API) to drive periodic retries;
omitting the interval leaves `Tick` undriven.

Context registrations can opt into grouping already queued live BGP updates with
`max_batch_events` in their input policy.
Callbacks must preserve event order and report dispositions using each event's original sequence number.
The host adds no waiting period to fill a group, and a group shares the existing per-call limits.
Input preparation and runtime failures affect the whole combined call.
See [grouping live updates](../../cplane-route-api.md#grouping-live-updates) for the operator setting and recovery semantics.

Build with standard Go (Go 1.24 or later supports WASI reactors; this repository
pins Go 1.27.3):

```sh
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -trimpath \
    -buildvcs=false -ldflags="-s -w" -o plugin.wasm .
```

The host links WASI preview 1 and calls `_initialize` before the ABI callbacks.
The Go runtime, garbage collector, reflection and WASI-compatible standard library packages are available.
WASI supplies real clocks and randomness, without inheriting the host environment, arguments, filesystem mounts or sockets.
The existing hard memory cap and call timeout remain the resource boundaries.
Stdin is EOF and stdout is discarded.
The host retains at most the first 4 KiB of stderr per export call and attaches it only when WASM execution fails, such as a trap or timeout.
Use `guest.Log` for normal diagnostics.
`time.Now` uses real time; `guest.NowMonotonic` and `Tick` use the host's plugin clock, which a test harness can simulate.
Timers and sleeps remain inside the call timeout.
Guest work runs only while the host calls the module; use `Tick` for periodic
work and finish any goroutines that access callback data before returning.

`make cplane-example` builds the committed example with standard Go. The runtime
limits remain 16 MiB of linear memory and 2 seconds per call by default. The
harness tests 50,000 update/withdraw pairs within that memory limit; larger
route views may require an explicit higher limit.

TinyGo 0.43.0 remains an optional smaller build:

```sh
tinygo build -o plugin.tinygo.wasm -target=wasm-unknown \
    -scheduler=none -gc=conservative -panic=trap -no-debug .
```

Use `make cplane-example-tinygo` for the example. `-gc=conservative` is required
for reclaiming memory on this target; its default leaking collector is unsuitable
for a long-running plugin. TinyGo's standard-library and scheduler limitations
still apply. Both compilers use the same SDK callbacks and ABI 1.

## Declaring state

Construct `cplane.Client{Host: guest.Host{}}` and call `ApplyHeadendV4`,
`ApplyHeadendV6`, `ApplyAdvertise`, or `ApplyLocalSIDs`. Each slice is the
**complete desired set for that kind**. An empty slice removes that kind's
entries belonging to this plugin. The client stages chunks of at most 32 KiB
by default, aborts staging when a chunk fails, and commits once. Adjust
`MaxChunkBytes` if the host uses a smaller buffer limit. An individual entry
must fit within that limit.

The host enforces capabilities, scope, ownership and quotas. Registration must
grant both the capability and its scope. A refused begin is `ErrBeginRefused`;
the ABI does not identify its cause. Put/commit failures are `ApplyError` values
with the stage and host status. Live commits are synchronous and may partially
apply before returning an error. During initialization/replay before publication,
success means the host staged the declaration; the host applies it at publication
and retries failures. Retain desired state after a returned error and retry as
appropriate. ABI 1 exposes no separate acceptance/application generations or
cross-kind dependency status.

On same-name replacement, the host prunes existing state excluded by the new
capabilities or scope. A guest cannot clear a kind after its capability is
revoked. Within one daemon run this covers headend entries, local SIDs and
advertisements; daemon restore can only discover prior headend entries.
During authorization pruning, advertisements referencing a removed SID must be
withdrawn before that SID is released. A failed withdrawal keeps the SID and
fails the replacement so the operator can retry.

For local SIDs, declare a name, locator and endpoint slot. While its address is
unknown, retry until the matching allocated SID event arrives: a successful
commit does not guarantee notification delivery when the host queue is full.
An unchanged address already delivered to this instance need not be notified again.

Before changing or removing a SID entry, the host withdraws advertisements
referencing it. A failed withdrawal refuses the SID change, including during
publication and retries. The plugin must redeclare its desired advertisements
after a successful SID change. The SDK does not automatically order declarations
or restore those advertisements. The host derives VPN RD/RT from the declared VRF.
Stable SID names retain their addresses across guest replacement with the same locator
within one daemon run. Changing the locator reallocates the SID; daemon restarts
do not guarantee the name/address mapping.

## Maintaining a route view

`RouteView` supports `vpnv4`, `vpnv6`, `ipv4_unicast` and `ipv6_unicast` prefix
routes. `Accept` filters advertisements; a rejected update removes the prior
version of that path. Withdrawals match recorded paths without needing behavior
attributes. Identity includes family, RD, masked prefix, peer and ADD-PATH ID.
EVPN and MUP require different NLRI identities and are not tracked by this view;
the typed event decoder still exposes their available route fields.

Pass every batch to `view.Update(events)` before computing declarations. A BGP
replay clears the view and suppresses `Pending()` across batches and ticks until
its end marker. Markers for other sources do not alter it. An empty completed
replay is pending too, so stale headend entries can be pruned. The zero value
accepts live events before any replay marker arrives.

When `Pending()` is true, use `Range` to compute your desired headend set. Call
`Applied()` only after the declaration succeeds. On failure it stays pending;
a tick can retry using the latest view. Methods assume serialized callbacks.
Do not mutate retained route slices or the view during `Range`.

The view does not choose a path or combine its SIDs. Several input paths can
map to one forwarding key; selection belongs to the plugin and must be independent
of map iteration order. See the example's
[`headendEntries`](../../examples/cplane-custom-behavior/main.go) for a deterministic
selection policy and its handling of local SID and advertisement retries.

## Reading the GoBGP packet model

`Route.BGPPath` carries the serialized NLRI, complete path attributes, an opaque destination key and source metadata alongside the legacy fields.
The host supplies this model for its currently supported received BGP families on both live events and RIB snapshots.
It is a serialization of GoBGP's parsed model, not a capture of the original BGP message.
Attribute order, duplicates and unknown attribute values are retained as represented by GoBGP.
The NLRI has no ADD-PATH header; `Route.Peer` and `Route.PathID` identify the received source.
`Metadata.LocalPathID` is the host's separate local identifier.
`Metadata.Best` is present for snapshots and absent for live post-policy updates, where GoBGP does not supply it.

For native packet types, import the optional `cplane/gobgppath` package and call `gobgppath.Decode(route)`.
The returned NLRI and attributes own their data and use `github.com/osrg/gobgp/v4/pkg/packet/bgp` types.
This adapter does not expose GoBGP server calls or change write permissions.
The codec is pinned to the host's MUP fork; consumer modules must repeat the GoBGP replacement from the [observer example](../../examples/cplane-bgp-observer/go.mod).
The base SDK remains independent of GoBGP.

Use `Route.BGPKey()` to identify retained inputs.
Its key includes codec, AFI/SAFI, the host's opaque destination identity, peer and received ADD-PATH ID.
Destination identity follows the pinned GoBGP RIB: VPN labels, EVPN non-key fields and MUP ST1 TEID/QFI/endpoint parameters may change without creating a new destination.
Complete NLRI bytes retain those fields as payload.
Do not derive identity from serialized NLRI or formatted packet values in a guest.
A codec upgrade must review these identity semantics.

Encoding failures are explicit in `EncodingError`; the adapter rejects them rather than returning partial attributes.
An attribute failure can still carry a valid `BGPKey()`.
When maintaining a view, remove the previous value of that key before decoding or filtering its replacement, so a rejected update cannot leave stale input.
A missing key requires an explicit recovery policy such as rebuilding the view; the SDK does not provide a generic MUP/EVPN view yet.
Withdrawals retain the destination key and NLRI and omit attributes.

`guest.InputFeatures()` returns a support bitmap; test `cplane.FeatureBGPPath` before requiring this input.
This read-only import adds no capabilities and leaves `Configure` bytes unchanged.
Guests using only the original SDK continue to run on the updated host.
A guest importing `input_features` requires an updated host; older hosts refuse the unknown import before execution.
See the [read-only observer](../../examples/cplane-bgp-observer) for a complete example.

## Testing

The base package works in native Go tests: inject a `Host` implementation to
record declarations or simulate failed calls. Codec tests compare SDK messages
with the daemon's generated protobuf types.

[`cplaneharness`](../cplaneharness/harness.go) runs compiled WASM through the real
runtime. `Deliver`, `Route`, `Tick`, `Restart`, `Reconfigure` and `SetDenyCommits` exercise replay
boundaries and recovery, with `Declarations` exposing successfully committed
sets. Set explicit capabilities and scope when testing deployment constraints;
zero-valued harness scope intentionally skips checks that a daemon registration
would enforce. Locator membership and VRF bindings still require daemon tests.

From the repository root:

```sh
make cplane-example
go test -race ./sdk/go/cplane/... ./sdk/go/cplaneharness ./pkg/cplane/...
```
