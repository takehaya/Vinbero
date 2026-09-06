# Go control-plane plugin SDK

`github.com/takehaya/vinbero/sdk/go/cplane` supplies typed events and desired
sets, and a view of BGP prefix routes. The `guest` subpackage supplies TinyGo
WASM entry points and host calls. Both use the daemon's existing ABI version 1.

The SDK is part of the Vinbero Go module. Use a module dependency pinned to a
revision containing it, or a local `replace` as in
[the custom-behavior example](../../examples/cplane-custom-behavior/go.mod).
No guest dependency uses the generated protobuf runtime or reflection.

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

Build with TinyGo 0.39.0 and the repository's Go version:

```sh
tinygo build -o plugin.wasm -target=wasm-unknown \
    -scheduler=none -gc=conservative -panic=trap -no-debug .
```

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

For local SIDs, declare a name, locator and endpoint slot. Retry the declaration
until the matching allocated SID event arrives: a successful commit does not
guarantee notification delivery when the host queue is full. Advertise only after
receiving that event. The SDK does not automatically order different
kinds of declarations. The host derives VPN RD/RT from the declared VRF. Stable
SID names retain their addresses across guest replacement with the same locator
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
