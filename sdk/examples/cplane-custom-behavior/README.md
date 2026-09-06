# cplane-custom-behavior

An operator's own SRv6 endpoint behavior, driven from the control plane.

This is the control-plane half of the case the plugin mechanism exists for.
You define a behavior of your own, number it outside the standardized
codepoint space, implement its forwarding as a data-plane plugin in an eBPF
slot, and let this half of the plugin claim the codepoint, watch for routes
carrying it, and program the headend entries that steer traffic into the
SID each advertisement names.

Vinbero's own appliers never see those routes. They read a service SID
without consulting its behavior codepoint, so an unrecognized one would be
installed with the wrong meaning and then collide with this plugin's write
to the same prefix. The claim is what keeps the two apart.

## What it does

It runs both halves of the case.

Sending: at startup it asks the daemon for a local SID from a configured
locator, pointing at the eBPF slot its data-plane half occupies. The daemon
allocates the address, installs the dispatch entry and tells the plugin
which address it got -- the plugin names the SID, the daemon chooses the
value. Recreating the plugin with the same locator within the same daemon run
preserves that name/address mapping. Changing the locator reallocates the SID;
daemon restarts do not guarantee the mapping. It then advertises
the configured prefix behind
that SID, naming its own behavior codepoint in the SID TLV.

Receiving, on every batch of events:

- an advertisement carrying the claimed behavior and an SRv6 SID adds a
  headend entry for its prefix, steering into that SID
- a withdrawal removes that path, keeping any alternatives
- an update whose behavior no longer matches removes the old version of that path

Two nodes running this plugin therefore reach each other over a behavior
neither vinbero nor BGP knows anything about.

It then declares the whole set, not a delta. The daemon diffs the
declaration against what this plugin already owns and applies the
difference, which is what makes a restart uneventful: a fresh instance
comes back with no memory, the daemon replays the routes, and the same
declaration converges on the same state.

A withdrawal is matched by family, RD, masked prefix, peer and ADD-PATH ID.
BGP withdrawals carry no behavior attributes. Several paths for one prefix
remain distinct until selection: this example chooses the lowest RD, then
peer, then numeric path ID.

The SDK suspends headend declarations from BGP replay start through its end,
across batches and ticks. Empty completed snapshots still declare an empty set
to prune stale entries. Failed declarations remain pending and retry on ticks;
they do not need another route update to make progress.

## Build

```sh
make cplane-example        # from the repository root
```

or directly:

```sh
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -trimpath \
    -buildvcs=false -ldflags="-s -w" -o plugin.wasm .
```

The default is standard Go, pinned to Go 1.25.5 by this repository. The reactor
build exports `_initialize` and the SDK callbacks; the daemon invokes them via
wazero with WASI preview 1. `-trimpath`, `-buildvcs=false` and stripped debug
information keep the committed artifact reproducible.

The host grants clocks and randomness without host filesystem, environment or
network access. Use `guest.Log` for diagnostics. The churn test runs 50,000
update/withdraw pairs under the default 16 MiB memory limit with Go's collector.

`make cplane-example-tinygo` optionally creates `plugin.tinygo.wasm` without
replacing the default artifact. See the [SDK build instructions](../../go/cplane/README.md)
for its flags and runtime limitations.

## Run

From the repository root, with the daemon running and the CLI built (`make build`),
register a receive-only instance handling `10.7.0.0/16`:

```sh
./out/bin/vinbero plugin cplane register \
    --name custom-behavior \
    --wasm sdk/examples/cplane-custom-behavior/plugin.wasm \
    --behavior 0xFE01 \
    --family vpnv4 \
    --capability headend \
    --headend-prefix 10.7.0.0/16 \
    --tick-ms 1000

./out/bin/vinbero plugin cplane list
./out/bin/vinbero plugin cplane unregister --name custom-behavior
```

The capabilities are what this plugin is allowed to do. The daemon links
only the host functions they cover, so a plugin granted nothing that writes
cannot reach the apply functions at all; between the kinds of declaration
the check happens where the transaction is opened, because those functions
are shared. A receive-only deployment needs the `headend` capability and its
prefix scope. An allocating deployment also needs `local_sid` and `advertise`,
with grants for its locator, VRF and endpoint slot; pass the encoded configuration
with `--config`. See the [two-site lab](../../../examples/interop-clab/scenarios/cplane-plugin-2site/README.md)
for the data-plane registration and complete deployment configuration.

Registering the same name again upgrades in place: the entries the running
instance wrote stay, and the new module reconciles over them. Unregistering
is the deliberate removal and takes the plugin's entries with it. Disabling
allocation or advertising in the configuration declares empty sets for those
kinds, retracting state retained from the previous instance. Failed cleanup
commits retry on ticks. A kind whose declaration cannot begin is skipped for
this instance, including after capability revocation. Failed puts/commits and
missing SID notifications remain retryable. Periodic retries require `--tick-ms`;
it defaults to disabled.

## Configuration

The config blob is this plugin's own protobuf message, which the daemon
does not interpret. It carries everything that differs between
deployments, so one build serves all of them:

| field | meaning |
|---|---|
| 1 | the endpoint behavior codepoint to claim |
| 2 | the locator to take a local SID from |
| 3 | the prefix to advertise behind that SID |
| 4 | the VRF to advertise it into |
| 5 | the eBPF slot the SID dispatches to |
| 7 | the next hop to advertise the prefix with |
| 8 | the VRF a plugin-dispatched End.DT4 decapsulates into |

There are two ways to run it, and the config picks between them:

- **Allocating.** Set the locator and the slot. The plugin asks the host
  for a SID, is told the address, and advertises the prefix behind it. The
  slot is where its eBPF half lives; [`../plugin-custom-behavior`](../plugin-custom-behavior)
  is that half, and the two are exercised together by the
  `cplane-plugin-2site` interop scenario.
- **Receive-only.** Set neither a locator nor a slot. The plugin originates
  nothing and only acts on routes carrying its behavior, which is a
  perfectly ordinary way to run it.

A plugin may advertise only a SID it was itself allocated: the daemon
refuses a route pointing at any other SID, since one the plugin did not
allocate could belong to another VRF. Fronting a SID an operator
provisioned outside the plugin would need an explicit operator grant the
scope model does not yet carry, so there is no "advertise a given SID" mode.

Fields 3, 4 and 7 are what the advertisement is made of, so the allocating
mode needs all three. The daemon refuses an advertisement with no next hop
rather than guessing one.

The VRF has to be one the plugin's registration lists in its scope, and the
route distinguisher and route targets come from that VRF's binding rather
than from this config. A plugin cannot name them: they are what decides
which VPN a peer imports the route into.

Field 8 is the return direction. When the eBPF half hands decapsulated
traffic to a built-in End.DT4, the handoff nulls the SID's own aux so the
plugin cannot spell an arbitrary VRF there. Naming the VRF here makes the
host record it in a grant it owns, and the built-in decap reads the VRF from
the grant. It must be a VRF in the plugin's scope, the same set the
advertisement is bound to. Leave it unset for a half that forwards on its
own without a built-in handoff; the built-in decap drops with no grant.

## Notes on the code

`main.go` uses the [Go guest SDK](../../go/cplane/README.md): `guest.Register`
supplies the WASM entry points, `RouteView` tracks input paths and replay,
and `Client` sends typed desired sets. `config.go` decodes this example's
private configuration with the SDK's reflection-free wire decoder.

`vinbero_abi_version` is what lets the daemon refuse a module built against
an ABI it no longer implements, rather than letting it trap on the first
call into a function whose signature moved.

The periodic callback retries failed declarations. The plugin uses host logging
and has no filesystem or network access. The host supplies BGP events and
performs the declared writes.
