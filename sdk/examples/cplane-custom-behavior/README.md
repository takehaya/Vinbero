# cplane-custom-behavior

An operator's own SRv6 endpoint behavior, driven from the control plane.

The implementation lives in the shared [`customcontroller`](../../go/cplane/customcontroller) package.
This example supplies the WASM entry points and host transport; the daemon's native adapter calls the same controller.

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

Sending: at startup it asks the daemon for a local SID from its
locator, pointing at the eBPF slot its data-plane half occupies. The daemon
allocates the address, installs the dispatch entry and tells the plugin
which address it got -- the plugin names the SID, the daemon chooses the
value. Recreating the plugin with the same locator within the same daemon run
preserves that name/address mapping. Changing the locator reallocates the SID;
daemon restarts do not guarantee the mapping. It then advertises
the configured prefix behind
that SID, naming its own behavior codepoint in the SID TLV.

Receiving, on every batch of events:

- an advertisement carrying the claimed behavior and an SRv6 SID, within the
  receive prefixes, adds a headend entry steering into that SID
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

## Run natively

Native is the default backend and is enabled by default in the daemon.
For the registration named `custom-behavior` below, omit `--wasm sdk/examples/cplane-custom-behavior/plugin.wasm` to run the shared controller natively.
Use `--native custom-behavior` for a different registration name, and optionally pin the implementation with `--native-version 1`; otherwise the daemon resolves and persists its catalog version.
Set `settings.cplane_plugins.native_enabled: false` to allow only WASM plugins.
Keep the same configuration, behavior claims, families, capabilities, scopes and tick interval.
Both backends read the same JSON configuration and the same registration grants; neither uses the MUP context-input envelope.
Receive-only operation needs a headend grant; sending also needs the existing local-SID and advertisement grants and scopes.

The controller is statically linked into the daemon, so adding or updating it requires rebuilding the daemon.
Native calls run in the daemon process with cooperative cancellation, without WASM memory isolation or forced interruption.
Persisted native registrations must match the rebuilt daemon's source identity; an identity mismatch requires an explicit registration update.

To check both builds from the repository root:

```sh
make cplane-example cplane-bgp-observer cplane-route-composition cplane-route-composition-observer
VINBERO_CPLANE_PARITY=1 go test -race ./pkg/cplane/native
VINBERO_CPLANE_PARITY=1 go test -race ./pkg/cplane -run 'TestExample|TestNativeCustomBehaviorIntegration'
```

The differential tests compare configure-time transactions, encoded outputs, event statuses, logs and retries.
The Manager integration tests reuse the same expected forwarding maps and authorization checks for both backends.

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

A receiver needs no `--config`. The plugin reads its registration when it
starts: it steers the behavior it claims (`--behavior`) and accepts the
prefixes of its headend scope (`--headend-prefix`).

A sender also allocates a SID and advertises a prefix behind it. The
registration supplies the locator, VRF and endpoint slot; the configuration
names what only the plugin knows:

```sh
cat > /tmp/custom-behavior.json <<'EOF'
{"schema_version": 1,
 "routing": {"prefix": "10.2.0.0/24", "next_hop": "2001:db8:ff::2", "decap_vrf": "vpn-a"}}
EOF
./out/bin/vinbero plugin cplane register \
    --name custom-behavior \
    --wasm sdk/examples/cplane-custom-behavior/plugin.wasm \
    --config /tmp/custom-behavior.json \
    --behavior 0xFE01 \
    --family vpnv4 \
    --capability headend --capability advertise --capability local_sid \
    --headend-prefix 10.7.0.0/16 \
    --locator main --vrf vpn-a --endpoint-slot 33 \
    --tick-ms 1000
```

The capabilities are what this plugin is allowed to do. The daemon links
only the host functions they cover, so a plugin granted nothing that writes
cannot reach the apply functions at all; between the kinds of declaration
the check happens where the transaction is opened, because those functions
are shared. A receive-only deployment needs the `headend` capability and its
prefix scope. A sender also needs `local_sid` and `advertise`, with grants
for its locator, VRF and endpoint slot. See the
[two-site lab](../../../examples/interop-clab/scenarios/cplane-plugin-2site/README.md)
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

The configuration is a JSON object that the daemon passes to the plugin
without reading it. Empty configuration is the same as `{"schema_version": 1}`.
Unknown keys and `null` values are refused, so a misspelled key fails
registration instead of being ignored.

```json
{
  "schema_version": 1,
  "routing": {
    "behavior": 65025,
    "headend_prefixes": ["10.7.0.0/16"],
    "locator": "main",
    "slot": 33,
    "decap_vrf": "vpn-a",
    "vrf": "vpn-a",
    "prefix": "10.2.0.0/24",
    "next_hop": "2001:db8:ff::2"
  }
}
```

Every `routing` key is optional. Where the registration already decides a
value, leave the key out and the plugin takes it from the registration:

| key | meaning | when omitted |
|---|---|---|
| `behavior` | endpoint behavior codepoint to steer | the claimed behavior if exactly one is claimed; `0xFE01` if none |
| `headend_prefixes` | IPv4 receive prefixes (CIDR) | the IPv4 prefixes of the headend scope |
| `locator` | locator to take a local SID from | the scope's locator, if it lists exactly one |
| `slot` | eBPF endpoint slot the SID dispatches to, in [32,64) | the scope's endpoint slot, if it lists exactly one |
| `decap_vrf` | VRF a plugin-dispatched End.DT4 decapsulates into | no decap grant |
| `vrf` | VRF to advertise into | the scope's VRF, if it lists exactly one |
| `prefix` | IPv4 prefix to advertise behind the SID | no advertisement |
| `next_hop` | IPv6 next hop to advertise with | no advertisement |

A value the configuration does give must agree with the registration: a
behavior it does not claim, a receive prefix outside its headend scope, or a
locator, VRF or slot outside its scope fails registration with an error naming
both values. When the registration lists several candidates and the
configuration names none, registration fails and asks for one. An axis the
registration grants nothing on is not checked; the host still refuses every
declaration outside the scope.

The configuration picks the mode:

- **Receive-only.** No SID or advertisement key. The plugin originates
  nothing and only acts on routes carrying its behavior, which is a
  perfectly ordinary way to run it.
- **Allocating.** Any of `locator`, `slot` or `decap_vrf`. The plugin asks
  the host for a SID, is told the address, and points it at its slot. The
  slot is where its eBPF half lives; [`../plugin-custom-behavior`](../plugin-custom-behavior)
  is that half, and the two are exercised together by the
  `cplane-plugin-2site` interop scenario.
- **Advertising.** Any of `prefix`, `next_hop` or `vrf`, which also
  allocates. `prefix` and `next_hop` are both required: the daemon refuses
  an advertisement with no next hop rather than guessing one.

The receive prefixes matter because the guest receives routes outside its
headend scope too. Filtering them before building the desired set keeps one
rejected route from blocking valid withdrawals. A route must fit wholly
inside one receive prefix.

A plugin may advertise only a SID it was itself allocated: the daemon
refuses a route pointing at any other SID, since one the plugin did not
allocate could belong to another VRF. Fronting a SID an operator
provisioned outside the plugin would need an explicit operator grant the
scope model does not yet carry, so there is no "advertise a given SID" mode.

The route distinguisher and route targets come from the VRF's binding
rather than from this config. A plugin cannot name them: they are what
decides which VPN a peer imports the route into.

`decap_vrf` is the return direction. When the eBPF half hands decapsulated
traffic to a built-in End.DT4, the handoff nulls the SID's own aux so the
plugin cannot spell an arbitrary VRF there. Naming the VRF makes the host
record it in a grant it owns, and the built-in decap reads the VRF from the
grant. It must be a VRF in the plugin's scope, the same set the
advertisement is bound to. Leave it unset for a half that forwards on its
own without a built-in handoff; the built-in decap drops with no grant.

## Notes on the code

`main.go` connects the shared controller to `guest.Register`, which supplies the WASM entry points.
Its `Configure` reads the registration with `guest.Grants()` and passes it to `customcontroller.New` with the configuration bytes.
In [`customcontroller`](../../go/cplane/customcontroller), `RouteView` tracks input paths and replay, and `Client` sends typed desired sets through the injected host transport.
That package decodes the configuration with [`jsonconfig`](../../go/cplane/jsonconfig) and fills unset values from the grants in `Routing.Resolve`.

`vinbero_abi_version` is what lets the daemon refuse a module built against
an ABI it no longer implements, rather than letting it trap on the first
call into a function whose signature moved.

The periodic callback retries failed declarations.
The WASM instance uses host logging and has no filesystem or network access.
The host supplies BGP events and performs the declared writes.
