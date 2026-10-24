# MUP route composition guest

This example imports the shared [`mupcontroller`](../../go/cplane/mupcontroller) package, which is also used by the daemon's native adapter.
The controller source is maintained once and compiled for each target.
It joins authorized MUP routes in a shared View and submits a complete forwarding set after each ready revision.
The default configuration observes routes and logs the number of buildable entries without calling the output API.
The default build also omits the host's write imports, so it needs no write capability and cannot be switched to writing through configuration.

The downlink rule matches each ST1 endpoint against ISD prefixes, chooses the longest prefix, and requires a unique result after equivalent candidates are combined.
The uplink rule matches ST2 and DSD Direct Segment communities and requires a unique result.
These are application selection rules; they do not run BGP best-path selection.

## Build and observe

Run these commands from this directory with Go 1.25.5 or later:

```sh
(cd ../../.. && go test -race ./sdk/go/cplane/mupcontroller)
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w" -o plugin.wasm .
vinbero plugin cplane register \
  --name mup-composition --wasm plugin.wasm \
  --family mup_ipv4 --family mup_ipv6 \
  --input-policy policy.json --config config.json --tick-ms 1000
```

The host must implement context input API v1 and the pinned GoBGP binary codec.
The example imports `input_features` and rejects a missing or incompatible configure envelope.
Both MUP families are required because the selector factories inspect both families.
The host grants only routes carrying RT `65000:7` to the `mobile` context in this policy.
Adjust the policy to your deployment before registration.

`config.json` supplies an explicit IPv6 outer source and SID argument offset in bytes.
The default offset of 7 expects the ISD service SID's locator and function to occupy 56 bits, leaving at least 72 argument bits.
The GTP4 downlink builder checks that structure, embeds the gNB IPv4 address, QFI, and TEID, and uses RQI 0.
The example does not derive its outer source from another session route.

## Enable forwarding

Writing requires both an explicit `"observe_only": false` in the operator configuration and host authorization.
Build a separate writing artifact with the `composition_write` tag:

```sh
GOOS=wasip1 GOARCH=wasm go build -tags composition_write -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w" -o plugin-write.wasm .
```

Make a copy of `config.json` named `config-write.json`, set that field to false, and supply the correct source and argument offset.
Unregister the observing instance before changing its input policy:

```sh
vinbero plugin cplane unregister --name mup-composition
vinbero plugin cplane register \
  --name mup-composition --wasm plugin-write.wasm \
  --family mup_ipv4 --family mup_ipv6 \
  --input-policy policy-write.json --config config-write.json \
  --capability mup --capability headend \
  --headend-prefix 10.0.0.0/24 --headend-prefix 192.0.2.0/24 \
  --tick-ms 1000
```

The write policy delegates ST1 and ST2 processing for the global MUP instance (`mup_vrf` is empty).
It bounds ST2 outputs to endpoints in `192.0.2.0/24` and permits all TEIDs with `0/0`.
The command grants headend keys for downlink trigger prefixes in `10.0.0.0/24` and uplink endpoint gates in `192.0.2.0/24`.
Choose these scopes deliberately: delegation hands the selected built-in processing to the plugin, including routes the builders cannot turn into an output.
Input policy changes require unregistering and completing cleanup before registering again.
To return to observation, unregister the writing instance and register with the observation command above.

The host retains final control of capabilities, context delegation, output scope, ownership conflicts, and recovery.
The guest does not install local SIDs or advertise routes; provision the receiving SRv6 behaviors separately.

## Batch live updates

Use `--input-policy policy-write-batched.json` with either backend to permit up to 16 queued live events per controller call.
This policy has the same grants, delegation, and output bounds as `policy-write.json`; it only sets `max_batch_events` to 16.
The host takes events already waiting in the queue and adds no collection delay, so a call can contain fewer than 16 events.
Leaving this field unset or setting it to 0 or 1 retains one-event delivery; explicit values from 2 through 16 enable batching.
Replay boundaries and ticks remain separate from live batches.

The controller reconciles the final route view of each batch, so intermediate versions in that batch need not become forwarding state.
A batch shares one call timeout; choose a cap that fits the controller's call budget.
If input preparation fails for one event, the host rejects the whole group and requests input recovery.
For a changed, ready view, the controller attempts one complete desired-set transaction per batch; this does not guarantee atomic rollback of BPF writes.
Queue overflow still marks input incomplete and triggers cleanup and replay.
To apply a different input policy, unregister and finish cleanup before registering again, as described above.

## Updates and recovery

The controller waits for a complete BGP replay before constructing outputs.
Each successful apply records the View revision; unchanged ticks perform no writes.
A failed apply leaves that revision pending, so the next event or tick rebuilds the full desired set from the latest ready View.
Replay and incomplete input suspend retries, and a completed empty replay submits an empty set to withdraw the plugin's outputs.
The tick interval in the registration command enables retries when no further routes arrive.

Unresolved or ambiguous pairs are omitted and reported through diagnostics.
Built outputs are also grouped by their actual forwarding key: equivalent values collapse, while every value for a conflicting key is omitted and diagnosed.
This includes reflected copies of one route and different RDs that map to the same headend trigger.
An uplink also claims its endpoint `/32` as a shared MUP gate, so a downlink with that exact trigger conflicts across output types.
All successful raw builder outputs contribute to that collision check before either list is reduced; the controller omits every claimant without giving one output type priority.
A pair that fails the builder's profile checks is also omitted, allowing its previous output to be withdrawn in the next complete set.
The first profile supports GTP4 ST1+ISD and ST2+DSD; ST2+ISD and GTP6 writes are unsupported.
Missing, duplicate, and unsupported Direct Segment communities are distinct from a valid zero-valued community.

Native tests exercise both rules, the client transport, withdrawal, empty replay, incomplete input, and retries after newer updates.
The standard Go WASI build is supported here; TinyGo compatibility has not been tested.

## Run the same controller natively

The daemon can statically link the same controller under implementation ID `mup-composition`, version `1`.
The observation profile is `mup-composition-observer`, version `1`; supplying write configuration to this profile is rejected.
Native is the default backend and is enabled by default in the daemon; `settings.cplane_plugins.native_enabled: false` restricts execution to WASM.
Use the same input policy, configuration, capabilities, scope and tick interval as the WASM command, replacing `--wasm plugin-write.wasm` with `--native mup-composition`.
For observation, replace `--wasm plugin.wasm` with `--native mup-composition-observer`.
The implementation ID defaults to the registration name, so it can also be omitted when those names match.
Use `--native-version 1` to pin the version; otherwise the daemon resolves and persists its catalog version.
Use the existing same-name replacement or unregister workflow; a backend is never selected by fallback.

The native adapter uses the same encoded events, results and output transactions, and the manager retains policy checks and reconciliation.
Native calls run serially, with cooperative cancellation and panic recovery; a hung call cannot be forcibly stopped in-process and can block shutdown.
WASM memory limits do not impose a per-instance native heap limit.
The daemon persists a native identity derived from controller/SDK/adapter source, dependency pins and Go toolchain, and refuses restoration if that identity changes.
Adding or upgrading native implementations requires rebuilding the daemon.

To check both builds from the repository root:

```sh
make cplane-route-composition cplane-route-composition-observer
VINBERO_CPLANE_PARITY=1 go test ./pkg/cplane/native
```

The parity tests replay the same GoBGP-encoded paths through both adapters and compare event statuses and output transactions, including retries and observation-only behavior.
They complement manager tests of final map state; passing them does not establish a performance advantage.
