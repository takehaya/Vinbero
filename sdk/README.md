# Vinbero Plugin SDK

Vinbero's plugin SDK lets you extend vinbero without modifying it. There
are two halves, and a plugin may be either or both.

A **data-plane plugin** is an eBPF object that runs in a reserved
PROG_ARRAY slot, extending the XDP data plane with custom tail call
targets. That is what most of this document is about.

A **control-plane plugin** extends routing logic by observing BGP routes and declaring forwarding state, local SIDs, and advertisements.
Upload a WebAssembly module to add or upgrade that logic while `vinberod` is running, without rebuilding the daemon.
Shared Go controllers can also be statically linked into the daemon and registered through the native backend.
Start with [Control-plane plugins](#control-plane-plugins) below for the WASM walkthrough and backend selection.
The [context route API](cplane-route-api.md) adds authorized Views, typed route joins, and owned composition outputs.

Register and unregister plugins through the Connect RPC `PluginService` API or the `vinbero plugin` CLI.
New eBPF and WASM code is supplied as an artifact; native registration selects an implementation already compiled into the daemon.

Rebuild data-plane plugins that read the FDB against these headers.
Use `fdb_read_forward()` for one coherent forwarding snapshot and the lookup key's BD ID for peer lookups; separate field loads can mix concurrent MAC-learning updates.
The FDB map layout remains 32 bytes, so existing pinned maps do not need migration.

## Slot ranges

| Map              | Builtin | Reserved | Plugin     |
|------------------|---------|----------|------------|
| `sid_endpoint_progs` | 0-21   | 22-31    | **32-63**  |
| `headend_v4_progs`   | 0-7    | 8-15     | **16-31**  |
| `headend_v6_progs`   | 0-7    | 8-15     | **16-31**  |

## Return contract

Plugins either return through `tailcall_epilogue(ctx, action)` (leaf) or
`bpf_tail_call` into one of the vinbero PROG_ARRAYs (handoff). The
server validator rejects ELFs that satisfy neither.

The recommended way to write a plugin is the `VINBERO_PLUGIN(name)`
macro, which generates a `SEC("xdp")` wrapper that always returns
through `tailcall_epilogue`:

```c
#include <vinbero/plugin.h>
#include <vinbero/maps.h>

VINBERO_PLUGIN(my_plugin)
{
    if (err) return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

## Installation

Two options:

### From a release tarball (recommended for plugin authors)

```bash
curl -L https://github.com/takehaya/Vinbero/releases/download/vX.Y.Z/vinbero-sdk-vX.Y.Z.tar.gz \
  | sudo tar xz -C /usr/local/
```

This installs:

- `/usr/local/include/vinbero/*.h` — public ABI headers
- `/usr/local/include/core/*.h` — internal headers referenced by the public ones
- `/usr/local/include/vinbero/Makefile.plugin` — build template for plugin projects
- `/usr/local/share/vinbero-sdk/{README.md,LICENSE}` — SDK overview and license
- `/usr/local/share/vinbero-sdk/proto/vinbero/v1/cplane_plugin.proto` — control-plane wire contract

Examples and Go packages remain in the repository; the tarball does not install them.
The packaged README links to repository documentation at the source commit used to build the SDK (or `main` when built without Git metadata).

### From an in-tree checkout (for vinbero developers)

```bash
git clone https://github.com/takehaya/Vinbero
cd Vinbero
sudo make install-sdk
```

This target installs the C headers and build template from the working tree.
Use this checkout for the documentation, examples, and Go packages.

## Build

1. Create a one-line Makefile that includes the SDK template:
   ```
   echo 'include /usr/local/include/vinbero/Makefile.plugin' > Makefile
   make
   ```
   The template picks up every `*.c` in the directory and builds `*.o`.
   See `sdk/examples/*/Makefile` for the in-tree pattern (overrides
   `VINBERO_SDK_ROOT` / `VINBERO_CORE_ROOT` for local builds).
2. Validate locally before uploading:
   ```
   vinbero plugin validate --prog plugin.o --program my_plugin
   ```
3. Register with a running vinbero:
   ```
   vinbero -s http://localhost:8080 plugin register \
       --type endpoint --index 32 --prog plugin.o --program my_plugin
   ```

## Plugin aux: passing config per SID

Plugins can read per-SID configuration from `sid_aux_entry.plugin_raw`
(256 bytes). Declare a matching struct in the plugin source and anchor
it so clang keeps the type in BTF:

```c
#include <vinbero/plugin.h>
#include <vinbero/types.h>

struct my_plugin_aux {
    __u32            limit;
    vinbero_mac_t    match_mac;
    struct vinbero_ipv6_prefix_t source;
};
VINBERO_PLUGIN_AUX_TYPE(my_plugin, my_plugin_aux);
```

Inside the plugin body, fetch the aux via `TAILCALL_AUX_LOOKUP` and cast
with `VINBERO_PLUGIN_AUX_CAST`:

```c
TAILCALL_AUX_LOOKUP(tctx, aux);
if (aux) {
    struct my_plugin_aux *cfg =
        VINBERO_PLUGIN_AUX_CAST(struct my_plugin_aux, aux);
    ...
}
```

On the CLI side there are three ways to attach aux data to a SID, and
they are mutually exclusive per SID:

```
# A) inline JSON — server encodes via plugin BTF, aux lives with the SID
vinbero sid create --action 32 \
  --plugin-aux-json '{"limit": 100,
                      "match_mac": "aa:bb:cc:dd:ee:ff",
                      "source": "fc00:1::/64"}'

# B) hex bytes — bypass BTF, caller pre-encodes
vinbero sid create --action 32 --plugin-aux-hex <hex>

# C) reference a standalone aux allocated separately
IDX=$(vinbero plugin aux alloc --map-type endpoint --slot 32 \
        --json '{"limit":200}' | jq -r .index)
vinbero sid create --action 32 --plugin-aux-index "$IDX"
```

Well-known SDK typedefs (`vinbero_mac_t`, `vinbero_ipv4_t`,
`vinbero_ipv6_t`, `vinbero_ipv4_prefix_t`, `vinbero_ipv6_prefix_t`)
get parsed from their natural string forms. Plain arrays and integers
accept hex or decimal strings / JSON numbers.

### Standalone aux lifecycle

The `vinbero plugin aux` subcommands manage aux entries independently of
SID creation. Each entry carries an owner tag (`plugin:<map_type>:<slot>`)
so only the slot that allocated it can touch it:

```
vinbero plugin aux alloc  --map-type endpoint --slot 32 --json '{...}'
vinbero plugin aux update --map-type endpoint --slot 32 --index 1 --json '{...}'
vinbero plugin aux get    --map-type endpoint --slot 32 --index 1
vinbero plugin aux free   --map-type endpoint --slot 32 --index 1
```

Standalone aux entries are **not persisted across daemon restarts** —
see [`docs/design/ja/persistence.md`](../docs/design/ja/persistence.md)
for details.

### Go client wrapper

For Go controllers there's a small typed wrapper under
`sdk/go/plugin`:

```go
import "github.com/takehaya/vinbero/sdk/go/plugin"

aux := plugin.NewPluginAux[MyAuxStruct](client, "endpoint", 32)
idx, _ := aux.Alloc(ctx, MyAuxStruct{Limit: 100})
v, _   := aux.Get(ctx, idx)
_       = aux.Free(ctx, idx)
```

`MyAuxStruct` must be a fixed-size, little-endian, C-struct compatible
layout (it is decoded from the on-wire raw bytes via
`encoding/binary`).

## Directories

- `c/include/vinbero/` - public C headers (re-export of internal vinbero
  headers; treat these as the stable API surface)
- `c/Makefile.plugin` - build template for plugin ELFs
- `examples/plugin-counter/` - packet counter with aux-driven increment,
  three-router E2E demo
- `examples/plugin-acl-prefix/` - source-prefix ACL driven by aux
  (`vinbero_ipv6_prefix_t`), three-router E2E demo
- `examples/simple-acl/` - IPv6 source ACL via hash map,
  `CALL_WITH_CONST_L3` helper demo (build + validate only)

## Observability

- Registered plugins (program name, aux type, map classification):
  ```
  vinbero plugin list                  # MAP_TYPE / SLOT / PROGRAM / AUX / REGISTERED
  vinbero plugin list --type endpoint  # filter by PROG_ARRAY
  vinbero plugin list -v               # expand owned / shared RO / shared RW maps
  ```
- Per-action global counters (RX / PASS / DROP / REDIRECT / ABORTED):
  ```
  vinbero stats show
  ```
- Per-slot invocation counters (builtin + plugin, labeled by function name):
  ```
  vinbero stats slot show                  # all slots, packets>0
  vinbero stats slot show --type endpoint  # one PROG_ARRAY only
  vinbero stats slot show --plugin-only    # only plugin slots
  vinbero stats slot show --top 10         # hot slots first
  ```
  Requires `enable_stats: true` in `vinbero.yml`. Plugin slots are
  labeled `plugin:<program_name>` based on the registration.

For packet capture / deep inspection, use the external `xdp-ninja` tool.
The SDK does not require any BPF-side instrumentation for this.


## Control-plane plugins

A control-plane plugin receives BGP events and declares the state it wants installed, advertised, or allocated.
Its WASM artifact is a dynamic extension point: an operator can load new routing logic through the API without rebuilding or restarting the daemon.
The host applies authorized declarations to the existing forwarding and BGP machinery.
WASM runs in the daemon's wazero runtime; the plugin does not process packets in the kernel.

### Load a WASM observer

Use a checkout containing the control-plane SDK and a Go version supported by its `go.mod`.
The development toolchain is recorded in `mise.toml`.
Run the following commands from the repository root, with `vinbero` on `PATH` and a running daemon reachable at the CLI's server address:

```sh
make cplane-bgp-observer
vinbero plugin cplane register --name route-audit \
  --wasm out/cplane-bgp-observer.wasm --family evpn
vinbero plugin cplane stats --name route-audit
```

The module logs route events and requests no write capabilities, so it cannot install forwarding state or originate routes.
Configure BGP peers and the selected address family separately; registration subscribes to received events and does not establish sessions.
The registration name `route-audit` need not identify a native implementation because `--wasm` supplies the code.
See the [observer example](examples/cplane-bgp-observer/README.md) for its input requirements and log format.

To upgrade, build the new module and repeat registration with the same name and the required configuration and grants.
To remove this observer:

```sh
vinbero plugin cplane unregister --name route-audit
```

For writing plugins, replacement and cleanup depend on their input authority, configuration, and owned outputs.
Same-name replacement can retain compatible forwarding state, but it is not an unconditional loss-free handoff guarantee.
The [lifecycle reference](../docs/design/ja/cplane-plugin.md#lifecycle) specifies those conditions.

### Selecting a backend

| | WASM | Native |
| --- | --- | --- |
| Code supplied at registration | A `.wasm` file through `--wasm` | An ID already in the daemon's implementation catalog |
| Adding or updating controller code | Rebuild the module and register it with the running daemon | Rebuild and deploy the daemon |
| Execution boundary | Guest linear-memory limit and call timeout | In-process execution with cooperative cancellation |
| Go controller source | Shared controller package called through the guest adapter | The same package called through the native adapter |

The CLI selects native when `--wasm` is omitted.
For the linked observer, register `--name route-audit --native bgp-observer --family evpn`; this selects the same shared controller used above.
Without `--native`, the implementation ID defaults to the registration name; `--native-version` can pin its catalog version.
Native execution is enabled by default, and `settings.cplane_plugins.native_enabled: false` restricts the daemon to WASM registrations.
This setting does not add a native copy of a new WASM plugin: native support requires an explicit adapter and a daemon build.
An invalid WASM module is rejected rather than falling back to native.
Treat native implementations as trusted daemon code; they have no per-instance heap cap or forced call termination.

### Routing policies

The case it exists for is an SRv6 endpoint behavior of your own. The
behavior is a 16-bit codepoint inside the SID TLV, so a plugin can claim
one, advertise routes naming it, and act on routes carrying it -- with no
new BGP family and nothing to standardize first. Vinbero's own appliers
never see a claimed route, because they read a service SID without
consulting its behavior and would install it with the wrong meaning.

### The contract

Everything crossing the boundary is protobuf, defined in
`vinbero/v1/cplane_plugin.proto` (shipped in this tarball under
`share/vinbero-sdk/proto/`). Generate bindings from it in whatever
language you write the plugin in.

The module exports a small ABI -- `alloc`, `free`, `handle_events`,
`vinbero_abi_version`, and optionally `configure`, `on_tick` and the
reactor initializer `_initialize` -- and imports host functions from the
`vinbero` module. A module missing `vinbero_abi_version` is refused at
registration: it is what lets the daemon turn away a plugin built against
an ABI it no longer implements, rather than letting it trap on the first
call into a function whose signature moved.

Which host functions are linked depends on the capabilities the plugin was
granted. That is the coarse half of the gate: a plugin granted nothing that
writes cannot reach the apply functions at all -- they are not calls that
fail but functions it cannot import. The apply functions are shared across
the kinds of declaration, so which kind a plugin may declare is checked
where it opens the transaction instead: one granted `advertise` alone is
refused when it opens a headend transaction.
The [Japanese design reference](../docs/design/ja/cplane-plugin.md) documents the ABI, event delivery, authorization, and lifecycle in full.

### Writing one

The [Go guest SDK](go/cplane/README.md) supplies Go WASM entry points,
typed events and desired-set declarations, and a prefix-route view that handles
BGP replay boundaries. The plugin supplies route selection and the forwarding
state it wants. Host ownership and scope checks still apply to every declaration.

Standard Go WASI reactors are the default build; TinyGo remains an optional smaller artifact.
Choose a worked example by the policy being implemented:

| Example | Purpose |
| --- | --- |
| [BGP observer](examples/cplane-bgp-observer/README.md) | Read received GoBGP paths without write capabilities |
| [Custom behavior](examples/cplane-custom-behavior/README.md) | Claim a behavior, allocate local SIDs, advertise routes, and declare headend state |
| [JSON-configured Cplane and Dplane](examples/cplane-custom-cdplane-behavior/README.md) | Configure an outer source-prefix policy, advertise its service SID, and use native or WASM with the same JSON |
| [MUP composition](examples/cplane-route-composition/README.md) | Join authorized MUP routes and build forwarding outputs |
| [IMET-gated EVPN](examples/cplane-evpn-imet/README.md) | Join RT2 and RT3 for an optional static MAC policy |

The custom-behavior example is exercised by the `cplane-plugin-2site` interop lab.
Each example documents its grants, build options, and supported profile.

The [context route API](cplane-route-api.md) defines authorized views, generic join rules, and complete composition outputs for MUP and EVPN.

The guest SDK is a Go package in this repository's module. The header/proto
tarball does not install Go packages; use a checkout or a Go module dependency
pinned to a Vinbero revision containing the SDK.

Rust is a natural fit for this ABI -- `wasm32-unknown-unknown` with
`prost` in a `no_std + alloc` profile covers everything the boundary needs
-- but no Rust shim ships here yet, because none has been built and tested
against the daemon. The ABI is small and fully documented, so writing one
does not require anything this SDK withholds.

### Testing one

`sdk/go/cplaneharness` runs a plugin against the real runtime with no
daemon: it drives the sequences that matter (a rib replay, a restart, a
refused commit) and hands back what the plugin declared as ordinary Go
values. A plugin that quietly depends on state from before a restart
passes every other test and fails there.
