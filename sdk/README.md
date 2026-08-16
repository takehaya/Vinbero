# Vinbero Plugin SDK

Vinbero's plugin SDK lets you extend vinbero without modifying it. There
are two halves, and a plugin may be either or both.

A **data-plane plugin** is an eBPF object that runs in a reserved
PROG_ARRAY slot, extending the XDP data plane with custom tail call
targets. That is what most of this document is about.

A **control-plane plugin** is a WebAssembly module that runs inside
vinberod: it sees the BGP routes vinbero receives, and declares the
forwarding state, the local SIDs and the advertisements it wants. See
[Control-plane plugins](#control-plane-plugins) below.

Both are loaded and unloaded dynamically over the Connect RPC
`PluginService` API or the `vinbero plugin` CLI.

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
- `/usr/local/share/vinbero-sdk/{README.md,LICENSE,examples/}` — docs and worked examples

### From an in-tree checkout (for vinbero developers)

```bash
git clone https://github.com/takehaya/Vinbero
cd Vinbero
sudo make install-sdk
```

This installs the same files from the working tree without producing a tarball.

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

A control-plane plugin is a WebAssembly module. Where a data-plane plugin
decides what happens to a packet, a control-plane plugin decides what the
forwarding state should be: it is handed the routes vinbero receives and
declares what it wants installed, advertised, or allocated.

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

The module exports a small ABI -- `alloc`, `free`, `handle_events`, and
optionally `configure` and `on_tick` -- and imports host functions from
the `vinbero` module. Which host functions are linked depends on the
capabilities the plugin was granted: one it was not granted is not a call
that fails but a function it cannot reach. `docs/design/ja/cplane-plugin.md`
documents the ABI and the lifecycle in full.

### Writing one

TinyGo is the supported toolchain today. The worked example is
`sdk/examples/cplane-custom-behavior/`, which implements both directions
of the custom-behavior case and is what the `cplane-plugin-2site` interop
lab runs. Its README covers the build flags and why each is needed.

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
