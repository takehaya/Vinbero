# Vinbero Plugin SDK

Vinbero's plugin SDK lets you extend the XDP data plane with custom tail
call targets without modifying vinbero itself. Plugins run in reserved
PROG_ARRAY slots and are loaded/unloaded dynamically over the Connect
RPC `PluginService` API or the `vinbero plugin` CLI.

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

## Build

1. Install the SDK headers:
   ```
   sudo make install-sdk   # from vinbero source
   ```
2. Create a one-line Makefile that includes the SDK template:
   ```
   echo 'include /usr/local/include/vinbero/Makefile.plugin' > Makefile
   make
   ```
   The template picks up every `*.c` in the directory and builds `*.o`.
   See `sdk/examples/*/Makefile` for the in-tree pattern (overrides
   `VINBERO_SDK_ROOT` / `VINBERO_CORE_ROOT` for local builds).
3. Validate locally before uploading:
   ```
   vinbero plugin validate --prog plugin.o --program my_plugin
   ```
4. Register with a running vinbero:
   ```
   vinbero -s http://localhost:8080 plugin register \
       --type endpoint --index 32 --prog plugin.o --program my_plugin
   ```

## Directories

- `c/include/vinbero/` - public C headers (re-export of internal vinbero
  headers; treat these as the stable API surface)
- `c/Makefile.plugin` - build template for plugin ELFs
- `examples/plugin-counter/` - packet counter + three-router E2E demo
  (`setup.sh` / `test.sh` / `teardown.sh`)
- `examples/simple-acl/` - IPv6 source ACL, `CALL_WITH_CONST_L3` helper
  demo (build + validate only)

## Observability

- Per-action global counters (RX / PASS / DROP / REDIRECT / ERROR):
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
