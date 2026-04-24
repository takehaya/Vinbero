# Vinbero
Vinbero is a very fast high-performance SRv6 implementation.

<div style="text-align:center;">
<img src="./design/logo-w.png" width="400">
</div>

The [previous implementation](
https://github.com/takehaya/Vinbero-legacy/tree/master) has become outdated, so we decided to reimplement it with a new codebase.

## Quickstart

### Build

```bash
make protobuf-gen
make bpf-gen
make build
```

This produces two binaries:
- `out/bin/vinberod` — SRv6 daemon (XDP/TC dataplane + Connect RPC server)
- `out/bin/vinbero` — CLI client for managing the daemon

### Run

```bash
# Start the daemon
sudo ./out/bin/vinberod -c vinbero.yml
```

### Configuration

```yaml
# vinbero.yml
internal:
  devices:
    - eth0
  bpf:
    device_mode: "driver"  # or "generic"
  server:
    bind: "0.0.0.0:8080"
  logger:
    level: info

settings:
  enable_stats: true      # needed for `vinbero stats ...`
  pin_maps:
    enabled: true         # optional: keep control-state across restarts
    path: /sys/fs/bpf/vinbero
```

See [`docs/design/ja/configuration.md`](./docs/design/ja/configuration.md) for
the full field reference and [`docs/design/ja/persistence.md`](./docs/design/ja/persistence.md)
for what survives a restart with and without `pin_maps`.

## CLI

`vinbero` CLI provides a convenient interface to the daemon's Connect RPC API.

```bash
# Set default server address (optional, defaults to http://localhost:8080)
export VINBERO_SERVER=http://localhost:8080

# Network resources
vinbero vrf create --name vrf100 --table-id 100 --members eth0 --enable-l3mdev-rule
vinbero br create --name br100 --bd-id 100 --members eth1

# SRv6 SID functions
vinbero sid create --trigger-prefix fc00::1/128 --action END_DT4 --vrf-name vrf100
vinbero sid create --trigger-prefix fc00::2/128 --action END_DT2 --bd-id 100 --bridge-name br100
vinbero sid list

# Headend encapsulation
vinbero hv4 create --trigger-prefix 192.0.2.0/24 --src-addr fc00::1 --segments fc00::100,fc00::200
vinbero hl2 create --interface eth1 --vlan-id 100 --src-addr fc00::1 --segments fc00::100,fc00::200 --bd-id 100

# BUM flood peers
vinbero peer create --bd-id 100 --src-addr fc00::1 --segments fc00::100,fc00::200

# FDB (MAC address table)
vinbero fdb list

# VLAN cross-connect (End.DX2V)
vinbero vt create --table-id 5 --vlan-id 100 --oif <ifindex>

# Stats: global + per-tail-call-slot
vinbero stats show
vinbero stats slot show --type endpoint --plugin-only

# Custom XDP plugins
vinbero plugin validate --prog plugin.o --program plugin_counter
vinbero plugin register --type endpoint --index 32 \
    --prog plugin.o --program plugin_counter
vinbero sid create --trigger-prefix fc00:2::32/128 --action 32 \
    --plugin-aux-json '{"increment": 10}'

# Bulk flush (requires --yes)
vinbero sid flush --yes
vinbero fdb flush --yes --keep-static
vinbero peer flush --yes --bd-id 100

# JSON output
vinbero --json sid list

# Specify server address per command
vinbero -s http://192.168.1.1:8080 sid list
```

### Shell Completion

```bash
# bash
eval "$(vinbero completion bash)"

# zsh
eval "$(vinbero completion zsh)"
```

### Available Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `sid-function` | `sid` | SRv6 SID endpoint functions (End, End.DT4, End.DT2, etc.) |
| `headend-v4` | `hv4` | SRv6 Headend for IPv4 (H.Encaps) |
| `headend-v6` | `hv6` | SRv6 Headend for IPv6 (H.Encaps) |
| `headend-l2` | `hl2` | SRv6 Headend for L2 frames (H.Encaps.L2) |
| `bd-peer` | `peer` | Bridge Domain remote PE management |
| `bridge` | `br` | Linux bridge device management |
| `vrf` | | Linux VRF device management |
| `fdb` | | FDB (MAC address table) entries |
| `vlan-table` | `vt` | VLAN cross-connect table for End.DX2V |
| `stats` | | Global and per-slot packet statistics |
| `plugin` | | Register / unregister custom BPF plugins |
| `completion` | | Shell completion scripts |

Each resource command carries a `flush` subcommand (requires `--yes`) that
clears the underlying BPF map in one call; useful together with
`settings.pin_maps.enabled` for resetting persistent state without
removing the pin directory.

## Supported SRv6 Functions

See [docs/loadmap.md](./docs/loadmap.md) for supported functions and roadmap.

## Plugins

Vinbero's XDP data plane can be extended with custom BPF plugins.
Plugins are loaded into reserved PROG_ARRAY slots and can be dynamically
registered / unregistered via the Connect RPC API or the `vinbero plugin` CLI.

### Quick Start

```c
#include <vinbero/plugin.h>

VINBERO_PLUGIN(my_plugin)
{
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
```

```bash
# Build, validate, and register
make -f /usr/local/include/vinbero/Makefile.plugin
vinbero plugin validate --prog my_plugin.o --program my_plugin
vinbero plugin register --type endpoint --index 32 \
    --prog my_plugin.o --program my_plugin
```

### Plugin Aux (per-SID Config)

Declare a struct with the `VINBERO_PLUGIN_AUX_TYPE` macro, and JSON
passed via `--plugin-aux-json` is automatically encoded into the
plugin's byte layout through BTF.

SDK-provided types accept their natural string representations:

| Type | JSON Example |
|------|-------------|
| `vinbero_mac_t` | `"aa:bb:cc:dd:ee:ff"` |
| `vinbero_ipv4_t` | `"192.0.2.1"` |
| `vinbero_ipv6_t` | `"fc00::1"` |
| `vinbero_ipv4_prefix_t` | `"192.0.2.0/24"` |
| `vinbero_ipv6_prefix_t` | `"fc00:1::/64"` |

Runnable examples live under [`sdk/examples/`](./sdk/examples/).
See [`sdk/README.md`](./sdk/README.md) for the full SDK reference.

## Examples

See [examples/](./examples/) for playground environments.

## Trivia
The Vinbero is an Esperanto word meaning `grape`
A meshed node running SRv6 looks like a grape when viewed from above:)
