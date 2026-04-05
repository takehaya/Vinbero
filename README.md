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
```

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
| `completion` | | Shell completion scripts |

## Supported SRv6 Functions

See [docs/loadmap.md](./docs/loadmap.md) for supported functions and roadmap.

## Examples

See [examples/](./examples/) for playground environments.

## Trivia
The Vinbero is an Esperanto word meaning `grape`
A meshed node running SRv6 looks like a grape when viewed from above:)
