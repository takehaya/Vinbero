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

### Run

```bash
sudo ./out/bin/vinbero -c vinbero.yml
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

### API Examples

Register SRv6 SID function (End.DX4):
```bash
curl -X POST http://localhost:8080/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{"sid_functions": [{"trigger_prefix": "fc00::1/128", "action": "SRV6_LOCAL_ACTION_END_DX4"}]}'
```

Register Headend encapsulation (H.Encaps for IPv4):
```bash
curl -X POST http://localhost:8080/vinbero.v1.Headendv4Service/Headendv4Create \
  -H "Content-Type: application/json" \
  -d '{"headends": [{"trigger_prefix": "192.0.2.0/24", "src_addr": "fc00::1", "segment_list": ["fc00::100", "fc00::200"], "behavior": "SRV6_HEADEND_BEHAVIOR_H_ENCAPS"}]}'
```

## Supported SRv6 Functions

See [docs/loadmap.md](./docs/loadmap.md) for supported functions and roadmap.

## Examples

See [examples/](./examples/) for playground environments.

## Trivia
The Vinbero is an Esperanto word meaning `grape`
A meshed node running SRv6 looks like a grape when viewed from above:)
