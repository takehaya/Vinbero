# Vinbero Examples

*(日本語: [README.ja.md](./README.ja.md))*

Playground environments for trying Vinbero's SRv6 features.

This directory contains two kinds of examples:

- **Network namespace examples** (`end-*`, `headend-*` and `gtp*-*` directly under this directory): self-contained scripts that test individual SRv6 features using Linux network namespaces.
  CI runs the examples listed in the `test.yaml` matrix in parallel.
  Examples outside that matrix run locally only.
- **Interoperability labs** ([`interop-clab/`](interop-clab/)): containerlab scenarios for testing Vinbero with third-party implementations such as FRR.

This page covers the network namespace examples.
See the [interoperability lab README](interop-clab/README.md) for containerlab scenarios.

## Build prerequisites

The network namespace examples use `out/bin/vinberod` and `out/bin/vinbero`.
After cloning the repository, build them from the repository root:

```bash
make protobuf-gen && make bpf-gen && make build
```

Without the binaries, `setup.sh` may succeed but `test.sh` fails with `Vinbero failed to start`.

## Quick start

```bash
cd examples/end
sudo ./setup.sh    # Set up the environment
sudo ./test.sh     # Run the tests
sudo ./teardown.sh # Clean up
```

Each example uses its own namespace prefix, such as `end-host1` or `dx4-router1`, so different examples can run in parallel without namespace collisions.

## Add an example

1. Create a directory at `examples/<name>/`.
2. Add the required files:
   - `README.md`: scenario description.
   - `setup.sh`: environment setup using the helpers in `common/`.
   - `test.sh`: test execution.
   - `teardown.sh`: cleanup.
   - `vinbero_*.yaml`: Vinbero configuration.
3. Set `TOPO_NS_PREFIX` to a prefix that does not overlap with other examples.
   Derive it from the directory name or choose a short prefix explicitly:

   ```bash
   EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
   export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"
   # Or use a short prefix: export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx4-}"
   ```

4. Add the example to `matrix.example` in the `Integration Test` job in [`.github/workflows/test.yaml`](../.github/workflows/test.yaml).

## Shared helpers

- **`common/netns.sh`**: create and delete namespaces, enable SRv6, and configure sysctls.
- **`common/veth.sh`**: create veth pairs and configure IP addresses, detecting IPv4 or IPv6 automatically.
- **`common/test_utils.sh`**: check ping connectivity, start vinberod and check readiness, verify root privileges, and print colored output.
- **`common/topologies/three_router.sh`**: create and remove a three-router topology, customized through configuration variables.

## Available examples

### Endpoint functions

| Directory | Behavior | Description |
| --- | --- | --- |
| `end/` | End | Basic SRH endpoint processing |
| `end-x/` | End.X | Cross-connect to a specified next hop |
| `end-t/` | End.T | FIB lookup in a specified VRF |
| `end-dx4/` | End.DX4 | IPv4 decapsulation |
| `end-dx6/` | End.DX6 | IPv6 decapsulation |
| `end-dt4/` | End.DT4 | IPv4 table lookup in a VRF |
| `end-dt6/` | End.DT6 | IPv6 table lookup in a VRF |
| `end-dt2/` | End.DT2 | L2VPN with FDB learning and bridge forwarding |
| `end-dt2-p2mp/` | End.DT2 P2MP | Multisite L2VPN with BUM flooding |
| `end-dt2m-multihomed/` | End.DT2M | Multihomed L2VPN with DF election and split horizon |
| `end-dx2v/` | End.DX2V | Per-VLAN L2 cross-connect |
| `end-un/` | uN | NEXT-C-SID shift forwarding (RFC 9800, F3216) |
| `end-ua/` | uA | NEXT-C-SID shift and adjacency forwarding (RFC 9800, F3216) |
| `end-ut/` | uT | NEXT-C-SID shift and VRF table forwarding (RFC 9800, F3216) |
| `end-udt4/` | uDT4 | End.DT4 at the final uSID in a container, with LPM priority for a zero-padded /128 |
| `end-un-usd/` | uN + USD | Outer decapsulation at the end of a container without an SRH |
| `end-replace/` | End(REP) | REPLACE-CSID container walk (RFC 9800, 32-bit C-SID) |
| `end-t-replace/` | End.T(REP) | REPLACE-CSID container walk using a VRF table, with a main-table blackhole to verify table selection |
| `end-lbs/` | End.LBS | Locator block swap that moves a C-SID sequence to a different block (RFC 9800 Section 7) |

### Headend functions

| Directory | Behavior | Description |
| --- | --- | --- |
| `headend-v4/` | H.Encaps (IPv4) | SRv6 encapsulation of IPv4 packets |
| `headend-v6/` | H.Encaps (IPv6) | SRv6 encapsulation of IPv6 packets |
| `headend-l2/` | H.Encaps.L2 | SRv6 encapsulation of L2 frames |
| `headend-ecmp/` | H.Encaps + ECMP | Headend ECMP path groups and liveness-based fast reroute |

### Mobile (GTP-U)

| Directory | Behavior | Description |
| --- | --- | --- |
| `gtp4-encap/` | H.M.GTP4.D + End.M.GTP4.E | Conversion between GTP-U/IPv4 and SRv6 |
| `gtp6-encap/` | H.M.GTP6.D + End.M.GTP6.E | Conversion between GTP-U/IPv6 and SRv6 |
| `gtp6-drop-in/` | End.M.GTP6.D.Di | GTP-U drop-in mode |

### Plugin extensions

| Directory | Components | Description |
| --- | --- | --- |
| [`custom-cdplane-behavior/`](custom-cdplane-behavior/) | Cplane + Dplane | JSON-configured outer IPv6 source-prefix filtering, BGP SID advertisement, VRF decapsulation, and native/WASM replacement |

Use the SDK to build plugin extensions.
See [`../sdk/examples/`](../sdk/examples/) for build checks and end-to-end demos, and the [Plugin SDK documentation (Japanese)](../docs/design/ja/plugin-sdk.md) for instructions on writing plugins.
