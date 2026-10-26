# Cplane and Dplane plugins together

Run the existing custom-behavior SDK plugins through two real `vinberod` processes, BGP and customer traffic, using four Linux network namespaces.
This is the Docker-free counterpart of the [two-site containerlab scenario](../interop-clab/scenarios/cplane-plugin-2site/README.md).

```text
host1                 PE1                    PE2                  host2
10.1.0.10 ---- Cplane receiver ===== Cplane advertiser ---- 10.2.0.10
                H.Encaps            Dplane endpoint slot32
                                    counter -> End.DT4
```

The [Cplane controller](../../sdk/examples/cplane-custom-behavior/README.md) on PE2 requests a local SID and advertises `10.2.0.0/24` with behavior `0xFE01` over BGP.
The same controller on PE1 claims that behavior and installs the headend entry pointing at the advertised SID.
Packets reach the [Dplane plugin](../../sdk/examples/plugin-custom-behavior/README.md) in PE2's endpoint slot32, which counts them and hands them to the built-in End.DT4 for decapsulation into `vrf-cust`.
The customer route exists only in that VRF's table, so the reply proves actual decapsulation and delivery, in addition to plugin invocation.
The return path uses an ordinary VPN route and built-in End.DT4.

The controller source is shared between the native and WASM builds.
The Dplane plugin is an eBPF ELF in both cases; selecting WASM changes the Cplane runtime.
No new SDK, behavior implementation or plugin binary is added by this example.

Build from the repository root with the pinned toolchain from `mise.toml`:

```sh
mise install
make build
make -C sdk/examples/plugin-custom-behavior BPF_CLANG=clang-18
# Optional: rebuild the committed Cplane WASM artifact from its shared source.
make cplane-example
```

The host needs root privileges, Linux network namespaces, veth, VRF and generic XDP support.
On Debian/Ubuntu, install `iproute2`, `iputils-ping`, `jq`, `clang-18`, `libbpf-dev` and `libelf-dev`.
Load the `vrf` module if the kernel does not provide it directly.
Then run:

```sh
cd examples/cplane-dplane
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

`test.sh` starts the daemons, registers both plugin halves through the CLI/RPC interface and checks:

1. Native Cplane controllers establish forwarding through the BGP-advertised, dynamically allocated SID and Dplane slot32.
2. Three customer pings complete and the slot32 counter increases by at least three.
3. Same-name registrations replace both controllers with WASM, then native again, without restarting the daemons or replacing the established BGP sockets.
   Each stable state repeats the SID, ping and counter checks.
4. Unregistering the advertising controller retracts the remote headend and local SID, after which customer pings fail.

This tests forwarding after convergence at each stage; it does not measure packet loss during replacement.
PE1 receives only the `headend` capability for `10.2.0.0/24`.
PE2 receives only `advertise` and `local_sid`, scoped to its locator, VRF and slot32.

The example reserves the `cpdp-*` namespace names and refuses to replace existing namespaces.
The test stops its own daemon processes on exit and prints the unique `/tmp/vinbero_cpdp.*` directory containing logs and per-daemon resource state.
Plugin persistence and BPF map pinning are disabled because network namespaces share the filesystem.
Run `teardown.sh` after the test to remove the four namespaces; it refuses while processes remain.
