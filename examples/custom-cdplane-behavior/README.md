# Custom Cplane and Dplane behavior

Advertise a service over BGP and let its Dplane endpoint accept packets from a configured outer IPv6 source prefix before decapsulating into a VRF.
The Cplane controller uses the same Go implementation for native and WASM execution.
The Dplane is an eBPF program in both cases.

```text
host1                 PE1                     PE2                  host2
10.1.0.10 ---- Cplane receiver ===== Cplane advertiser ---- 10.2.0.10
                H.Encaps             source-prefix filter
                                     -> End.DT4 -> vrf-cust
```

PE2 allocates a service SID and advertises `10.2.0.0/24` with endpoint behavior `0xFE01`.
PE1 receives the route and installs a headend entry pointing at that SID.
PE2's endpoint permits outer IPv6 source `fd00:100::/128`, then uses the host's VRF grant to call End.DT4.
This is PE1's headend source derived from `LOC1`, as shown by `headend-v4 list`; it differs from the BGP next hop `2001:db8:ff::1`.
The customer route exists only in `vrf-cust`, so successful pings also verify decapsulation and delivery.
The return path uses an ordinary VPN route and built-in End.DT4.
The source-prefix policy is local to PE2; it is not advertised over BGP and is not cryptographic authentication.

## Build and run the checks

Build a matching daemon, Cplane WASM module and Dplane ELF from this checkout:

```sh
mise install
make build cplane-custom-cdplane-behavior
make -C sdk/examples/plugin-custom-cdplane-behavior BPF_CLANG=clang-18
cd examples/custom-cdplane-behavior
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

The host needs root privileges, Linux network namespaces, veth, VRF and generic XDP support.
On Debian/Ubuntu, the example uses `iproute2`, `iputils-ping`, `jq`, `bpftool`, `clang-18`, `libbpf-dev` and `libelf-dev`.
Load the `vrf` module if the kernel does not provide it directly.

The test uses four namespaces and two real daemons.
It verifies native → WASM → native, policy allow → deny → restore for each backend, stable-state traffic and counters, and withdrawal after unregister.
It keeps the service SID and Dplane program unchanged across policy changes and checks that the headend and SID still exist during denial.
It also checks daemon process and BGP socket identities across backend changes.
It does not measure packet loss during updates.

## Try a change interactively

Start the same lab and leave its daemons running:

```sh
sudo ./setup.sh
sudo ./test.sh --interactive
```

Keep that terminal open.
The command prints the directory containing logs, the active JSON files and a prepared deny policy.
In another terminal, change to this example directory.
Use the supplied [PE1 configuration](pe1.json) and [PE2 configuration](pe2.json) as editable policy files:

```sh
# Native is the default. The wrapper preserves each PE's explicit grants.
sudo ./apply.sh pe1 pe1.json
sudo ./apply.sh pe2 pe2.json
sudo ip netns exec cpdp-host1 ping -c 3 -W 1 10.2.0.10
```

Expect three replies.
The new daemon must include native implementation `custom-cdplane-behavior`; an older daemon will report that it is unavailable.
The existing `custom-behavior` implementation retains its original binary configuration format.

To reject PE1's traffic, save a modified policy and apply it to PE2:

```sh
jq '.endpoint.allowed_underlay_prefix = "fd00:100::bad/128"' pe2.json > /tmp/pe2-deny.json
sudo ./apply.sh pe2 /tmp/pe2-deny.json
sudo ip netns exec cpdp-host1 ping -c 2 -W 1 10.2.0.10
```

Expect no replies and ping exit status 1 after the configuration converges.
This changes the allowed **outer tunnel source**, not Host1's inner IPv4 source.
Restore the known-good policy with the same operation:

```sh
sudo ./apply.sh pe2 pe2.json
sudo ip netns exec cpdp-host1 ping -c 3 -W 1 10.2.0.10
```

To use WASM, keep the registration names, permissions and JSON files and select the other backend:

```sh
sudo ./apply.sh pe1 pe1.json wasm
sudo ./apply.sh pe2 pe2.json wasm
sudo ip netns exec cpdp-host1 ping -c 3 -W 1 10.2.0.10
# Return to native using exactly the same policy files.
sudo ./apply.sh pe1 pe1.json native
sudo ./apply.sh pe2 pe2.json native
```

`apply.sh` only supplies the complete CLI registration request for this lab.
It does not interpret policy JSON, infer permissions or automatically roll back failed updates.
A successful register means the configuration was accepted; check forwarding after convergence.
An invalid JSON configuration is rejected before the running controller is replaced.
Other runtime or resource failures can leave retries or partially applied state; inspect the daemon logs and restore the known-good policy if needed.
Policy changes currently remove and reinstall the SID entry, so updates are not guaranteed to be loss-free.

## Check what is running

Run these commands from this example directory while the interactive lab is open:

```sh
sudo ip netns exec cpdp-pe2 ../../out/bin/vinbero -s http://127.0.0.1:8082 \
  plugin cplane stats --name custom-cdplane-behavior
sudo ip netns exec cpdp-pe2 ../../out/bin/vinbero -s http://127.0.0.1:8082 sid list
sudo ip netns exec cpdp-pe1 ../../out/bin/vinbero -s http://127.0.0.1:8082 headend-v4 list
```

The stats report the backend, running state, pending declarations and owned SID/advertisement counts.
PE2 should own one SID and one advertisement after convergence.
PE1's headend should contain `10.2.0.0/24` pointing at that SID.
These observations establish readiness; packet probes establish the configured behavior.
If registration fails, first check the field named in the error and the native/WASM artifact version.
If registration succeeds but traffic fails, check the SID, headend, BGP session, underlay source and the daemon logs printed by the lab.

For an optional policy-counter check in this single-instance lab:

```sh
sudo bpftool -j map dump name cdplane_policy |
  jq '[.[] | (.formatted // .) | {decision: .key, packets: ([.values[].value] | add)}]'
```

Decision 0 counts policy allows and decision 1 counts rejects.
An allow means that the prefix check passed; End.DT4 and the host VRF grant still determine whether the packet is delivered.
If several copies of the plugin are loaded, identify the correct map ID instead of looking it up by name.

## Register on an existing deployment

The lab wrapper expands to ordinary CLI commands.
Run the following on PE1 and PE2 respectively, with the matching JSON files and an already configured daemon, BGP session, locator and VRF.
Change the explicit grants as well as the policy when adapting the topology.
Policy fields do not grant authority.

PE1:

```sh
vinbero plugin cplane register --name custom-cdplane-behavior \
  --config pe1.json --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
  --capability headend --headend-prefix 10.2.0.0/24
```

PE2, after loading the Dplane ELF:

```sh
vinbero plugin register --type endpoint --index 32 \
  --prog sdk/examples/plugin-custom-cdplane-behavior/plugin.o \
  --program plugin_custom_cdplane_behavior
vinbero plugin cplane register --name custom-cdplane-behavior \
  --config pe2.json --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
  --capability advertise --capability local_sid \
  --vrf vrf-cust --locator LOC2 --endpoint-slot 32
```

Native is selected by default, with the implementation ID taken from `--name`.
For WASM, add `--wasm out/cplane-custom-cdplane-behavior.wasm` to the Cplane registration command and keep all other grants.
Repeat the **complete** registration command for policy changes or backend switches; omitted permissions are not inherited from an earlier registration.
The [Cplane SDK example](../../sdk/examples/cplane-custom-cdplane-behavior/README.md) describes the JSON fields.
The [Dplane example](../../sdk/examples/plugin-custom-cdplane-behavior/README.md) describes the internal aux layout and manual SID configuration.

## Remove the plugin

In an existing deployment, unregister the advertising Cplane first and wait until its route and SID are gone before removing its Dplane program:

```sh
# PE2
vinbero plugin cplane unregister --name custom-cdplane-behavior
vinbero sid list
# PE1: verify the service headend has disappeared, then remove the receiver.
vinbero headend-v4 list
vinbero plugin cplane unregister --name custom-cdplane-behavior
# PE2: after withdrawal is confirmed.
vinbero plugin unregister --type endpoint --index 32
```

In the interactive lab, Ctrl-C stops its own daemons.
Then run `sudo ./teardown.sh` to remove the namespaces.
The automated test checks plugin withdrawal before stopping the daemons.

The example reserves `cpdp-*` namespace names and refuses to replace existing namespaces.
The lab stops only the daemon processes it started and preserves its unique `/tmp/vinbero_cpdp.*` logs and resource state.
Plugin persistence and BPF map pinning are disabled because network namespaces share the filesystem.
Teardown refuses to remove namespaces while processes remain.
