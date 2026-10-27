# Custom source-prefix endpoint

`plugin_custom_cdplane_behavior` permits an outer IPv6 source prefix and hands permitted packets to built-in End.DT4.
The host-owned VRF grant determines the decapsulation VRF.
Missing or invalid policy, a nonmatching source, a missing grant or an unavailable tailcall target results in DROP.
The prefix check is an underlay policy, not cryptographic authentication.

Build from the repository root:

```sh
make -C sdk/examples/plugin-custom-cdplane-behavior BPF_CLANG=clang-18
out/bin/vinbero plugin validate \
  --prog sdk/examples/plugin-custom-cdplane-behavior/plugin.o \
  --program plugin_custom_cdplane_behavior
```

The [combined topology](../../../examples/custom-cdplane-behavior/README.md) provides the complete forwarding workflow.
Its [Cplane adapter](../cplane-custom-cdplane-behavior/README.md) configures policy, allocates the SID and requests the host VRF grant for both native and WASM execution.
The endpoint ELF does not change when the Cplane backend changes.

## Policy layout

The BTF-declared `plugin_custom_cdplane_behavior_aux` has the following 32-byte layout:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | Layout version `1` |
| 1 | 7 | Reserved, zero |
| 8 | 1 | IPv6 prefix length, 0–128 |
| 9 | 7 | SDK prefix padding, zero |
| 16 | 16 | IPv6 network address in network order |

The prefix uses the SDK's `vinbero_ipv6_prefix_t` type.
Every scalar is one byte, so the layout is independent of host endian.
The Dplane checks the version, reserved bytes, padding, prefix length and outer IPv6 header bounds before matching.

For manual BTF encoding, save this as `endpoint.json`:

```json
{
  "version": 1,
  "allowed_underlay_prefix": "fd00:100::/128"
}
```

With the Dplane program already registered, the independent aux API accepts the file:

```sh
vinbero plugin aux alloc --map-type endpoint --slot 32 --json-file endpoint.json
# Substitute the index printed by alloc.
vinbero plugin aux get --map-type endpoint --slot 32 --index 7
vinbero plugin aux update --map-type endpoint --slot 32 --index 7 --json-file endpoint.json
vinbero plugin aux free --map-type endpoint --slot 32 --index 7
```

`--json-file`, inline `--json` and `--raw` are mutually exclusive.
Allocation alone does not bind an aux to a SID.
Manual SIDs can reference independent aux with `sid create --plugin-aux-index`, but this does not create the host VRF grant required by this endpoint.
Use the Cplane workflow for actual VRF decapsulation.
Independent aux and Cplane-generated aux have separate ownership and lifetimes; these commands cannot overwrite a Cplane-generated policy.

## Counters and checks

The private per-CPU array `cdplane_policy` has two entries:

- Index 0 counts packets that passed the source-prefix policy.
- Index 1 counts policy rejects, including missing or malformed policy.

A policy allow is not a delivery acknowledgement; the host grant and End.DT4 can still reject the packet.
The combined example checks both policy counters and actual traffic.
The BPF tests cover SRH and no-SRH packets, /0, /64, /65 and /128 matches, mismatches, malformed headers and policy, and absent grants or tailcall targets.
The server test compares this ELF's BTF encoder output with the shared Go adapter's bytes.
