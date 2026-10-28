# JSON-configured custom Cplane and Dplane behavior

This example advertises an operator-defined service SID and configures an outer IPv6 source-prefix filter in its eBPF endpoint.
The native implementation `custom-cdplane-behavior` and this WASM entry point both call [`cdplanecontroller`](../../go/cplane/cdplanecontroller).
That adapter validates the example's JSON and passes routing and opaque endpoint bytes to the existing [`customcontroller`](../../go/cplane/customcontroller).
Route selection, replay handling, SID allocation notifications, advertisements and retries are shared.

For a runnable two-PE topology, policy changes, backend switching and removal, follow the [combined example](../../../examples/custom-cdplane-behavior/README.md).
The Dplane remains eBPF when the Cplane backend changes.

## Configuration

Pass JSON directly through `vinbero plugin cplane register --config PATH`.
The host forwards the bytes without interpreting this schema.
The JSON schema belongs to this example; it is not a format required of other Cplane plugins.
Registration capabilities and scopes are separate from these configuration values.

Receiver:

```json
{
  "schema_version": 1,
  "routing": {
    "headend_prefixes": ["10.2.0.0/24"]
  }
}
```

Advertiser and local endpoint:

```json
{
  "schema_version": 1,
  "routing": {
    "locator": "LOC2",
    "prefix": "10.2.0.0/24",
    "vrf": "vrf-cust",
    "slot": 32,
    "next_hop": "2001:db8:ff::2",
    "decap_vrf": "vrf-cust"
  },
  "endpoint": {
    "allowed_underlay_prefix": "fd00:100::/128"
  }
}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Required; currently `1` |
| `routing` | Required object containing the routing parameters |
| `routing.behavior` | Optional integer endpoint behavior, 1–65535; defaults to `65025` (`0xFE01`) |
| `routing.headend_prefixes` | Optional IPv4 prefixes restricting accepted routes; omitted or empty retains unrestricted receiver selection, still bounded by host grants |
| `routing.locator`, `routing.slot` | Supply both to allocate a SID; endpoint slot must be 32–63 |
| `routing.decap_vrf` | Required with SID allocation; selects a host-authorized VRF grant, separate from endpoint aux bytes |
| `routing.prefix`, `routing.vrf`, `routing.next_hop` | Supply all three with SID allocation to advertise an IPv4 VPN prefix; next hop must be a usable native IPv6 address |
| `endpoint.allowed_underlay_prefix` | Required with SID allocation; allowed outer IPv6 source prefix, including `::/0` to permit all sources |

Prefixes are masked to their network address.
IPv4-mapped IPv6 addresses and zoned addresses are not accepted as IPv6 endpoint policy or next-hop values.
Unknown fields, null values, unsupported schema versions and multiple JSON documents are rejected.
The JSON structure and the field constraints listed above are validated before the adapter invokes the routing controller.
Locator and VRF existence and authorization remain host checks when applying declarations.
The error identifies the field to correct.

An endpoint can allocate a SID without advertising it by omitting all three advertisement fields.
The receiver configuration does not allocate a SID and must omit endpoint policy and `decap_vrf`.
The combined example grants the receiver only headend writes and the advertiser only local SID and advertisement writes.

The filter matches the source of the encapsulated IPv6 packet, not the original customer source or necessarily the BGP next hop.
In the combined topology, PE1's headend source is `fd00:100::`, derived from its locator.
Check `headend-v4 list` when adapting the policy to a different deployment.

## Build and backend selection

From the repository root:

```sh
make cplane-custom-cdplane-behavior
```

This builds `out/cplane-custom-cdplane-behavior.wasm` with the standard-Go artifact toolchain pinned by the root `go.mod`.
Build the daemon from the same checkout for native support.
Use `--name custom-cdplane-behavior` for the default native implementation, or add `--wasm out/cplane-custom-cdplane-behavior.wasm`.
If using a different instance name, select native explicitly with `--native custom-cdplane-behavior`.
Repeat all capability and scope flags on replacement; they are not inherited.

The original `custom-behavior` native ID and [binary-configured guest](../cplane-custom-behavior/README.md) remain available.
This example does not change their configuration format or the Cplane SDK wire ABI.

## Endpoint data and lifecycle

The adapter encodes a versioned 32-byte policy using the [Dplane layout](../plugin-custom-cdplane-behavior/README.md).
It declares those bytes in `LocalSID.AuxRaw` and names the decap VRF separately.
The host owns allocation and cleanup of the SID, aux and VRF grant.
Do not update Cplane-generated aux through `plugin aux update`; its independent slot ownership does not match the host-managed allocation.
Change the JSON and repeat the same-name Cplane registration instead.

Invalid configuration is rejected before the existing controller is replaced.
Successful configuration changes can remove and recreate forwarding entries, and runtime failures can require retries.
Native/WASM replacement and policy updates do not promise loss-free forwarding.
Unregister the Cplane and confirm withdrawal before removing its Dplane endpoint.
