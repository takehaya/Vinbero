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
The `routing` object is the one [`customcontroller`](../../go/cplane/customcontroller) reads for `custom-behavior`, including its defaults; this example adds `endpoint`.
Values the registration already decides (the claimed behavior, the headend scope, and a single locator, VRF or endpoint slot) can be left out, and the plugin reads them from its registration when it starts.
A configured value that disagrees with the registration fails registration with an error naming both values.
Configuration values grant nothing: the host checks every declaration against the registration.

Receiver, registered with `--behavior 0xFE01 --headend-prefix 10.2.0.0/24 --vrf vrf-cust`, whose customer port is an access circuit of `vrf-cust`:

```json
{
  "schema_version": 1,
  "routing": {
    "headend_vrf": "vrf-cust"
  }
}
```

Advertiser and local endpoint, registered with `--locator LOC2 --vrf vrf-cust --endpoint-slot 32`:

```json
{
  "schema_version": 1,
  "routing": {
    "prefix": "10.2.0.0/24",
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
| `routing.behavior` | Endpoint behavior, 1–65535; defaults to the claimed behavior when exactly one is claimed, otherwise `65025` (`0xFE01`) |
| `routing.headend_prefixes` | IPv4 prefixes restricting accepted routes; defaults to the IPv4 prefixes of the headend scope, or to accepting no routes when the scope has only IPv6 prefixes |
| `routing.locator`, `routing.slot` | Locator and endpoint slot (32–63) for the SID; each defaults to the scope's only value |
| `routing.decap_vrf` | Required with SID allocation, and requests one; selects a host-authorized VRF grant, separate from endpoint aux bytes |
| `routing.prefix`, `routing.next_hop` | Both required to advertise an IPv4 VPN prefix; next hop must be a usable native IPv6 address |
| `routing.vrf` | VRF to advertise into; defaults to the scope's only VRF |
| `routing.headend_vrf` | VRF of the headend entries for received routes; the global VRF when omitted. The behavior claim keeps the built-in applier off a received prefix only in the VRFs that import the route, so name one of those |
| `endpoint.allowed_underlay_prefix` | Required with SID allocation; allowed outer IPv6 source prefix, including `::/0` to permit all sources |

Prefixes are masked to their network address.
IPv4-mapped IPv6 addresses and zoned addresses are not accepted as IPv6 endpoint policy or next-hop values.
Unknown or differently cased keys, repeated keys, null values, unsupported schema versions and multiple JSON documents are rejected.
A key that is present is validated as written; only absent keys take the registration's value.
The configuration is validated against these constraints and the registration before the adapter invokes the routing controller.
Locator and VRF existence remain host checks when applying declarations.
The error identifies the field to correct.

An endpoint can allocate a SID without advertising it by giving `decap_vrf` and `endpoint` and no advertisement field.
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

The [`custom-behavior`](../cplane-custom-behavior/README.md) implementation shares the routing controller without the endpoint policy.

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
