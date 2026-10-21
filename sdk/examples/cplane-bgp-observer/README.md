# BGP observer

This read-only control-plane plugin decodes received routes into GoBGP's native NLRI and attribute types and logs their family, source and attribute count.
It makes no forwarding declarations or BGP advertisements and needs no write capabilities.

Build from the repository root with Go 1.25.5:

```sh
make cplane-bgp-observer
```

With a running daemon and peers configured for the desired families, register it using:

```sh
vinbero plugin cplane register --name bgp-observer \
    --wasm out/cplane-bgp-observer.wasm --family mup_ipv4 --family evpn
```

Registration subscribes to received routes; it does not configure BGP peers or enable new address families on them.
The example calls `guest.InputFeatures()` and requires `cplane.FeatureBGPPath`.
An older host that lacks this import refuses the module during admission.
The import reports input support and does not change the opaque `Configure` payload.

The guest module pins the same GoBGP MUP fork as the host because Go module dependency replacements are not inherited.
See the [SDK documentation](../../go/cplane/README.md#reading-the-gobgp-packet-model) for the codec and identity contract.
The standard Go build is exercised in the real WASM runtime with its default 16 MiB memory limit; this example does not retain a route view or measure large-RIB performance.
