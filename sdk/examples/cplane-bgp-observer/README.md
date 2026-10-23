# BGP observer

This read-only control-plane plugin decodes received routes into GoBGP's native NLRI and attribute types and logs their family, source and attribute count.
It makes no forwarding declarations or BGP advertisements and needs no write capabilities.
The shared [`bgpobserver`](../../go/cplane/bgpobserver) package implements the controller for both WASM and native execution.

Build from the repository root with Go 1.25.5:

```sh
make cplane-bgp-observer
```

With a running daemon and peers configured for the desired families, register the native controller using:

```sh
vinbero plugin cplane register --name bgp-observer --family mup_ipv4 --family evpn
```

Native is the default backend; omitting the implementation ID uses the registration name, and omitting the version selects the daemon's catalog version.
Use `--native bgp-observer` when registering under a different name.
To load the WASM build instead:

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

Native execution is enabled by default; set `settings.cplane_plugins.native_enabled: false` to allow only WASM plugins.
Use `--native-version 1` to require an exact native implementation version.
Keep the same families and omit write capabilities.
Both adapters require full BGP input and ignore the opaque configuration payload.
Malformed BGP paths produce quarantined event results with the original sequence number.

Native execution is statically linked and runs inside the daemon without WASM memory isolation or forced interruption.
Rebuild the daemon when updating the implementation and explicitly update persisted registrations if their native identity no longer matches.
The native/WASM differential tests compare encoded event statuses, route and withdrawal logs, and the absence of output transactions.
