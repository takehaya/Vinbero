# Optional IMET-gated EVPN static MAC policy

This example uses one shared [`evpncontroller`](../../go/cplane/evpncontroller) implementation for the native daemon and the WASM guest.
It permits a remote static MAC from RT2 only while a unique matching RT3 IMET projection is present in the same host-authorized context.
This is an application policy, not a required EVPN dependency or proof that the remote PE is reachable.

The join uses the IPv6 MP_REACH next hop and Ethernet Tag.
RDs may differ between RT2 and RT3; the RT3 originator address is not the MP_REACH next hop.
Equivalent reflected paths collapse; different IMET candidates remain ambiguous and produce no MAC.
Conflicting RT2 outputs for one MAC are all omitted.

The existing builders restrict this example to zero ESI, Ethernet Tag zero, an RT2 End.DT2U SID and an RT3 End.DT2M SID.
The RT3 service is validated without installing a BUM flood peer.
MAC mobility, multihoming, BGP best-path selection and local SID provisioning are outside this example.
Provision the bridge domain, interfaces and receiving SRv6 behaviors separately.

## Build and register

From the repository root with Go 1.25.5 or later:

```sh
make cplane-evpn-imet
VINBERO_CPLANE_PARITY=1 go test -race -timeout 35m \
  ./sdk/go/cplane/evpncontroller ./pkg/cplane/native
```

The native implementation ID is `evpn-imet`, version `1`.
For example, from this example directory:

```sh
vinbero plugin cplane register --name evpn-imet \
  --family evpn --capability evpn --input-policy policy.json \
  --config config.json --tick-ms 1000
```

To select WASM, add `--wasm ../../../out/cplane-evpn-imet.wasm` to that command.
For a different registration name, use `--native evpn-imet` to select this native implementation explicitly.
The daemon must authorize trusted native execution; native does not provide a per-instance heap limit or forced call termination.
Both adapters use the same encoded inputs, statuses and composition transactions.
The native identity includes this controller's source through the existing source fingerprint.

The sample policy grants only RT `65000:7` to context `l2` and delegates its EVPN writes to bridge domain 100.
Choose the RT and bridge domain for the actual deployment.
The host retains capability, context delegation, ownership, quota and output validation.
Delegation replaces selected built-in processing, including unsupported routes the controller omits; it is not additive observation of built-in forwarding.
Changing the policy requires the existing unregister/cleanup workflow.

`config.json` explicitly enables writes.
Omitting `observe_only` or setting it to true produces previews without output calls, but this artifact includes write imports and still requires a write capability at registration.
It is not an import-restricted observer artifact.

## Withdrawal and retry

The controller waits for complete BGP replay and emits a full desired set for each ready revision.
Loss of the matching IMET, loss of authorization, or an ambiguous replacement removes the affected MAC from that set.
Incomplete input suspends reconciliation until replay recovers the view; the host handles fail-closed cleanup.
A failed apply is retried from the latest ready view on the next event or tick.
A completed empty replay withdraws every output.

Tests cover independent expected MAC/SID values, mismatch and ambiguity, authorization removal, replay, retry, and native/WASM encoded parity.
The Manager fixture verifies full FDB and peer values plus owner cleanup.
The optional privileged test loads anonymous BPF maps and verifies the same representative lifecycle without attaching an XDP program or claiming packet interoperability:

```sh
go test -exec 'sudo env VINBERO_CPLANE_PARITY=1 VINBERO_CPLANE_EVPN_BPF=1' \
  -race -timeout 35m \
  -run '^TestEVPNControllerOwnedBPFMaps$' ./pkg/cplane
```

The packet lifecycle tests use the same Manager and anonymous BPF collection with native, WASM, and both directions of same-name backend replacement.
They check settled registration, IMET withdrawal, re-advertisement, and cleanup for one zero-ESI/tag-zero MAC.
From the repository root, run them with BPF and network-namespace privileges:

```sh
make cplane-evpn-imet
go test -exec "sudo env VINBERO_CPLANE_EVPN_PACKET=1 VINBERO_CPLANE_EVPN_WIRE=1 VINBERO_CPLANE_EVPN_WASM=$PWD/out/cplane-evpn-imet.wasm" \
  -v -race -count 1 -timeout 35m \
  -run '^TestEVPNController(Packet|Wire)Lifecycle$' ./pkg/cplane
```

`PacketLifecycle` uses `BPF_PROG_TEST_RUN` to inspect encapsulation and unchanged Ethernet bytes after withdrawal; known BUM metadata is checked separately.
`WireLifecycle` attaches generic XDP to an owned veth pair and checks one identified packet per state in a one-second capture window.
A positive capture must contain the expected IPv6/SRH headers and the complete original Ethernet frame; a negative capture requires no identified encapsulation in that window.
Routes, neighbors, forwarding settings, and interfaces are confined to the test namespaces.
The tests do not send traffic during replacement or establish BGP sessions, and do not verify remote decapsulation, general EVPN interoperability, or loss-free handoff.
The kernel 6.1 CI job runs the test-run variant separately from the existing BPF load checks.
