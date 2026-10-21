# Context route API

The context route API lets a WASM plugin retain authorized paths, join projected fields, and declare forwarding and advertisements.
The host owns input grants, internal IDs, map ownership, and cleanup.
The SDK exposes the pinned GoBGP **packet model**; it does not expose the GoBGP server or an unrestricted AddPath operation.

## Input and View

Registration opts in with `CplanePluginRegisterRequest.input.version = 1` or `vinbero plugin cplane register --input-policy policy.json`.
The policy defines named contexts and grants by family, route target, peer, and prefix.
Route-target families require explicit RT grants; unicast grants require both peer and prefix restrictions.
Each grant combines its restrictions with AND; multiple grants combine with OR.
A path may belong to several contexts, but the View stores it once.
The configure envelope contains only context names and families, plus the operator's original payload and codec identifier.
The guest cannot enlarge that catalog.

```go
input, err := cplane.DecodeInputConfig(configBytes, guest.InputFeatures())
if err != nil { return err }
view, err := routes.NewView(input, routes.Limits{MaxPaths: 4096, MaxBytes: 8 << 20})
```

`routes.View` starts unready and becomes readable after a complete BGP start/end replay.
It keys paths by host-supplied identity, including peer and ADD-PATH ID, independently of attributes.
An attribute replacement removes the old value before decoding the replacement.
Malformed attributes quarantine that path; missing identity or exceeded budgets invalidate the whole input until a new complete replay.
The host sends a key-only withdrawal when a path loses its last authorized context, without disclosing its new attributes.
`Range` yields packet models borrowed read-only for that callback; `gobgppath.Encode` copies them before serialization.
The byte budget measures retained encoded data plus accounting overhead, not the Go runtime's exact heap consumption.

Existing registrations without `input` keep their original configure bytes and legacy output API.
The presence of an `input_features` import alone never switches the configure format.

## Rules

A selector projects a packet into a comparable value containing every field the output builder reads.
A field accessor returns Present, Missing, Invalid, or Ambiguous; a missing Direct Segment community is distinct from a present zero-valued community.
Typed left and right references prevent accidentally comparing two fields from the same side.

```go
engine, err := resolve.NewEngine(view, resolve.Limits{})
rank := resolve.LongestPrefix(resolve.Right(mup.ISDPrefix))
down, err := resolve.Register(engine, resolve.Rule[mup.ST1, mup.ISD]{
    Name: "downlink", Context: "mobile",
    Left: mup.ST1Selector(), Right: mup.ISDSelector(),
    Match: resolve.Contains(resolve.Right(mup.ISDPrefix), resolve.Left(mup.ST1Endpoint)),
    Rank: &rank, Choose: resolve.Unique,
})
```

`Equal`, `Contains`, and `All` express the join independently of MUP or EVPN.
Rules use equality or prefix indexes and enforce rule, work, and diagnostic budgets.
Equivalent supporters of the same canonical destination collapse only when their complete projections agree.
Different destinations, conflicting projections, and equal-ranked ties remain ambiguous.
No map iteration order chooses a winner, and these rules do not implement BGP best-path selection.
The generic VPN service-SID to IPv6-unicast longest-prefix example is exercised in `go/cplane/resolve/rule_test.go`.

## Outputs

After `engine.Update(events)` reports Ready, builders consume resolved pairs and produce a complete `cplane.Composition` with that View revision.
`Client.ApplyComposition` uses the existing bounded apply transaction transport.
A newer committed desired set supersedes older retries even when the newer set cannot apply.
Rebuild a failed desired set from the latest ready View on the next event or tick.
Replay and incomplete input suspend writes; an empty complete set withdraws outputs.
Local SID declarations for a context guest should be made after the replay barrier.

| Output | Host authority |
| --- | --- |
| Forwarding headend | `headend` capability, context membership, trigger prefix and slot scope |
| MUP uplink | `mup` and `headend`, delegated ST2, endpoint and TEID scopes, host-resolved MUP VRF |
| EVPN remote MAC or flood peer | `evpn`, delegated bridge domain, host-assigned peer index |
| BGP advertisement | `advertise`, context family, VRF/locator scope, allocated SID ownership |

MUP sessions are handed away from built-ins only by explicit delegation matching the context grants and host-resolved target VRF.
EVPN delegation similarly checks the bridge domain.
Delegations stay reserved when a plugin fails or cannot restore, and cannot be taken by a different plugin while cleanup is outstanding.
Changing input policy requires unregistering and finishing cleanup first.
Context registrations use store manifest version 3 so an older daemon refuses them rather than silently ignoring their authorization policy.
Legacy registrations continue using version 2.

The initial MUP builders support GTP4 ST1+ISD and ST2+DSD.
The downlink requires an explicit IPv6 source and a compatible SID argument layout; the uplink leaves the DSD SID unchanged.
ST2+ISD and GTP6 outputs are rejected by this profile.
The EVPN helpers support single-homed RT2/RT3 with zero ESI, Ethernet tag zero, an IPv6 next hop, and a single DT2U/DT2M service SID.
Controlled EVPN MAC entries are static, and plugin peers do not create dynamic remote MAC entries.
A remote PE has one unicast reverse mapping; a separate flood peer does not replace it.
MAC mobility, aliasing, and multihoming are outside this profile.

`gobgppath.Encode` accepts native NLRI and path attributes for advertisements.
The host currently admits IPv6 unicast and single-service SRv6 VPNv4/VPNv6 profiles: IGP origin, one matching MP_REACH, and one L3 Prefix-SID for VPN.
VPN NLRI uses zero RD/label placeholders; the host derives RD and RTs from the authorized VRF binding.
SID Structure is retained; label transposition and attributes the host cannot reproduce are rejected.
Unknown received attributes remain available in the input packet model even when they are outside this output profile.

The host withdraws advertisements before changing their forwarding dependencies and advertises only after all forwarding outputs succeed.
Apply is ordered convergence, not an atomic multi-map transaction; a failure can leave partial forwarding state with ownership reserved for retry.
Input loss invalidates pending work and initiates owner-scoped cleanup.
Persistent owner inventories preserve failed deletes across daemon restart, including peer companions and shared MUP gate dependencies.
Stats expose input readiness/fault, cleanup pending, and desired/applied revisions with the last output failure.
The legacy standalone conformance validator lacks context policy and rejects composition transactions; use the manager integration tests for this API.

## Run the example

See [the composition guest](examples/cplane-route-composition/README.md) for complete read-only and writing builds, registration policies, and retry handling.
From the repository root, `make cplane-route-composition-observer` builds an artifact without write imports, and `make cplane-route-composition` builds the writing artifact.
`go test ./pkg/cplane -run TestCompositionWASMReplayAndWithdraw` exercises the writing artifact in the real host after building it.
