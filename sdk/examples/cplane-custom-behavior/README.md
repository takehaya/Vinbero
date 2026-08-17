# cplane-custom-behavior

An operator's own SRv6 endpoint behavior, driven from the control plane.

This is the control-plane half of the case the plugin mechanism exists for.
You define a behavior of your own, number it outside the standardized
codepoint space, implement its forwarding as a data-plane plugin in an eBPF
slot, and let this half of the plugin claim the codepoint, watch for routes
carrying it, and program the headend entries that steer traffic into the
SID each advertisement names.

Vinbero's own appliers never see those routes. They read a service SID
without consulting its behavior codepoint, so an unrecognized one would be
installed with the wrong meaning and then collide with this plugin's write
to the same prefix. The claim is what keeps the two apart.

## What it does

It runs both halves of the case.

Sending: at startup it asks the daemon for a local SID from a configured
locator, pointing at the eBPF slot its data-plane half occupies. The daemon
allocates the address, installs the dispatch entry and tells the plugin
which address it got -- the plugin names the SID, the daemon chooses the
value, which is what lets a restarted plugin declare the same name and be
handed the same address. It then advertises the configured prefix behind
that SID, naming its own behavior codepoint in the SID TLV.

Receiving, on every batch of events:

- an advertisement carrying the claimed behavior and an SRv6 SID adds a
  headend entry for its prefix, steering into that SID
- a withdrawal removes it
- anything else is ignored

Two nodes running this plugin therefore reach each other over a behavior
neither vinbero nor BGP knows anything about.

It then declares the whole set, not a delta. The daemon diffs the
declaration against what this plugin already owns and applies the
difference, which is what makes a restart uneventful: a fresh instance
comes back with no memory, the daemon replays the routes, and the same
declaration converges on the same state.

A withdrawal is matched by prefix rather than by behavior. BGP sends only
the NLRI when a route goes away, so a withdrawal carries no attributes at
all and its behavior always decodes as zero. Matching what the plugin is
already holding is the only thing that works.

## Build

```sh
make cplane-example        # from the repository root
```

or directly:

```sh
tinygo build -o plugin.wasm -target=wasm-unknown \
    -scheduler=none -gc=conservative -panic=trap -no-debug .
```

The flags are not incidental.

`wasm-unknown` is the target without WASI, which the daemon does not link.

`scheduler=none` because the plugin has no goroutines and the daemon calls
it one event batch at a time.

`panic=trap` because a panic is a bug rather than a control-flow tool, and
the daemon treats a trap as a failed instance to restart.

`no-debug` because TinyGo otherwise embeds the absolute build path in
DWARF, which makes the committed artifact differ on every machine; with it
the build is reproducible and the module drops from ~83 KB to ~14 KB. A
trap then carries no stack info, which costs little: the daemon reports
the trap either way and a plugin's own diagnostics go through `log`.

`gc=conservative` because a control-plane plugin runs for the life of the
daemon and sees every route change in the network. TinyGo's default for
this target is `gc=leaking`, which never reclaims: built that way this
example dies partway through the SDK's churn test, while the conservative
build runs indefinitely in a megabyte. See
`TestPluginSurvivesSustainedChurn` in `sdk/go/cplaneharness`.

## Run

```sh
vbctl plugin cplane register \
    --name custom-behavior \
    --wasm plugin.wasm \
    --behavior 0xFE01 \
    --family vpnv4 \
    --capability headend \
    --capability advertise \
    --capability local_sid

vbctl plugin cplane list
vbctl plugin cplane unregister --name custom-behavior
```

The capabilities are what this plugin is allowed to do. The daemon links
only the host functions they cover, so a plugin granted nothing that writes
cannot reach the apply functions at all; between the kinds of declaration
the check happens where the transaction is opened, because those functions
are shared. A receive-only deployment of this same plugin needs
`--capability headend` alone.

Registering the same name again upgrades in place: the entries the running
instance wrote stay, and the new module reconciles over them. Unregistering
is the deliberate removal and takes the plugin's entries with it.

## Configuration

The config blob is this plugin's own protobuf message, which the daemon
does not interpret. It carries everything that differs between
deployments, so one build serves all of them:

| field | meaning |
|---|---|
| 1 | the endpoint behavior codepoint to claim |
| 2 | the locator to take a local SID from |
| 3 | the prefix to advertise behind that SID |
| 4 | the route distinguisher to advertise it with |
| 5 | the eBPF slot the SID dispatches to |
| 6 | a SID to advertise as given, instead of allocating one |
| 7 | the next hop to advertise the prefix with |

There are three ways to run it, and the config picks between them:

- **Allocating.** Set the locator and the slot. The plugin asks the host
  for a SID, is told the address, and advertises the prefix behind it.
- **Advertising a SID it was given.** Set field 6 instead. Nothing is
  allocated and the locator and the slot are not needed: the address
  already exists, and something else put it in the data plane.
- **Receive-only.** Set neither field 6 nor a locator and slot. The plugin
  originates nothing and only acts on routes carrying its behavior, which
  is a perfectly ordinary way to run it.

Fields 3, 4 and 7 are what the advertisement is made of, so the two
advertising modes need all three. The daemon refuses an advertisement with
no next hop rather than guessing one.

## Notes on the code

`wire.go` is a small protobuf codec written by hand. The generated Go
bindings need reflection, which TinyGo's WebAssembly targets do not
support, and what crosses the boundary here is small and fixed.

`vinbero_abi_version` is what lets the daemon refuse a module built against
an ABI it no longer implements, rather than letting it trap on the first
call into a function whose signature moved.

There is no clock and no I/O in this plugin. The sandbox provides neither,
beyond the `log` and `now_monotonic` host functions; a plugin that needs to
reach anything else is asking for something this mechanism deliberately
does not offer.
