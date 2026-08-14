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

On every batch of events it receives:

- an advertisement carrying the claimed behavior and an SRv6 SID adds a
  headend entry for its prefix, steering into that SID
- a withdrawal removes it
- anything else is ignored

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
    -scheduler=none -gc=leaking -panic=trap .
```

The flags are not incidental. `wasm-unknown` is the target without WASI,
which the daemon does not link; `scheduler=none` because the plugin has no
goroutines and the daemon calls it one event batch at a time; `panic=trap`
because a panic is a bug rather than a control-flow tool, and the daemon
treats a trap as a failed instance to restart.

`gc=leaking` never reclaims memory, which is fine for an example and wrong
for a long-running plugin: a real one should use `-gc=conservative` and be
soak-tested against the instance memory limit. That is why TinyGo is not
yet a fully supported toolchain for this SDK.

## Run

```sh
vbctl plugin cplane register \
    --name custom-behavior \
    --wasm plugin.wasm \
    --behavior 0xFE01 \
    --family vpnv4

vbctl plugin cplane list
vbctl plugin cplane unregister --name custom-behavior
```

Registering the same name again upgrades in place: the entries the running
instance wrote stay, and the new module reconciles over them. Unregistering
is the deliberate removal and takes the plugin's entries with it.

## Configuration

The config blob is a bare varint holding the codepoint to claim, so one
build serves deployments that numbered their behavior differently:

```sh
printf '\202\374\003' > behavior.bin   # 0xFE02
vbctl plugin cplane register --name custom-behavior --wasm plugin.wasm \
    --config behavior.bin --behavior 0xFE02
```

A plugin with more than one knob would define a protobuf message and encode
that; a whole message for a single number would be ceremony.

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
