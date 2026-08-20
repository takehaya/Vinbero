# plugin-custom-behavior

The data-plane half of the custom-behavior example. Its control-plane half
is [`../cplane-custom-behavior`](../cplane-custom-behavior), and neither is
much use without the other.

Together they are one operator-defined SRv6 endpoint behavior, end to end:

1. the control-plane plugin claims an endpoint behavior codepoint no
   standard assigns (0xFE01), so routes carrying it are withheld from
   vinbero's own appliers;
2. it asks the daemon for a local SID from a locator, pointing at the
   eBPF slot this program occupies;
3. it advertises that SID over BGP with the codepoint in the SID TLV;
4. the far end's control-plane plugin reads the codepoint, understands
   what it means, and installs the forwarding state that steers traffic
   into the SID;
5. packets arriving for the SID land here.

## What it does

It counts the packets its SID received and hands them to vinbero's End.DT4
to be decapsulated and forwarded. A behavior that owns a slot would
normally do its own work at this point -- that is the reason to own one --
but the example is about the wiring, and the wiring is the part that is
hard to get right.

Handing off rather than forwarding directly is not a shortcut. A plugin
cannot call `bpf_redirect`: every packet-level redirect goes through the
epilogue or a vinbero PROG_ARRAY, so tail-calling into a validated slot is
how a plugin finishes a packet's journey. End.DT4 reads what it needs from
the same tail-call context this program was handed, so the handoff needs
nothing prepared.

## Build and register

```sh
make
vbctl plugin register --type endpoint --index 32 \
    --prog plugin.o --program plugin_custom_behavior
```

The index has to be one of the endpoint plugin slots (32-63), and it has to
be the same one the control-plane half names in its config, because that is
what the SID it allocates will dispatch to.

## Where it is exercised

`examples/interop-clab/scenarios/cplane-plugin-2site` runs both halves
against a second vinbero, and pings a customer address through the SID the
control-plane plugin allocated.
