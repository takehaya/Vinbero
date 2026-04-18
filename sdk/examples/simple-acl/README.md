# simple-acl — IPv6 source ACL plugin

Drops packets whose outer IPv6 source address appears in a userspace
populated deny-list (`acl_deny_map`, a BPF hash map). Otherwise passes
the packet through.

Demonstrates:

- Reading the outer IPv6 header with `CALL_WITH_CONST_L3` to keep the
  verifier happy with variable VLAN depth
- Defining a plugin-owned `BPF_MAP_TYPE_HASH` that vinbero creates on
  registration and tears down on unregistration
- Composing with vinbero's SRv6 pipeline: registering against
  `sid_endpoint_progs[32]` and pointing a SID at it

## Build

```
make
```

## Validate

```
../../../out/bin/vinbero plugin validate --prog plugin.o --program simple_acl
```

## Register

```
../../../out/bin/vinbero -s http://127.0.0.1:8080 \
    plugin register --type endpoint --index 32 \
    --prog plugin.o --program simple_acl

../../../out/bin/vinbero -s http://127.0.0.1:8080 \
    sid create --trigger-prefix fc00:2::32/128 --action 32
```

Populating `acl_deny_map` currently requires an external loader (or a
privileged `bpftool map update`) — the goal of this example is the
plugin itself, not the management tooling.
