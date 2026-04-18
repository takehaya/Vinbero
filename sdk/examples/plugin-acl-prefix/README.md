# plugin-acl-prefix — Source-prefix ACL driven by plugin aux

A Vinbero plugin that drops (or passes) packets whose outer IPv6 source
address is inside a configured prefix. The rule lives in plugin aux
(`vinbero_ipv6_prefix_t`) and is delivered per-SID via
`--plugin-aux-json`, so operators can change the ACL without recompiling
the plugin.

## How it works

- Plugin occupies endpoint slot 33 on router2.
- `plugin_acl_prefix_aux` carries `{deny_src: vinbero_ipv6_prefix_t,
  action: u32}`. The BTF-driven JSON encoder on the server converts
  `"fc00:12::/64"` into the packed `{prefix_len=64, _pad, addr}` the
  plugin reads.
- On each packet, the plugin inspects the outer IPv6 src. If it matches
  `deny_src` at `prefix_len` bits and `action == 1` (DROP), the packet
  is dropped; otherwise it is passed to the normal SRv6 pipeline.
- Two SIDs are created pointing at the same plugin slot but carrying
  different aux rules — this is the whole point of keeping the rule in
  aux rather than in the plugin's own map.

## Quickstart

```bash
cd sdk/examples/plugin-acl-prefix

# Bring up the three-router topology used by the example.
sudo ./setup.sh

# Runs the full E2E (compile, register, create SIDs, send probes).
sudo ./test.sh

# Tear down when done.
sudo ./teardown.sh
```

## Try the encoder by hand

After `setup.sh` you can register the plugin and play with different
rules yourself:

```bash
sudo ip netns exec plgacl-router2 \
  out/bin/vinbero -s http://127.0.0.1:8083 \
  plugin register --type endpoint --index 33 \
  --prog sdk/examples/plugin-acl-prefix/plugin.o --program plugin_acl_prefix

sudo ip netns exec plgacl-router2 \
  out/bin/vinbero -s http://127.0.0.1:8083 \
  sid create --trigger-prefix fc00:2::33/128 --action 33 \
  --plugin-aux-json '{"deny_src": "fc00:12::/64", "action": 1}'
```

## Files

- `plugin.c` — BPF plugin source, declares `plugin_acl_prefix_aux` so the
  server picks it up via BTF
- `Makefile` — thin wrapper over `sdk/c/Makefile.plugin`
- `setup.sh` / `teardown.sh` — three-router netns topology
- `test.sh` — E2E drop/pass assertions
- `vinbero_config.yaml` — runtime config for the router2 daemon
