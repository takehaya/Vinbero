# Runtime device attach

*(日本語: [README.ja.md](./README.ja.md))*

Attaches an interface to the data plane while vinberod is running, the way a
CNI plugin attaches the veths it creates. The topology is the one from
[`end-dt4/`](../end-dt4/): router3 decapsulates End.DT4 into `vrf100`, but
only the host-facing interface is in `internal.devices`. The uplink is
attached with `vbctl device attach`.

The test checks that:

- End.DT4 traffic reaches host2 only while the uplink is attached, and the
  ingress ACs and default-deny apply to it
- the same-mode attach is idempotent, a mode change and a detach of a config
  device are refused, and detach removes the programs
- a restart attaches the uplink again from the state file
- a device whose interface was deleted detaches, and is dropped at the next
  start instead of failing it
- a bridge member added with `vbctl vrf bridge-member-add` is enslaved again
  after a restart, and one deleted while the daemon was down is dropped

```bash
make build
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

See [docs/design/ja/device_attach.md](../../docs/design/ja/device_attach.md)
for the design.
