# CNI plugin, L2 mode

*(日本語: [README.ja.md](./README.ja.md))*

Runs the `vinbero` CNI plugin in L2 mode the way a container runtime does,
with `CNI_COMMAND` in the environment and the network configuration on stdin.
Two PE namespaces run vinberod with an iBGP EVPN session between their
loopbacks; empty namespaces stand in for pods. IPAM is the reference
`host-local` plugin.

In L2 mode a pod joins a pre-declared **EVPN bridge domain**: its host-side
veth becomes a port of the bridge, the pod gets an on-link address, and the
pods of one network on different nodes share one Ethernet segment (same
subnet, ARP/ND across nodes, MAC routes over BGP). The bridge domain (bridge
device and `bd_id`) is declared in each node's vinberod config; the plugin
never creates or destroys it.

`pod1`, `pod1b` and a silent `pods` on PE1 and `pod2` on PE2 are in `tenant-l2`
(bridge `br-l2`, `bd_id` 100). `pod1x` on PE1 and `pod2x` on PE2 are in
`tenant-l2b` (bridge `br-l2b`, `bd_id` 200), a second bridge domain that uses
the same subnet, down to the same addresses and the same MAC. All pods share
one `10.200.0.0/16` subnet with per-node host-local ranges.

PE1's `tenant-l2` network configuration carries `rd`, `rts` (family `evpn`)
and `locator`, so the first ADD creates the BGP binding. Every other binding,
and both bridge domains, are declared in the daemon config
(`vinbero_pe1.yaml`, `vinbero_pe2.yaml`), which has `evpn_auto_advertise: true`
and `settings.l2.bum_mode: tc`.

The test checks that:

- ADD gives the pod its IPAM address on-link (no gateway, no /32), puts the
  host veth on the bridge and the data plane, registers it as an AC and a
  `bd_id` circuit, and pre-advertises the pod MAC as an EVPN RT2
- the bridge domain's bridge is hardened against giving a pod a path into the
  host stack (`disable_ipv6`, `rp_filter`, `arp_ignore`, no IPv4 forwarding);
  a UDP probe from a pod to a node address is dropped, and is delivered only
  with `rp_filter` turned off (a negative control)
- pods ping and ARP each other across the PEs and on the same PE, and reach
  each other's IPv6 link-locals (ND floods as BUM)
- a silent pod (one that never sends) is reachable from the other node through
  the static-FDB pre-advertisement
- two bridge domains with the same subnet, the same address and the same MAC
  stay apart: a ping reaches only the pod of the sender's bridge domain
- a DF ping within the 1422-byte MTU passes and one over it is dropped
- DEL and re-ADD, and a DEL after the pod's veth vanished, work
- after a daemon restart (TERM and KILL) with pods attached, the host veth is
  attached again, the `bd_id` circuit is back, the bridge stays hardened, and
  pods reach each other again — without any further CNI call
- DEL withdraws the MAC, detaches and deletes the veth, removes the AC and the
  bridge membership and releases the address; the bridge stays after the last
  pod

The test looks for `host-local` in `$CNI_PLUGIN_DIR`, `/opt/cni/bin` and
`/usr/lib/cni` (Debian and Ubuntu: `apt install containernetworking-plugins`).

```bash
make build
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

See [docs/design/ja/cni.md](../../docs/design/ja/cni.md) for the design and
deployment with Multus.
