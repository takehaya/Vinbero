# CNI plugin, L3 mode

*(日本語: [README.ja.md](./README.ja.md))*

Runs the `vinbero` CNI plugin the way a container runtime does, with
`CNI_COMMAND` in the environment and the network configuration on stdin.
Two PE namespaces run vinberod with an iBGP VPNv4 session between their
loopbacks; three empty namespaces stand in for pods (`pod1` and `pod1b` on
PE1, `pod2` on PE2). IPAM is the reference `host-local` plugin.

PE1's network configuration carries `rd`, `rts` and `locator`, so its first
ADD creates the VRF and the BGP binding. PE2 declares both in
`vinbero_pe2.yaml`, and its network configuration only names the VRF.

The test checks that:

- ADD gives the pod a /32 routed via the link-local gateway, puts the host
  veth into the VRF, installs the /32 into the VRF table as a static route,
  attaches the veth to the data plane and registers it as an AC
- each PE imports the other's pod /32 with a service SID from the other's
  locator, and pods ping each other across the PEs and on the same PE
- CHECK passes on a wired pod and fails after DEL
- after a PE2 restart the veth is attached again and pod2's /32 is
  advertised again
- DEL withdraws the /32, detaches and deletes the veth, removes the AC and
  releases the address; a second DEL succeeds

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
