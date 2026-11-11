# CNI plugin, L3 mode

*(日本語: [README.ja.md](./README.ja.md))*

Runs the `vinbero` CNI plugin the way a container runtime does, with
`CNI_COMMAND` in the environment and the network configuration on stdin.
Two PE namespaces run vinberod with an iBGP VPNv4 session between their
loopbacks, which only PE1 dials (`passive` on PE2); empty namespaces stand
in for pods: `pod1`, `pod1b` and `pod1x` on PE1, `pod2` and `pod2x` on PE2.
IPAM is the reference `host-local` plugin.

`pod1`, `pod1b` and `pod2` are in tenant-a (table 100, route target
65000:100). `pod1x` and `pod2x` are in tenant-b (table 200, route target
65000:200), whose network configuration has tenant-a's subnets. host-local
keeps its leases per network name, so `pod1x` gets `pod1`'s address and
`pod2x` gets `pod2`'s.

PE1's network configurations carry `rd`, `rts` and `locator`, so the first
ADD of each tenant creates the VRF and the BGP binding. PE2 declares both
VRFs and bindings in `vinbero_pe2.yaml`, and its network configurations
only name the VRF.

The test checks that:

- ADD gives the pod a /32 routed via the link-local gateway, puts the host
  veth into the VRF, installs the /32 into the VRF table as a static route,
  attaches the veth to the data plane and registers it as an AC
- each PE imports the other's pod /32 with a service SID from the other's
  locator, and pods ping each other across the PEs and on the same PE
- tenant-b's pods have tenant-a's addresses, and each PE holds the shared
  /32s in both VRFs with a different service SID; a ping reaches only the
  pod of the sender's tenant (the other tenant's pod with the same address
  counts no echo request), across the PEs and on the same PE
- CHECK passes on a wired pod and fails after DEL
- after a PE2 restart the veth is attached again and the /32s of both
  tenants are advertised again, each in its own VRF
- DEL of a tenant-b pod leaves tenant-a's pod with the same address, its
  route and its lease alone
- a veth that vanishes before its DEL does not block other pods' ADD and DEL
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
