# EVPN BUM with 33 PEs in one bridge domain

*(日本語: [README.ja.md](./README.ja.md))*

[evpn-bum-scale](../evpn-bum-scale/) with `NUM_PES=33`: 33 Vinbero PEs in one
EVPN bridge domain over an iBGP full mesh (528 sessions). Every PE installs 32
RT3 flood peers, which fill the 32 flood slots of a bridge domain (the most
it floods to: 32 remote PEs, 33 nodes), and 32 RT2 unicast peers, which take
no flood slot. The checks are those of evpn-bum-scale at this size: all 64
peers and 32 remote MACs on every PE, known unicast between every pair of
hosts, exactly one copy of unknown unicast, broadcast and ARP at every remote
PE and host with none sent back into the core, and RX split horizon on an
Ethernet Segment shared by PE 32 and PE 33.

The run takes several minutes and starts 33 daemons and about 100 packet
captures at a time, so it is not part of every CI run; evpn-bum-scale (9 PEs)
is. Give the machine at least 4 CPUs and 8 GB of memory.

```bash
make build            # from the repository root
cd examples/evpn-bum-scale-33
sudo ./setup.sh
sudo BUM_MODE=tc ./test.sh        # or xdp, xdp-native
sudo ./teardown.sh
```
