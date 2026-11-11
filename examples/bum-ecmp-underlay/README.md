# BUM over an ECMP underlay

*(日本語: [README.ja.md](./README.ja.md))*

Checks xdp-mode BUM replication when the peers of a bridge domain are reached
through a multipath route. The PE has two uplinks to a transit router; the
peers are locators under `fc00:100::/32`, routed over both uplinks.

The test creates 8 peers with `peer create`, which fills the bridge domain's
8 flood slots: a bridge domain floods to at most 8 remote PEs (9 nodes), and
the slots are shared with the EVPN RT3 peers BGP installs (see
[bum_mode.md](../../docs/design/ja/bum_mode.md)).

```mermaid
graph LR
    host[host<br/>VLAN 100] -->|VLAN 100| PE[PE<br/>Vinbero XDP+TC<br/>H.Encaps.L2, fc00:1::1]
    PE -->|up1| rt[transit router]
    PE -->|up2| rt
```

**Test scenarios** (run with `BUM_MODE=tc`, `xdp` or `xdp-native`):

1. Each peer gets exactly one copy of a broadcast frame, and every uplink is
   used. In tc and in the xdp mode, the same peer uses the same uplink, and
   `BUM_UPLINK_MISMATCH` stays 0. The xdp mode makes each next hop a managed
   neighbour.
2. The route moves to a nexthop-object group; its weights change; a member is
   deleted and added back; an uplink goes admin down and up. After each
   change, every peer again gets exactly one copy.
3. A gateway's neighbour goes FAILED, so its hash-threshold group leaves it
   out, with no netlink event. In the xdp mode a dropped copy triggers the
   rebuild; afterwards every peer gets one copy again. The same when it
   comes back.

4. In the xdp modes, two ACs of the BD disagree on a peer's uplink (an iif ip
   rule). One devmap cannot serve that, so the BD falls back to tc mode: every
   peer still gets one copy, and each AC's copies follow its own table. The BD
   returns to xdp mode when the ACs agree again.
5. In the xdp modes, the AC's forwarding sysctl goes off, which leaves every
   slot out. Turning it back on sends no netlink event; the periodic retry
   brings the slots back within 30 s.

## Quick start

```bash
sudo ./setup.sh    # build the environment
sudo BUM_MODE=xdp ./test.sh
sudo ./teardown.sh
```
