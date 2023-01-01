# Vinbero
Vinbero is a very fast high-performance SRv6 implementation
Vibero is about 3-5 Mpps in single flow, which is 2-3 times better performance than linux!

<div style="text-align:center;">
<img src="./design/logo-100.jpg" style="height:auto;width:60vw;">
</div>

The goal of this project is to implement the basic functions of SRv6 so that users can enjoy network programming:)
For example, L2,L3VPN, ServiceChain, Mobile Uplane(in UPF)...etc,

This implementation is also very powerful because it is written in XDP.
It does not require any special equipment like P4.
All you need is the latest linux kernel to run it.
It is also a very small implementation compared to VPP.
It's easy to understand and easy to add functionality.It is also possible to incorporate these:)(e.g. CNI, NOS...etc)

Please raise issue with use case description if you want to any SRv6 functions not implemented yet or let's make a contribution!

## Required package
* linux: 5.15.15<=x
  * It means that the version you are testing is 5.15.15. Actually, if BTF supports it, I think there is no problem.
* golang: 1.3<=x
* clang: 12

## Setup
```
ulimit -l unlimited

# if "ulimit -l unlimited" is not working when plz check
echo "DefaultLimitMEMLOCK=infinity">>/etc/systemd/system.conf
echo "DefaultLimitMEMLOCK=infinity">>/etc/systemd/user.conf
```

remove offload
```
for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
       /sbin/ethtool -K eth1 $i off 2>&1 > /dev/null;
done
```

use irqaffinity. this mellanox nic case.
```
git clone https://github.com/Mellanox/mlnx-tools.git
cd mlnx-tools/
./set_irq_affinity.sh ens4f0np0
```


## Build
```
cd include
wget https://raw.githubusercontent.com/cloudflare/xdpcap/master/hook.h
cd ..
make
```
## ConfigExample
This is an example of performing the End operation.
```yaml
internal:
  devices:
    - eth1
    - eth2
settings:
  functions:
    - action: SEG6_LOCAL_ACTION_END
      triggerAddr: fc00:2::1/128
      actionSrcAddr: fc00:1::1
      flaver: NONE
    - action: SEG6_LOCAL_ACTION_END
      triggerAddr: fc00:2::2/128
      actionSrcAddr: fc00:1::1
      flaver: NONE
```

In the transit case, actionSrcAddr works as a so-called bsid.

See this for details: [vinbero.yml.sample](./vinbero.yml.sample)

## Run
```
./bin/vinbero
```

## List of SRv6 functions of interest and status (a.k.a. Road Map)

### Reference list
* [draft-filsfils-spring-srv6-network-programming](https://datatracker.ietf.org/doc/draft-ietf-spring-srv6-network-programming/)
* [draft-ietf-dmm-srv6-mobile-uplane](https://datatracker.ietf.org/doc/draft-ietf-dmm-srv6-mobile-uplane/)
* [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding)

### Transit behaviors

| Function | schedule | description |
|----------|----------|-------------|
| T | n/a | Transit behavior|
| T.Insert | future | |
| T.Insert.Red |  | |
| T.Encaps | Done | |
| T.Encaps.Red |  | |
| T.Encaps.L2 | future | |
| T.Encaps.L2.Red |  | |

### Functions associated with a SID

| Function | schedule | description |
|----------|----------|-------------|
| End | Done | |
| End.X | Fed, 2020 | |
| End.T | | |
| End.DX2 (V) | | |
| End.DT2 (U/M) | | |
| End.DX6 | Done | |
| End.DX4 | Done | |
| End.DT6 | | |
| End.DT4 | | |
| End.DT46 | | |
| End.B6.Insert | | |
| End.B6.Insert.Red | | |
| End.B6.Encaps | | |
| End.B6.Encaps.Red | | |
| End.BM | | |
| End.S | | |
| Args.Mob.Session | Done | Consider with End.MAP, End.DT and End.DX |
| End.MAP | | |
| End.M.GTP6.D | Mar, 2021 | GTP-U/IPv6 => SRv6, For implementation purposes, it is treated as transit　|
| End.M.GTP6.D.Di | Mar, 2021 | GTP-U/IPv6 => SRv6, For implementation purposes, it is treated as transit |
| End.M.GTP6.E | Mar, 2021 | SRv6 => GTP-U/IPv6 |
| End.M.GTP4.E | partial Done, Mar, 2021 | SRv6 => GTP-U/IPv4 gtpv1ext hdr is not supported. |
| H.M.GTP4.D | partial Done, Mar, 2021 | GTP-U/IPv4 => SRv6, Currently, gtpv1ext hdr is not supported. |
| End.Limit | | Rate Limiting function |

### Non functional design items

| Item name | schedule |
|-----------|----------|
| BSID friendly table structure | future |

### Flavours

| Function | schedule | description |
|----------|----------|-------------|
| PSP | future | Penultimate Segment Pop |
| USP | | Ultimate Segment Pop |
| USD | | Ultimate Segment Decapsulation |

## Respectful implementation
I'm using these as a reference. thanks:)
* [p4srv6](https://github.com/ebiken/p4srv6)
* [linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)
* [VPP/srv6_mobile_plugin_doc](https://docs.fd.io/vpp/20.05/d7/d3c/srv6_mobile_plugin_doc.html)

## Trivia
The Vinbero is an Esperanto word meaning `grape`
A meshed node running SRv6 looks like a grape when viewed from above:)
