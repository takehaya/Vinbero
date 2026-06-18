# mup-2site-multivrf — 1 台の GW に 2 つの MUP サービスインスタンス、F-TEID 完全重複

*(English: [README.md](./README.md))*

MUP GW の uplink service instance を検証する
[containerlab](https://containerlab.dev/) シナリオです。2 つの VPN (A / B) が
1 台の Vinbero MUP-GW と 1 台の Vinbero MUP-PE を共有し、VPN として重複し得る
ものを意図的にすべて重複させます。N3 endpoint (`172.16.0.254`)、TEID
(`256`)、inner の UE (`10.1.0.1`)、DN ホスト (`10.0.0.1`) まで同一で、uplink
トラフィックを分けるのは GW のどの access interface に届いたかだけです。

## トポロジ

```mermaid
graph LR
    GNBA["gnb-a<br/>172.16.0.1"]
    GNBB["gnb-b<br/>172.16.0.1"]
    GW["mup-gw<br/>uplink instance 1 / 2"]
    CORE["core<br/>IPv6 backbone"]
    PE["mup-pe<br/>End.DT4 → vrf-a / vrf-b"]
    DNA["dn-a<br/>10.0.0.1"]
    DNB["dn-b<br/>10.0.0.1"]
    MC["mup-c<br/>MUP Controller"]

    GNBA ---|"N3-A GTP-U"| GW
    GNBB ---|"N3-B GTP-U"| GW
    GW --- CORE
    CORE --- PE
    PE ---|N6-A| DNA
    PE ---|N6-B| DNB
    MC -.iBGP SAFI 85.- CORE
```

## 検証する内容

F-TEID map は uplink セッションを {instance, endpoint, TEID prefix} でキー
し、`mup_ifindex_instance_map` が ingress ifindex からパケットの instance を
解決する。instance が無ければ、下の 2 つの T2ST は同じ {endpoint, TEID} で
衝突して後勝ちになる。

- mup-gw は VPN ごとに uplink instance を runtime に bind する。
  `vbctl vrf-bgp bind --vrf vpn-a --rt mup_ipv4:100:6001:import
  --mup-uplink-interfaces eth1` (vpn-b は eth2 で対称)。import RT がどの
  T2ST をその instance に install するかを決め、interface list がどの
  パケットをその instance に分類するかを決める。
- mup-c は `{endpoint, TEID}` が同一の SID なし T2ST を 2 本 advertise する。
  違いは RD (サービスインスタンスごと)、RT (uplink VPN ごと)、MUP segment id
  だけ。
- mup-pe は VPN ごとの DSD (segment id `1:1` / `1:2`、per-VPN の End.DT4
  direct SID 付き) を advertise し、同一アドレッシングの N6 を持つ kernel
  VRF vrf-a / vrf-b をホストする。

RD と RT の使い分けは次のとおり。RD は per-advertiser (controller の
セッションはサービスインスタンスごとに `65100:1` / `65100:2`、PE の DSD は
`65100:21` / `65100:22`)、VPN の所属と解決のスコープは RT (`100:6001` が A、
`100:6002` が B) が決め、segment id が各 T2ST を自 VPN の DSD と結ぶ。

## データ経路

uplink のみ (downlink と PE 側の headend instance 化は対象外。双方向の経路は
mup-2site を参照)。

- `gnb-a → dn-a`: `172.16.0.254` 宛 GTP-U (TEID 256) が mup-gw の eth1 に
  入る → instance 1 → F-TEID entry A → `fd00:d:0:1::` へ SRv6 → `End.DT4`
  が vrf-a へ decap → dn-a が inner `10.1.0.1 → 10.0.0.1` を受信。
- `gnb-b → dn-b`: byte 単位で同一のパケットが eth2 に入る → instance 2 →
  direct SID `fd00:d:0:2::` → vrf-b → dn-b。

`test.sh` は control plane (同一 {endpoint, TEID} の T2ST 2 本が共有 gate の
下で別 instance に install されること) と、VPN ごとに自分の DN へ届き、
byte 単位で同一の inner を受け入れてしまうはずのもう一方の DN には何も
届かないこと (cross-instance leak なし) を検証します。

## 実行

```bash
make all SCENARIO=mup-2site-multivrf
```
