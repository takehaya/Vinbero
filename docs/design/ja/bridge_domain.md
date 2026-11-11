# Bridge Domain (BD)

## BDとは何か

BDは、どのMACアドレステーブル（FDB）を使うかを決めるグループIDです。

L2スイッチに例えると、BDごとに独立したMACアドレステーブルを持つようなものです。同じBD IDのポート同士だけがL2で通信できます。

## VLAN IDでは不十分な理由

```
router1 の eth0 ──── VLAN 100 ──── 顧客A の host1
router1 の eth1 ──── VLAN 100 ──── 顧客B の host3
```

同じルータの異なるポートで VLAN 100 が別々の顧客に使われることがあります。FDBのキーが `(VLAN, MAC)` だと、顧客Aと顧客BのMACが同じテーブルに混在します。

BD IDを導入すると、次のように分離できます。

```
eth0/VLAN 100 → BD 100（顧客A）
eth1/VLAN 100 → BD 200（顧客B）
```

FDBは `(bd_id, MAC)` でキーイングされるため、顧客AとBのテーブルが完全に分離されます。

単純な構成であれば VLAN ID = BD ID で問題ありません。例えば VLAN 100 → BD 100 のように設定します。

## bd_id=0 と bd_id>0 の違い

```
bd_id=0:   全フレームをそのまま SRv6 encap する（P2P用）
bd_id>0:   MAC学習して効率的に転送する（P2MP用）
```

### bd_id=0 の場合は全フレームをencapする

```
host1 → [全フレーム] → SRv6 encap → 対向PE → decap → host2
```

1対1接続で使用します。入ってきたフレームをすべてSRv6で包んで送ります。MAC学習もBUM floodも行いません。

### bd_id>0 の場合はMACを学習して宛先を判定する

```
① 最初の通信（ARP broadcast）
   host1 → router1: MACが不明 → 全PEにflood → host2に届く

② 学習後のユニキャスト
   host1 → router1: host2のMACはPE3にいると判明 → PE3だけにencap → host2
```

MAC学習により、2回目以降のユニキャストは不要なPEに送らずに済みます。

## 3つのAPIでの使い方

### ① HeadendL2Create でポートをBDに所属させる

```json
{
  "vlan_id": 100,
  "interface_name": "eth0",
  "src_addr": "fc00:1::1",
  "segments": ["fc00:2::1", "fc00:3::3"],
  "bd_id": 100
}
```

eth0 の VLAN 100 に入ってきたフレームを BD 100 として扱います。Vinbero が管理し unreachable default で閉じた VRF の port はポートにできず、`HeadendL2Create` はエラーになります (encap と BUM のコピーの外側を、その interface で VRF table から引いて止まってしまうため。[vrf.md](vrf.md#encap-の外側の経路))。

- `bd_id: 100` を指定すると、MAC学習とFDB判定が有効になります。
- `bd_id` を省略すると0となり、全フレームを直接encapします。

### ② SidFunctionCreate でdecap後のBDを指定する

```json
{
  "trigger_prefix": "fc00:3::3/128",
  "action": "SRV6_LOCAL_ACTION_END_DT2",
  "bd_id": 100,
  "bridge_name": "br100"
}
```

SRv6パケットをdecapした後、BD 100のFDBで宛先を検索します。

- `bd_id` は、inner frameのdst MACをどのFDBテーブルで引くかを指定します。
- `bridge_name` は、FDBに載っていないMAC宛の場合にフレームをfloodするLinux bridgeデバイスです。

### ③ BdPeerCreate でBDに対向PEを登録する

```json
{
  "peers": [{
    "bd_id": 100,
    "src_addr": "fc00:1::1",
    "segments": ["fc00:2::1", "fc00:3::3"]
  }]
}
```

BD 100にリモートPEを追加します。BUM trafficが発生すると、ここに登録された全PEにコピーが送出されます。

## Linux bridgeとの関係

BD自体はFDBスコーピング用のIDであり、概念としてはLinux bridgeを必要としません。ただし実用上、End.DT2（decap側）ではLinux bridgeが必要になります。

### decap側でbridgeが必要な理由

FDB missのとき、decapしたフレームをローカルの顧客ポートに届ける手段が必要です。decapされたフレームはuplink（SRv6トランジットIF）で受信されるため、そのままXDP_PASSしても顧客ポートには届きません。bridgeがあれば、bridge memberの顧客ポートにfloodできます。

```
bridge なし: decap → XDP_PASS → uplink の kernel stack → 顧客ポートに届かない
bridge あり: decap → bpf_redirect(bridge_ifindex) → bridge が flood → 顧客ポートに届く
```

### headend側はbridgeなしでも動く

headend（H.Encaps.L2）側は、顧客ポートで直接XDPが処理するため、bridgeがなくても動作します。BUM floodの元パケットはTC_ACT_OKでkernel stackに渡りますが、顧客ポートが1つだけならローカルfloodの必要がありません。

同じBDに複数の顧客ポートがあり、ローカル間でもL2転送したい場合は、headend側にもbridgeが必要になります。

### まとめ

| 場所 | bridge | 理由 |
|------|--------|------|
| End.DT2（decap側） | 必要 | FDB miss時にdecapしたフレームを顧客ポートにfloodするため |
| H.Encaps.L2（headend側） | 顧客ポートが1つなら不要 | 複数ポート間のローカルL2転送が必要なら要る |

`settings.l2.bum_mode: xdp` の BD では、ローカルの flood と既知 unicast も XDP で行い、bridge を経路に使いません。その代わり STP や IGMP snooping などの bridge の機能は効きません。詳しくは [bum_mode.md](bum_mode.md) を参照してください。

### bridgeの作成方法

bridgeは `VrfService/VrfBridgeAttach` APIで、VRF オブジェクトの L2 facet として作成します ([vrf.md](vrf.md) 参照)。APIを呼ぶとnetlinkでbridgeを作成し、member interfaceをenslaveし、owning VRF に facet として記録し、FDBWatcherにも自動登録します。1 つの bd_id はちょうど 1 つの VRF に属します。

### bridge の L3 role と host stack

bridge domain の bridge は L2 専用です。IP アドレスも gateway も持たせないでください。bridge device には host の IP 入力経路があり、bridge の port に入った機器 (CNI L2 の pod など) が bridge の MAC 宛にフレームを送ると host stack に届きます。forwarding が有効だと、別 PE の SID 宛や node のアドレス宛のフレームが underlay へ出たり local 配送されたりして、tenant の分離が崩れます。これは「VRF device に enslave されていない AC」の一例です ([vrf.md](vrf.md#local-sid-と-ac))。bridge を tenant の VRF device に enslave しない構成では、bridge device の IP 入力を両 family とも塞いでください (`disable_ipv6`、`ipv4.*.forwarding=0`、`rp_filter=1`、`arp_ignore=8` など)。CNI L2 mode はこれを pod の attach 時に自動で設定し、CHECK で検証します。設定の一覧と理由は [cni.md](cni.md#bridge-に-l3-の役割を持たせない-host-stack-の分離) を参照してください。

## MAC学習の仕組み

### ローカル学習で顧客ポートのMACを記録する

```
host1 → eth0 → XDP:
  src MAC = AA:BB:CC:DD:EE:FF はこのポート(eth0)にいると記録する
  → fdb_map[(BD100, AA:BB:CC:DD:EE:FF)] = { oif=eth0, local }
```

### リモート学習でSRv6経由のMACを記録する

```
SRv6パケット → End.DT2 decap → inner frame:
  src MAC = 11:22:33:44:55:66 は PE3(peer_index=0) の先にいると記録する
  → fdb_map[(BD100, 11:22:33:44:55:66)] = { remote, peer_index=0 }
```

次にこのMACへのユニキャストが来たら、BUM floodせずに直接PE3へSRv6 encapします。

### 学習の保護

ローカル学習はリモートエントリを上書きしません。End.DT2で「このMACはPE3の先にいる」と学習した内容が、H.Encaps.L2側のローカル学習で壊されることを防ぎます。

### bridge の local エントリーと ageing

tc モードの BD では、kernel の bridge の FDB を `fdb_map` に写し、EVPN の自動広告では RT2 にします。

- bridge の port の MAC と bridge 自身の MAC は `fdb_map` には写しますが、RT2 にはしません。decap したフレームは bridge の送信経路に redirect されるので、host には届かないためです。`bridge fdb add MAC dev tap0 master` のように operator が port に置いた MAC は RT2 にします
- bridge が持っている MAC の寿命は kernel が決めます。`settings.fdb_aging_seconds` の ageing は、bridge が持っている local MAC を消しません。`ageing_time` で消えたときの通知で withdraw します。static エントリーも bridge が消すまで残ります
- XDP が直近 30 秒以内に見ている MAC は、bridge が ageing で消しても `fdb_map` にも RT2 にも残します。ホストが remote とだけ通信していると bridge からは見えないためです。XDP からも見えなくなると ageing で消えます
- それより長く静かだった MAC は bridge の ageing で RT2 を取り下げます。XDP がまた学習すると、ageing の周期ごとに RT2 に戻します

## 設定例

### 最小構成としてP2PでBDを使わない場合

```bash
# router1: 全VLAN 100トラフィックをSRv6 encapする（bd_idは省略して0にする）
curl -X POST .../HeadendL2Create -d '{
  "headend_l2s": [{"vlan_id":100, "interface_name":"eth0",
    "src_addr":"fc00:1::1", "segments":["fc00:3::3"]}]
}'

# router3: decapして直接出力する（Linux native）
ip -6 route add fc00:3::3/128 encap seg6local action End.DX2 oif eth0 dev lo
```

### P2MP構成でBDを使う場合

```bash
# === router1（headend側） ===

# eth0/VLAN100 を BD100 に紐付ける
curl -X POST .../HeadendL2Create -d '{
  "headend_l2s": [{"vlan_id":100, "interface_name":"eth0",
    "src_addr":"fc00:1::1", "segments":["fc00:2::1","fc00:3::3"],
    "bd_id":100}]
}'

# BD100 にリモートPE（router3）を登録する
curl -X POST .../BdPeerCreate -d '{
  "peers": [{"bd_id":100, "src_addr":"fc00:1::1",
    "segments":["fc00:2::1","fc00:3::3"]}]
}'

# === router3（decap側） ===

# Bridge を VRF の L2 facet として attach（FDBWatcherにも自動登録される）
curl -X POST .../VrfService/VrfBridgeAttach -d '{
  "vrf_name": "evi-100",
  "bridge": {"name":"br100", "bd_id":100, "members":["eth1"]}
}'

# End.DT2でdecapし、BD100のFDBで転送する。missの場合はbr100にfloodする
curl -X POST .../SidFunctionCreate -d '{
  "sid_functions": [{"trigger_prefix":"fc00:3::3/128",
    "action":"SRV6_LOCAL_ACTION_END_DT2",
    "bd_id":100, "bridge_name":"br100"}]
}'

# return path として router3 から router1 への設定を行う
curl -X POST .../HeadendL2Create -d '{
  "headend_l2s": [{"vlan_id":100, "interface_name":"eth1",
    "src_addr":"fc00:3::3", "segments":["fc00:2::2","fc00:1::2"],
    "bd_id":100}]
}'
curl -X POST .../BdPeerCreate -d '{
  "peers": [{"bd_id":100, "src_addr":"fc00:3::3",
    "segments":["fc00:2::2","fc00:1::2"]}]
}'
```
