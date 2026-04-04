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

eth0 の VLAN 100 に入ってきたフレームを BD 100 として扱います。

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

### bridgeの作成方法

bridgeは `NetworkResourceService/BridgeCreate` APIで作成します。APIを呼ぶとnetlinkでbridgeを作成し、member interfaceをenslaveし、FDBWatcherにも自動登録します。

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

# Bridge作成（API経由、FDBWatcherにも自動登録される）
curl -X POST .../NetworkResourceService/BridgeCreate -d '{
  "bridges": [{"name":"br100", "bd_id":100, "members":["eth1"]}]
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
