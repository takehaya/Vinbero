# SRv6 End.DT2 Playground

Vinbero XDPによるSRv6 End.DT2 (Decapsulation with L2 Table lookup) のデモ環境です。
Bridge Domain、MAC学習、BUM flooding を含むL2VPNの完全な双方向動作を検証します。

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│ VLAN100 │          │ (Vinbero) │          │          │          │ (Vinbero)│          │ VLAN100 │
│172.16   ├──────────┤fc00:1::1  ├──────────┤ fc00:12  ├──────────┤fc00:3::3 ├──────────┤172.16   │
│.100.1   │          │H.Encaps.L2│          │   ::2    │          │ End.DT2  │          │.100.2   │
│         │          │+ TC BUM   │          │   End    │          │ + bridge │          │         │
│         │          │           │          │          │          │   br100  │          │         │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                      ↑ Vinbero XDP+TC                             ↑ Vinbero XDP
                      H.Encaps.L2 (bd_id=100)                     SID: fc00:3::3
                      BUM flood via TC clone                       Action: End.DT2
                                                                   BD: 100, Bridge: br100
```

**パケットの流れ（host1 → host2、初回ARP）:**
1. host1がVLAN 100でARP broadcastを送信する
2. router1（Vinbero XDP）がBUMフレームを検出し、XDP_PASSでTCに渡す
3. router1（TC）がclone-to-selfで各リモートPEにSRv6 encapしたコピーを送出する
   - VLAN materializationでinner frameにVLAN tagを復元する
4. router2がEndでSRH transitする
5. router3（Vinbero XDP）がEnd.DT2を実行する
   - SRv6 decapしてinner L2 frame（VLAN 100付き）を取り出す
   - inner src MACをリモートエントリとしてFDBに学習する
   - FDB miss → bridge br100にredirectしてfloodする
6. host2がARP requestを受信し、replyを返す

2回目以降のユニキャストは、FDB学習済みのため直接対向PEにSRv6 encapされます。

## クイックスタート

```bash
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ
```

## 手動実行

### 1. 環境構築とVinbero起動

```bash
sudo ./setup.sh

# router1でVinbero起動（H.Encaps.L2 + TC BUM）
sudo ip netns exec dt2-router1 ../../out/bin/vinberod -c vinbero_router1.yaml &

# router3でVinbero起動（End.DT2 + H.Encaps.L2 return path）
sudo ip netns exec dt2-router3 ../../out/bin/vinberod -c vinbero_router3.yaml &
```

### 2. router1の設定（forward path）

```bash
# H.Encaps.L2: VLAN 100 → BD 100 → SRv6 encap
sudo ip netns exec dt2-router1 ../../out/bin/vinbero -s http://127.0.0.1:8082 \
  hl2 create --interface dt2-rt1h1 --vlan-id 100 \
  --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3 --bd-id 100

# BdPeer: BD 100のリモートPE（router3）を登録
sudo ip netns exec dt2-router1 ../../out/bin/vinbero -s http://127.0.0.1:8082 \
  peer create --bd-id 100 --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3
```

### 3. router3の設定（decap + return path）

```bash
# End.DT2: SRv6 decap → BD 100 → bridge flood
sudo ip netns exec dt2-router3 ../../out/bin/vinbero -s http://127.0.0.1:8083 \
  sid create --trigger-prefix fc00:3::3/128 --action END_DT2 --bd-id 100 --bridge-name br100

# H.Encaps.L2: return path
sudo ip netns exec dt2-router3 ../../out/bin/vinbero -s http://127.0.0.1:8083 \
  hl2 create --interface dt2-rt3h2 --vlan-id 100 \
  --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::2 --bd-id 100

# BdPeer: return path
sudo ip netns exec dt2-router3 ../../out/bin/vinbero -s http://127.0.0.1:8083 \
  peer create --bd-id 100 --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::2
```

### 4. テスト

```bash
# L2VPN経由のping（VLAN 100）
sudo ip netns exec dt2-host1 ping -c 3 -I dt2-h1rt1.100 172.16.100.2

# FDBエントリの確認
sudo ip netns exec dt2-router3 ../../out/bin/vinbero -s http://127.0.0.1:8083 fdb list
```

#### パケットキャプチャ

```bash
# router1-router2間でSRv6 encap済みパケットを確認
sudo ip netns exec dt2-router1 tcpdump -i dt2-rt1rt2 -n ip6

# router3-host2間でdecap後のL2フレーム（VLAN 100）を確認
sudo ip netns exec dt2-router3 tcpdump -i dt2-rt3h2 -n -e
```

### 5. クリーンアップ
```bash
sudo ./teardown.sh
```
