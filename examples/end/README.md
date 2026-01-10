# SRv6 End Playground

Vinbero XDPによるSRv6 End操作のデモ環境です。

## トポロジー

```
┌─────────┐          ┌──────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │ router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │          │          │ (Vinbero)│          │          │          │         │
│172.0.1.1├──────────┤172.0.1.2 ├──────────┤ fc00:12  ├──────────┤172.0.2.2 ├──────────┤172.0.2.1│
│         │          │fc00:1::1 │          │   ::2    │          │fc00:3::3 │          │         │
│         │          │ End.DX4  │          │ fc00:23  │          │ End.DX4  │          │         │
│         │          │          │          │   ::2    │          │          │          │         │
└─────────┘          └──────────┘          └──────────┘          └──────────┘          └─────────┘
                                            fc00:2::1 ← SID (host1→host2用)
                                            fc00:2::2 ← SID (host2→host1用)
                                            End動作
```

**パケットの流れ（host1→host2の例）:**
1. host1が172.0.2.1にpingを送信
2. router1がSRv6カプセル化（T.Encaps）してSegment List: [fc00:2::1, fc00:3::3]を付与
3. **router2 (Vinbero XDP)** がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. router3がfc00:3::3でEnd.DX4を実行（IPv4に戻す）
5. host2がpingを受信

## クイックスタート

```bash
sudo ./setup.sh    # 環境構築
sudo ./test.sh     # テスト実行
sudo ./teardown.sh # クリーンアップ（環境削除）
```

## 手動実行

### 1. 環境構築とVinbero起動

```bash
sudo ./setup.sh

# router2のLinux native SRv6を削除
sudo ip netns exec router2 ip -6 route del local fc00:2::1/128 2>/dev/null
sudo ip netns exec router2 ip -6 route del local fc00:2::2/128 2>/dev/null

# Vinbero起動
sudo ip netns exec router2 ../../out/bin/vinbero -c vinbero_router2.yaml
```

### 2. SID登録

```bash
sudo ip netns exec router2 curl -X POST http://127.0.0.1:8082/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [
      {
        "trigger_prefix": "fc00:2::1/128",
        "action": "SRV6_LOCAL_ACTION_END",
        "flavor": "SRV6_LOCAL_FLAVOR_NONE"
      },
      {
        "trigger_prefix": "fc00:2::2/128",
        "action": "SRV6_LOCAL_ACTION_END",
        "flavor": "SRV6_LOCAL_FLAVOR_NONE"
      }
    ]
  }'
```

### 3. テスト

```bash
sudo ip netns exec host1 ping -c 3 172.0.2.1
sudo ip netns exec host2 ping -c 3 172.0.1.1
```

#### パケットキャプチャ

```bash
sudo ip netns exec router3 tcpdump -i veth-rt3-rt2 -n ip6
```

SRv6 Routing Header (RT6) でsegleft: 1→0、DA: fc00:2::1→fc00:3::3の変化が確認できます。

### 4. 環境のクリーンナップ
```bash
sudo ./teardown.sh
```
