# SRv6 End.DX4 Playground

Vinbero XDPによるSRv6 End.DX4 (Decapsulation with IPv4 Cross-connect) のデモ環境です。

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │           │          │          │          │ (Vinbero)│          │         │
│172.0.1.1├──────────┤172.0.1.2  ├──────────┤ fc00:12  ├──────────┤172.0.2.2 ├──────────┤172.0.2.1│
│         │          │fc00:1::1  │          │   ::2    │          │fc00:3::3 │          │         │
│         │          │ H.Encaps  │          │   End    │          │ End.DX4  │          │         │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                                                                  ↑ Vinbero XDP
                                                                  SID: fc00:3::3
                                                                  Action: End.DX4
```

**パケットの流れ（host1→host2の例）:**
1. host1が172.0.2.1にpingを送信 (IPv4)
2. router1がLinux native H.Encapsを実行:
   - IPv4パケットをIPv6+SRHでカプセル化
   - Outer DA: fc00:2::1 (最初のセグメント)
   - Segment List: [fc00:2::1, fc00:3::3]
3. router2がfc00:2::1でEnd操作を実行（SL減少、次のセグメントへ）
4. **router3 (Vinbero XDP)** がfc00:3::3でEnd.DX4を実行:
   - 外側IPv6+SRHヘッダを除去
   - 内側IPv4パケットをFIBルックアップで転送
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

# router3のLinux native End.DX4ルートを削除
sudo ip netns exec dx4-router3 ip -6 route del local fc00:3::3/128 2>/dev/null

# Vinbero起動
sudo ip netns exec dx4-router3 ../../out/bin/vinbero -c vinbero_router3.yaml
```

### 2. SidFunction (End.DX4) エントリ登録

```bash
sudo ip netns exec dx4-router3 curl -X POST http://127.0.0.1:8082/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [
      {
        "trigger_prefix": "fc00:3::3/128",
        "action": "SRV6_LOCAL_ACTION_END_DX4"
      }
    ]
  }'
```

### 3. テスト

```bash
sudo ip netns exec dx4-host1 ping -c 3 172.0.2.1
```

#### パケットキャプチャ

```bash
# router2-router3間でSRv6パケットを確認
sudo ip netns exec dx4-router3 tcpdump -i dx4-rt3rt2 -n ip6

# router3-host2間でデカプセル化後のIPv4パケットを確認
sudo ip netns exec dx4-router3 tcpdump -i dx4-rt3h2 -n ip
```

### 4. 環境のクリーンナップ
```bash
sudo ./teardown.sh
```
