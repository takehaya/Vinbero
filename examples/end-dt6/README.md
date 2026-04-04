# SRv6 End.DT6 Playground

Vinbero XDPによるSRv6 End.DT6 (Decapsulation with IPv6 Table lookup via VRF) のデモ環境です。

## トポロジー

```
┌─────────┐          ┌───────────┐          ┌──────────┐          ┌──────────┐          ┌─────────┐
│  host1  │          │  router1  │          │ router2  │          │ router3  │          │  host2  │
│         │          │           │          │          │          │ (Vinbero)│          │         │
│10.0.1.1 ├──────────┤fc00:1::1  ├──────────┤ fc00:12  ├──────────┤fc00:3::3 ├──────────┤10.0.1.2 │
│2001:db8 │          │ H.Encaps  │          │   ::2    │          │ End.DT6  │          │2001:db8 │
│:1::1    │          │           │          │   End    │          │ vrf100   │          │:2::1    │
└─────────┘          └───────────┘          └──────────┘          └──────────┘          └─────────┘
                                                                  ↑ Vinbero XDP
                                                                  SID: fc00:3::3
                                                                  Action: End.DT6
                                                                  VRF: vrf100 (table 100)
```

**パケットの流れ（host1 → host2の例）:**
1. host1が2001:db8:2::1にpingを送信（IPv6）
2. router1がLinux native H.Encapsを実行し、IPv6パケットを外側IPv6+SRHでカプセル化する
3. router2がfc00:2::1でEnd操作を実行する（SL減少、次のセグメントへ）
4. router3（Vinbero XDP）がfc00:3::3でEnd.DT6を実行する
   - 外側IPv6+SRHヘッダを除去する
   - VRF vrf100のルーティングテーブルでFIBルックアップし、host2へ転送する
5. host2がpingを受信する

End.DT4との違いは、内側パケットがIPv6である点です。End.DT46を使えばIPv4/IPv6の両方を1つのSIDで処理できます。

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

# router3のLinux native End.DT6ルートを削除
sudo ip netns exec dt6-router3 ip -6 route del local fc00:3::3/128 2>/dev/null

# Vinbero起動
sudo ip netns exec dt6-router3 ../../out/bin/vinberod -c vinbero_router3.yaml
```

### 2. SidFunction (End.DT6) エントリ登録

```bash
sudo ip netns exec dt6-router3 ../../out/bin/vinbero -s http://127.0.0.1:8082 \
  sid create --trigger-prefix fc00:3::3/128 --action END_DT6 --vrf-name vrf100
```

### 3. テスト

```bash
sudo ip netns exec dt6-host1 ping6 -c 3 2001:db8:2::1
```

#### パケットキャプチャ

```bash
# router2-router3間でSRv6パケットを確認
sudo ip netns exec dt6-router3 tcpdump -i dt6-rt3rt2 -n ip6

# router3-host2間でデカプセル化後のIPv6パケットを確認
sudo ip netns exec dt6-router3 tcpdump -i dt6-rt3h2 -n ip6
```

### 4. クリーンアップ
```bash
sudo ./teardown.sh
```
