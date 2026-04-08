# SRv6 GTP-U/IPv6 (End.M.GTP6.D + End.M.GTP6.E)

RFC 9433に基づくGTP-U/IPv6とSRv6の双方向変換のデモ環境です。

## トポロジー

```mermaid
graph LR
    gNB[gNB/host1<br/>GTP-U/IPv6] -->|GTP-U/IPv6| router1[router1 / Vinbero XDP<br/>fc00:1::1<br/>End.M.GTP6.D]
    router1 -->|SRv6| router2[router2<br/>fc00:2::1<br/>End]
    router2 -->|SRv6| router3[router3 / Vinbero XDP<br/>fc00:3::3<br/>End.M.GTP6.E]
    router3 -->|GTP-U/IPv6| UPF[UPF/host2<br/>GTP-U/IPv6]
```

**パケットの流れ:**
1. gNBがGTP-U/IPv6パケットをSRv6パス上で送信
2. **router1 (End.M.GTP6.D)**: GTP-Uを剥離、SRv6セグメント処理を継続。TEID/QFIを次SIDのArgs.Mob.Sessionにエンコード
3. router2 (End): SRv6 transit
4. **router3 (End.M.GTP6.E)**: SRv6を剥離、SIDからTEID/QFIをデコード、GTP-U/IPv6で再カプセル化

## クイックスタート

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```
