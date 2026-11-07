# BUM 複製モード（settings.l2.bum_mode）

Bridge Domain（BD）の BUM（broadcast、未知 unicast、multicast）フレームを、どの hook で複製するかを選びます。BD の概念は [bridge_domain.md](bridge_domain.md) を参照してください。

| モード | 複製する場所 | ローカルの flood | 既定 |
|---|---|---|---|
| `tc` | TC ingress の `bpf_clone_redirect`（リモート PE ごとに 1 回） | kernel の bridge | ○ |
| `xdp` | XDP の devmap broadcast（`BPF_F_BROADCAST`） | XDP（同じ devmap） | |

`tc` はこれまでと同じ動作です。`xdp` を設定しない限り、データプレーンの命令列も変わりません（`bum_xdp_enabled` 定数が 0 のとき、xdp モードの分岐は verifier が取り除きます）。

## xdp モードの経路

送信側（AC から入った BUM）:

1. XDP の L2 headend がいつもどおり送信元 MAC を学習し、宛先が multicast か FDB miss なら、BD の devmap（`bum_flood_map[bd_id]`）へ `bpf_redirect_map(BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)` します。
2. devmap のメンバーはローカル AC（key は ifindex、program なし）と、リモートの flood スロット（key は `0x80000000 | index`、値は uplink の ifindex とスロット専用の egress program）です。
3. スロット i の egress program（`bum_remote_egress_i`）は、`ctx->ingress_ifindex` とフレームの VLAN から送信元 AC を引き、`bd_peer_map[{bd_id, i}]` へ H.Encaps.L2（.Red）をかけて、FIB の結果で MAC を書き換えます。split horizon（ESI 一致）と `flood_exclude` の判定は TC モードと同じ規則です。同じ uplink の先に複数の PE があっても、エントリーごとに別の program が走るので、コピーごとに正しい宛先になります。

ローカルの既知 unicast は bridge を通さず、FDB の出力ポートへ `bpf_redirect` します（入力ポートと同じなら破棄）。

受信側（End.DT2 / End.DT2M の decap 後）: FDB miss のとき、bridge への redirect の代わりに `bum_local_map[bd_id]`（ローカル AC のみ）へ broadcast します。DF と RX split horizon の判定はその前に行われ、変わりません。

devmap は control plane が `headend_l2_map`、`bd_peer_map`、BD のモードから組み立て直します（HeadendL2 / BdPeer の作成・削除のたび、起動時、経路の変化時）。devmap がない BD（作成前など）は TC モードの経路にフォールバックし、`BUM_XDP_FALLBACK` を数えます。

xdp モードの BD では kernel の bridge が MAC を学習しないため、XDP の学習（新規・移動）を ring buffer（`fdb_event_rb`）で通知し、EVPN RT2 の自動広告に使います。その BD の bridge の FDB 通知は無視します。取りこぼしは FDB エージングの周期で `fdb_map` から補います。

## 要件と制約

- **generic XDP が必要**（`internal.bpf.device_mode: generic`）。native XDP は redirect したフレームを出力デバイスごとの bulk queue にまとめ、NAPI poll の中で最初に積んだフレームの devmap program を queue 全体に使います。同じ uplink に向かうスロットのコピーがすべて同じ PE の header になり、他の経路で同じ uplink へ redirect したフレームとも混ざります。generic XDP ではエントリーごとに program が走ります（ただし ingress の data_meta は devmap program に渡らないので、egress program はフレームと ingress ifindex から送信元を求めます）。設定の読み込み時に、generic 以外との組み合わせは拒否します。
- flood の対象は BD の HeadendL2 で登録した AC だけです。bridge の他のポートや bridge 自身には届きません。
- AC の VLAN tag はそのまま運びます（TC モードと bridge の動作と同じく、変換はしません）。
- AC と uplink が同じ物理ポートにある構成は対象外です（`BPF_F_EXCLUDE_INGRESS` で uplink へのコピーも除かれます）。
- devmap は 1 BD あたり 32 エントリー（ローカル AC とリモートのスロット 8 つの合計）、xdp モードの BD は 4096 個までです。
- egress program は出力デバイスを変えられません。FIB の結果が devmap の uplink と違うコピーは破棄し、`BUM_UPLINK_MISMATCH` を数えます。uplink の MTU は「内側フレーム + 外側 IPv6 + SRH」以上にしてください（devmap の MTU 確認は encap 前の長さで行われます）。

## xdp モードで失う bridge の機能

| 機能 | xdp モード | 理由 |
|---|---|---|
| STP / RSTP | 使えない | BPDU も devmap で flood され、bridge が受け取らない |
| IGMP / MLD snooping | 使えない | multicast はすべて BD 全体へ flood する |
| bridge netfilter（nftables bridge family、ebtables） | 効かない | フレームが bridge を通らない |
| `bridge fdb show` での可視化 | 見えない | 学習は `fdb_map` だけ（`vbctl fdb list` で確認する） |
| BD 上のホスト自身の IP（bridge に IP を置く、IRB） | 使えない | 宛先がホストの BUM もホストに渡らない |

これらが必要な BD は `tc` モードのままにしてください。

## 設定例

```yaml
internal:
  bpf:
    device_mode: generic      # xdp モードに必要
settings:
  enable_stats: true          # BUM_* カウンタを見る場合
  l2:
    bum_mode: xdp             # 全 BD の既定（省略時は tc）
    bridge_domains:           # BD ごとの上書き
      - bd_id: 200
        bum_mode: tc          # この BD は bridge の機能を使う
```

モードは起動時の設定で決まり、実行中には変えられません。

## 統計カウンタ

`vbctl stats show`（`enable_stats: true` のとき）に次のカウンタが加わります。

| カウンタ | 意味 |
|---|---|
| `BUM_XDP_FLOOD` | AC から入った BUM を devmap で broadcast した |
| `BUM_XDP_LOCAL_FLOOD` | decap 後の flood をローカル AC へ broadcast した |
| `BUM_XDP_FALLBACK` | xdp モードだが devmap がなく、TC / bridge の経路を使った |
| `BUM_EGRESS_TX` | egress program がリモートへのコピーを encap した |
| `BUM_EGRESS_DROP` | egress program がコピーを破棄した（peer なし、encap や FIB の失敗） |
| `BUM_UPLINK_MISMATCH` | FIB の出力先が devmap の uplink と違った |

split horizon で落としたコピーは、TC モードと同じ `SPLIT_HORIZON_TX` に数えます。
