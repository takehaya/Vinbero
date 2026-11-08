# BUM 複製モード（settings.l2.bum_mode）

Bridge Domain（BD）の BUM（broadcast、未知 unicast、multicast）フレームを、どの hook で複製するかを選びます。BD の概念は [bridge_domain.md](bridge_domain.md) を参照してください。

| モード | 複製する場所 | ローカルの flood | 既定 |
|---|---|---|---|
| `tc` | TC ingress の `bpf_clone_redirect`（リモート PE ごとに 1 回） | kernel の bridge | ○ |
| `xdp` | XDP の devmap broadcast（`BPF_F_BROADCAST`） | XDP（同じ devmap） | |

`tc` はこれまでと同じ動作です。`xdp` を設定しない限り、データプレーンの命令列も変わりません（`bum_xdp_enabled` 定数が 0 のとき、xdp モードの分岐は verifier が取り除きます）。

## xdp モードの経路

送信側（AC から入った BUM）:

1. XDP の L2 headend がいつもどおり送信元 MAC を学習し、宛先が multicast か FDB miss なら、BD の devmap（`bum_flood_map[bd_id]`）で broadcast します。
2. devmap のメンバーはローカル AC（key は ifindex）と、リモートの flood スロット（key は `0x80000000 | index`）です。スロットのエントリーの値は、その peer へ向かう uplink の ifindex と egress program です。egress program は全エントリー共通の 1 本（`bum_remote_egress`）です。同じ uplink の先に peer が k 個あれば、その uplink のエントリーも k 個になり、broadcast はその uplink 向けに k 個のコピーを作ります。ローカル AC のエントリーは program を持ちません。ただし、AC のデバイスがその BD のスロットの uplink でもある場合（AC と uplink が同じポート）は、そのエントリーにも同じ egress program を付けます（後述）。
3. ingress program は broadcast の直前に、そのフレームの複製計画（以下 plan）を CPU ごとのリングに書きます（次節）。
4. `bpf_redirect_map(BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)` で broadcast します。入力ポートが、送るスロットの uplink でもある場合だけは `BPF_F_EXCLUDE_INGRESS` を付けません（付けると、そのポートへのリモートのコピーも除かれるため）。plan を書くときに引いた devmap をそのまま使うので、control plane が devmap を差し替えている最中でも、plan と broadcast が別々の版を見ることはありません。
5. egress program はコピーごとに、plan から自分の uplink の項目を探して次のスロットを 1 つ取り、`bd_peer_map[{bd_id, スロット}]` の peer へ H.Encaps.L2（.Red）をかけて、FIB の結果で MAC を書き換えます。

ローカルの既知 unicast は bridge を通さず、FDB の出力ポートへ `bpf_redirect` します（入力ポートと同じなら破棄）。devmap のない BD では、これまでどおり bridge に渡します。

受信側（End.DT2 / End.DT2M の decap 後）: FDB miss のとき、bridge への redirect の代わりに `bum_local_map[bd_id]`（ローカル AC のみ、egress program なし）へ broadcast します。DF と RX split horizon の判定はその前に行われ、変わりません。

devmap は control plane が `headend_l2_map`、`bd_peer_map`、BD のモードから組み立て直します（HeadendL2 / BdPeer の作成・削除のたび、起動時、経路の変化時）。新しい内側の map を作ってから、外側の map のエントリーを差し替えます。devmap がない BD（作成前や、ローカル AC がない BD）は TC モードの経路にフォールバックし、`BUM_XDP_FALLBACK` を数えます。AC のデバイスが消えているなど、devmap に加えられない AC やスロットは、警告を出して外し、残りで組み立てます。

xdp モードで正しく扱えない BD には、control plane は devmap を作りません。次の 2 つです。

- AC の VLAN ID が揃っていない BD。xdp モードはフレームを VLAN tag ごとそのまま送ります（後述）。
- AC のデバイスとスロットの合計が、devmap の 32 エントリーに収まらない BD。

このような BD は、BUM も既知 unicast も TC モードと同じ経路（TC の複製と bridge）を通り、BUM は `BUM_XDP_FALLBACK` に数えます。理由は、状態が変わったときに 1 回、警告としてログに出します。構成が直れば、次の組み立てで xdp モードに戻ります。MAC 学習の通知（次段落）は、その間も XDP の学習から出ます。

xdp モードの BD では kernel の bridge が MAC を学習しないため、XDP の学習（新規・移動）を ring buffer（`fdb_event_rb`）で通知し、EVPN RT2 の自動広告に使います。その BD の bridge の FDB 通知は無視します。取りこぼしは FDB エージングの周期で `fdb_map` から補います。tc モードの BD では、`fdb_aging_seconds: 0` でも bridge が自分のエージング（既定 300 秒）でローカルの MAC を消し、その通知で RT2 を取り下げます。xdp モードの BD の MAC は bridge に載らないので、`fdb_aging_seconds: 0` のときは、vinberod が 30 秒ごとに、その BD のローカルの MAC のうち 300 秒使われていないものを消して RT2 を取り下げ、あわせて取りこぼしを補います。

### 複製計画（plan）

同じフレームのコピーは中身が同じで、同じ uplink へ向かうコピーは出力デバイスも同じです。egress program はコピーを見ただけでは、どの peer 宛てか判断できません。そこで ingress program が、broadcast の直前にフレームごとの plan を書きます。

| map | 型 | 中身 |
|---|---|---|
| `bum_seq` | `PERCPU_ARRAY`（1 エントリー、u64） | CPU ごとの通し番号。AC から入った BUM フレーム 1 つごとに `seq = (*p)++` |
| `bum_plan_ring` | `PERCPU_ARRAY`（1024 エントリー、各 96 バイト） | `seq & 1023` の位置に、そのフレームの plan |

plan の中身は次のとおりです。

- `seq`（照合用）、送信元 AC の ifindex、`bd_id`、`vlan_id`、フレーム長
- uplink ごと（最大 8 個）の項目: uplink の ifindex、送るスロットの集合（ビット i がスロット i、小さい順に割り当てる）、個数 `n`、割り当て済みの数 `next_idx`、そのデバイスがこの BD のローカル AC でもあるか（`local`。送信元 AC 自身なら 0）。項目は、devmap にスロットのエントリーがある uplink すべてに作ります（送るスロットが 0 個でも）
- ingress 時点の `ctx->data`（共有バッファの検出用、後述）

送るスロットは ingress で決めます。対象は、devmap にエントリーがあり（uplink にはそのエントリーの ifindex を使う）、`bd_peer_map` に peer があり、`flood_exclude` でなく、送信元 AC と同じ Ethernet Segment にない（RFC 9252 の split horizon）スロットです。判定の規則は TC モードの `tc_dispatch_bum_clones` と同じで、split horizon で除いたスロットは `SPLIT_HORIZON_TX` に数えます。encap のヘッダーは plan に入れず、egress program が `bd_peer_map` から引きます。ヘッダーまで入れると、CPU 数 × 1024 × 8 スロット分の容量が要るためです。

egress program の手順は次のとおりです。

1. 担当する `seq` を決めます。generic XDP では、この CPU の最新の seq（`bum_seq` の値 − 1）です。
2. `bum_plan_ring[seq & 1023]` を引き、plan の `seq`、送信元 AC（`ctx->ingress_ifindex`）、フレーム長がコピーと一致するか確かめます。一致しなければ破棄し、`BUM_PLAN_STALE` を数えます。
3. `ctx->egress_ifindex` で uplink の項目を探し、`idx = next_idx++` とします。
4. `idx < n` なら、集合の `idx` 番目のスロットの peer へ encap し、FIB の出力先がエントリーの uplink と一致することを確かめてから、`XDP_PASS` で送ります。
5. `idx == n` で `local` が 1 なら、そのデバイスのローカル AC へのコピーとして、そのまま `XDP_PASS` で送ります。コピーはどれも同じなので、どのコピーをローカル用にしても結果は変わりません。
6. それ以外は破棄し、`BUM_PLAN_SURPLUS` を数えます。devmap のエントリーは uplink の先の peer の数だけあるので、split horizon や `flood_exclude` で ingress が除いた分だけコピーが余ります。入力ポートを除かずに broadcast したときの、送信元 AC 自身へのコピーもここで破棄されます。

### 「最新の seq」で足りる理由

generic XDP の broadcast は、ingress program が返った直後に、同じ CPU の同じ呼び出しの中で、各コピーの devmap program を順に実行します（`do_xdp_generic` → `xdp_do_generic_redirect` → `dev_map_redirect_multi` → `dev_map_generic_redirect`）。この区間は BH が無効です（NAPI や backlog の softirq、threaded NAPI、tun などの `local_bh_disable`）。同じ CPU で別のフレームの ingress program が割り込むことはないので、コピーの egress program から見たこの CPU の最新の seq は、必ずそのコピーのフレームの seq です。リングを 1024 エントリーにしてあるのは、コピーを後でまとめて処理するモード（native）で、seq をフレームと一緒に運ぶ場合に備えるためです。

PREEMPT_RT のカーネルは例外です。`CONFIG_PREEMPT_RT_NEEDS_BH_LOCK` がなければ、BH 無効の区間どうしが同じ CPU で入れ替わることがあり、この前提が成り立ちません。`/sys/kernel/realtime` が 1 のカーネルでは、xdp モードでの起動を拒否します。

フレームの識別に `ctx->data` のアドレスは使えません。次節の修正が入ったカーネルでは、egress program を持つコピーはそれぞれ別のバッファに複製され、アドレスが ingress のものと一致しないためです。plan との照合には、seq に加えて送信元 AC とフレーム長を使います。

### コピーがバッファを共有するカーネル

"bpf: Run generic devmap egress prog on private skb" が入っていないカーネルでは、generic XDP の broadcast のコピー（`skb_clone`）がすべて同じパケットバッファを共有します。egress program がフレームの前に書いたヘッダーは共有部分に入るので、送信待ちのコピーは全部、最後に書かれたヘッダーを運びます。xdp モードはコピーごとに別の peer 宛てのヘッダーを書くので、このようなカーネルでは使えません。

vinberod は起動時に、これを実際に試して確かめます。

1. 使い捨ての network namespace を作り、その中に veth のペアを置きます。
2. 片側に generic XDP の program を付けます。この program は、受け取ったフレームを同じ veth を指す 2 つの devmap エントリーへ broadcast します。2 つのエントリーの egress program は、フレームにそれぞれ別の値を 1 バイト書きます。
3. 反対側から通常の AF_PACKET socket で 3 フレームを送り、戻ってきたコピーの値を比べます。1 フレームの 2 つのコピーの値が違えば、コピーは別々のバッファにあります。

所要時間は 40 ms ほどです。namespace とその中の veth は、確認の終わりに消えます。

コピーがバッファを共有していた場合、または確認そのものが失敗した場合（network namespace を作れないなど）、vinberod は xdp モードを設定した BD を tc モードで動かします。理由つきの警告（`xdp BUM replication unavailable on this kernel`）をログに出し、その BD の BUM フレームを `BUM_XDP_FALLBACK` に数えます。ローカルの flood と MAC 学習は、tc モードと同じく kernel の bridge が担います。

egress program も、念のため共有を検出します。コピーの `ctx->data` が plan に記録した ingress のアドレスと同じなら、共有バッファ上のコピーとみなします。共有バッファ上で encap するのは最初の 1 コピーだけで、2 つ目以降は破棄して `BUM_SHARED_BUFFER` を数えます。

## 要件と制約

- **generic XDP が必要**（`internal.bpf.device_mode: generic`）。native XDP は redirect したフレームを出力デバイスごとの bulk queue にため、devmap program を NAPI poll の終わりの flush でまとめて実行します。その時点では CPU の最新の seq が後続のフレームのものになっているため、コピーが自分の plan を見つけられません。設定の読み込み時に、generic 以外との組み合わせは拒否します。
- PREEMPT_RT のカーネルでは使えません（起動時に拒否します）。
- generic XDP の broadcast のコピーに、それぞれ別のバッファを渡すカーネルが必要です。そうでないカーネルでは tc モードで動きます（前節）。
- flood の対象は BD の HeadendL2 で登録した AC だけです。bridge の他のポートや bridge 自身には届きません。
- AC の VLAN tag は、ローカルへのコピーでも既知 unicast でもリモートへのコピーでも、そのまま運びます。BD のすべての AC が同じ VLAN ID なら、これは bridge と同じ結果です（bridge のメンバーがポートそのものでも、ポート上の VLAN デバイスでも）。VLAN ID の違う AC が混ざる BD では、フレームが他の AC でどう見えるべきかは bridge の構成で決まります（ポート上の VLAN デバイスをメンバーにすれば、bridge は tag を付け替えます）。同じポートの別の VLAN どうしも、bridge を通らなければ届きません。そこで、このような BD は tc モードで動かします（前述）。
- devmap は 1 BD あたり 32 エントリー（ローカル AC のデバイスとリモートのスロット 8 つの合計）、xdp モードの BD は 4096 個までです。収まらない BD は tc モードで動かします。
- `bum_plan_ring` は CPU ごとに 96 KiB（96 バイト × 1024）を使います。
- egress program は出力デバイスを変えられません。FIB の結果が devmap の uplink と違うコピーは破棄し、`BUM_UPLINK_MISMATCH` を数えます。control plane は uplink を宛先だけで引くので、peer への経路が ECMP で複数の uplink に分かれる構成では、一部の peer へのコピーが恒常的にこの理由で落ちます。このような構成では tc モードを使ってください。
- egress program は、next hop の neighbor エントリーが解決していないコピーを kernel に渡して解決させることができません（tc モードやメインの program は `XDP_PASS` で渡します）。そこで control plane は、devmap を組み立てるたびに、各スロットの uplink の next hop（経路の gateway、on-link なら peer 自身）を managed の neighbor エントリー（`NTF_EXT_MANAGED`、`ip neigh` の `managed extern_learn`）にします。kernel は、通信がなくてもこのエントリーを解決し、解決したまま保ちます。next hop が応答しない間も定期的に解決を試みます（`extern_learn` は、失敗中のエントリーを neighbor の GC に消させないために付けます）。静的なエントリー（permanent、noarp）はそのままにします。managed にしたエントリーは、vinberod が止まっても残ります。まだ解決していないコピーは破棄し、`BUM_EGRESS_NO_NEIGH` を数えます。
- uplink の MTU は「内側フレーム + 外側 IPv6 + SRH」以上にしてください（devmap の MTU 確認は encap 前の長さで行われます）。

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
| `BUM_XDP_FALLBACK` | xdp モードの BD で TC / bridge の経路を使った（devmap がない、xdp モードで扱えない構成の BD、またはこのカーネルで xdp モードを使えない） |
| `BUM_EGRESS_TX` | egress program がリモートへのコピーを encap した |
| `BUM_EGRESS_DROP` | egress program がコピーを破棄した（plan の後で peer が消えた、encap や FIB の失敗） |
| `BUM_UPLINK_MISMATCH` | FIB の出力先が devmap の uplink と違った |
| `BUM_PLAN_STALE` | コピーと plan の seq・送信元 AC・長さが一致しなかった（破棄） |
| `BUM_PLAN_SURPLUS` | uplink の plan に残りのスロットがないコピーだった（破棄） |
| `BUM_SHARED_BUFFER` | コピーが他のコピーとバッファを共有していた（2 つ目以降を破棄） |
| `BUM_EGRESS_NO_NEIGH` | uplink の next hop の neighbor エントリーが未解決で、コピーを破棄した |

split horizon で落としたコピーは、TC モードと同じ `SPLIT_HORIZON_TX` に数えます。
