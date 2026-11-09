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
2. devmap のメンバーはローカル AC（key は ifindex）と、リモートの flood スロット（key は `0x80000000 | index`）です。スロットのエントリーの値は、その peer へ向かう uplink の ifindex と egress program です。egress program は全エントリー共通の 1 本（`bum_remote_egress`）です。同じ uplink の先に peer が k 個あれば、その uplink のエントリーも k 個になり、broadcast はその uplink 向けに k 個のコピーを作ります。ローカル AC のエントリーは program を持ちません。ただし、AC のデバイスがその BD のスロットの uplink でもある場合（AC と uplink が同じポート）は、そのエントリーにも同じ egress program を付けます（後述）。native XDP では、すべてのエントリーに付けます（「native XDP」の節）。
3. ingress program は broadcast の直前に、そのフレームの複製計画（以下 plan）を CPU ごとのリングに書きます（次節）。
4. `bpf_redirect_map(BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)` で broadcast します。入力ポートが、送るスロットの uplink でもある場合だけは `BPF_F_EXCLUDE_INGRESS` を付けません（付けると、そのポートへのリモートのコピーも除かれるため）。plan を書くときに引いた devmap をそのまま使うので、control plane が devmap を差し替えている最中でも、plan と broadcast が別々の版を見ることはありません。
5. egress program はコピーごとに、plan から自分の uplink の項目を探して次のスロットを 1 つ取り、`bd_peer_map[{bd_id, スロット}]` の peer へ H.Encaps.L2（.Red）をかけて、FIB の結果で MAC を書き換えます。

ローカルの既知 unicast は bridge を通さず、FDB の出力ポートへ `bpf_redirect` します（入力ポートと同じなら破棄）。devmap のない BD では、これまでどおり bridge に渡します。

受信側（End.DT2 / End.DT2M の decap 後）: FDB miss のとき、bridge への redirect の代わりに `bum_local_map[bd_id]`（ローカル AC のみ。generic XDP では egress program なし）へ broadcast します。DF と RX split horizon の判定はその前に行われ、変わりません。

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

- `seq`（照合用）、送信元 AC の ifindex、`bd_id`、フレーム長
- uplink ごと（最大 8 個）の項目: uplink の ifindex、送るスロットの集合（ビット i がスロット i、小さい順に割り当てる）、個数 `n`、割り当て済みの数 `next_idx`、そのデバイスがこの BD のローカル AC でもあるか（`local`。送信元 AC 自身なら 0）。項目は、devmap にスロットのエントリーがある uplink すべてに作ります（送るスロットが 0 個でも）
- ingress 時点の `ctx->data`（共有バッファの検出用、後述）

送るスロットは ingress で決めます。対象は、devmap にエントリーがあり（uplink にはそのエントリーの ifindex を使う）、`bd_peer_map` に peer があり、`flood_exclude` でなく、送信元 AC と同じ Ethernet Segment にない（RFC 9252 の split horizon）スロットです。判定の規則は TC モードの `tc_dispatch_bum_clones` と同じで、split horizon で除いたスロットは `SPLIT_HORIZON_TX` に数えます。encap のヘッダーは plan に入れず、egress program が `bd_peer_map` から引きます。ヘッダーまで入れると、CPU 数 × 1024 × 8 スロット分の容量が要るためです。

egress program の手順は次のとおりです。

1. 担当する `seq` と送信元 AC を決めます。generic XDP では、この CPU の最新の seq（`bum_seq` の値 − 1）と `ctx->ingress_ifindex` です。native XDP では、コピーが運ぶ metadata から読みます（後述）。
2. `bum_plan_ring[seq & 1023]` を引き、plan の `seq`、送信元 AC、フレーム長がコピーと一致するか確かめます。一致しなければ破棄し、`BUM_PLAN_STALE` を数えます。
3. `ctx->egress_ifindex` で uplink の項目を探し、`idx = next_idx++` とします。項目がなければ、スロットのエントリーがないデバイス、つまりローカル AC へのコピーなので、そのまま `XDP_PASS` で送ります（ローカル AC のエントリーにも program を付ける native XDP で起きます）。
4. `idx < n` なら、集合の `idx` 番目のスロットの peer へ encap し、FIB の出力先がエントリーの uplink と一致することを確かめてから、`XDP_PASS` で送ります。
5. `idx == n` で `local` が 1 なら、そのデバイスのローカル AC へのコピーとして、そのまま `XDP_PASS` で送ります。コピーはどれも同じなので、どのコピーをローカル用にしても結果は変わりません。
6. それ以外は破棄し、`BUM_PLAN_SURPLUS` を数えます。devmap のエントリーは uplink の先の peer の数だけあるので、split horizon や `flood_exclude` で ingress が除いた分だけコピーが余ります。入力ポートを除かずに broadcast したときの、送信元 AC 自身へのコピーもここで破棄されます。

### 「最新の seq」で足りる理由

generic XDP の broadcast は、ingress program が返った直後に、同じ CPU の同じ呼び出しの中で、各コピーの devmap program を順に実行します（`do_xdp_generic` → `xdp_do_generic_redirect` → `dev_map_redirect_multi` → `dev_map_generic_redirect`）。この区間は BH が無効です（NAPI や backlog の softirq、threaded NAPI、tun などの `local_bh_disable`）。同じ CPU で別のフレームの ingress program が割り込むことはないので、コピーの egress program から見たこの CPU の最新の seq は、必ずそのコピーのフレームの seq です。generic XDP は devmap program に metadata を渡さないので、seq をフレームと一緒には運べません。

PREEMPT_RT のカーネルは例外です。`CONFIG_PREEMPT_RT_NEEDS_BH_LOCK` がなければ、BH 無効の区間どうしが同じ CPU で入れ替わることがあり、この前提が成り立ちません。`/sys/kernel/realtime` が 1 のカーネルでは、generic でも native でも、xdp モードでの起動を拒否します（`bum_seq` の更新も、BH 無効の区間が入れ替わらないことを前提にしています）。

フレームの識別に `ctx->data` のアドレスは使えません。「コピーがバッファを共有するカーネル」の節の修正が入ったカーネルでは、egress program を持つコピーはそれぞれ別のバッファに複製され、アドレスが ingress のものと一致しないためです。plan との照合には、seq に加えて送信元 AC とフレーム長を使います。

### native XDP（`device_mode: driver`）

native XDP は redirect したフレームを CPU と出力デバイスごとの bulk queue にため、devmap program を NAPI poll の終わりの flush でまとめて実行します（`bq_enqueue` → `bq_xmit_all`）。その時点では、この CPU の最新の seq は後続のフレームのものになっていることがあります。そこで ingress program は、broadcast の直前にフレームの前へ 16 バイトの metadata（`struct bum_xdp_meta`: マーカー、送信元 AC、seq）を書きます。broadcast のコピー（`xdpf_clone`）はフレームを headroom ごと複製するので、どのコピーも同じ metadata を運びます。egress program はそこから seq と送信元 AC を読み、metadata を取り除いてから encap します。flush は同じ CPU、同じ poll の中で行われ、1 poll のフレーム数（NAPI の budget）はリングの 1024 エントリーより十分少ないので、plan は上書きされる前に使われます。万一上書きされていれば、seq の照合で `BUM_PLAN_STALE` になります。

コピーが自分の uplink の項目のどのスロットを取るかは、plan の `next_idx` で決まります。plan は CPU ごと、項目は uplink ごとなので、これは CPU × 出力デバイスごとの状態です。同じ uplink のコピーは同じ bulk queue に入り、同じ CPU で順に処理されます。

native XDP の bulk queue には、もう 1 つ性質があります。queue は flush のあと最初に入ったフレームの devmap program を記録し、poll の終わりまで、その queue のフレーム全部にその program を実行します（`bq_enqueue`）。program のないフレームが先に入ると、その poll のそのデバイスへの BUM のコピーは egress program を通らず、リモートへのコピーは encap されないまま出てしまいます。逆に program のある queue に入ったローカルへのコピーは、リモートへのコピーと区別できなければいけません。これを防ぐため、xdp モードを native XDP で動かすときは、BD の devmap が送るデバイスの queue で、常に egress program が動くようにします。

- 2 つの BD devmap（`bum_flood_map`、`bum_local_map`）のすべてのエントリーに、ローカル AC のものも含めて egress program を付けます。program は metadata のないフレーム（decap 後の flood のコピー）をそのまま送ります。metadata のあるコピーは plan で振り分けます。スロットのエントリーがないデバイスへのコピーはそのデバイスのローカル AC へのもので、metadata を取り除いてそのまま送ります。
- BD の devmap が送るデバイス（ローカル AC とスロットの uplink）への redirect は、すべて `bum_tx_map`（ifindex → {デバイス、`bum_remote_egress`}）を通ります。メインの program の redirect は全部 `xdp_redirect_dev` を使い、`bum_tx_map` にある出力デバイスにはこの map で、それ以外には `bpf_redirect` で送ります。egress program は metadata のないフレーム（unicast）をそのまま送ります。control plane は、BD の devmap を入れる前に、その devmap が送るデバイスを `bum_tx_map` に加えます。加えたデバイスは取り除きません（どの BD も使わなくなったデバイスへのフレームが、egress program を 1 回通るだけです）。
- ingress program は、届いたフレームの metadata を最初に消します。他のホストの native XDP から redirect されたフレームは、その program の metadata を持ったまま届くことがあるためです。
- この決まりがあるので、あるデバイスが AC と uplink を兼ねていても（同じ BD でも、別々の BD でも）、そのデバイスの queue に入るフレームはすべて egress program を通ります。BD の組み立ての順番によらず、program のないコピーが混ざることはありません。
- 新しいデバイスを `bum_tx_map` に加えたときは、BD の devmap を入れる前に 10 ms 待ちます。加える直前に、そのデバイスへ program なしで redirect した NAPI poll が終わるのを待つためです。全 BD を組み立て直すときは、全 BD のデバイスを先に加えて 1 回だけ待ちます。XDP の program を付ける前（起動時の組み立て）は待ちません。
- `bum_tx_map`（256 エントリー）にデバイスを加えられない BD には devmap を作らず、tc モードで動かします（警告と `BUM_XDP_FALLBACK`）。

native XDP では、コピーはそれぞれ別のバッファにあるので、次節の問題は起きません。起動時の確認も行いません。

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

- generic XDP か native XDP（`internal.bpf.device_mode: generic` か `driver`）で動きます。offload は使えません。
- PREEMPT_RT のカーネルでは使えません（起動時に拒否します）。
- generic XDP では、broadcast のコピーにそれぞれ別のバッファを渡すカーネルが必要です。そうでないカーネルでは tc モードで動きます（前節）。
- native XDP では、AC のドライバーが XDP の metadata を扱えること（tc モードの VNBU マーカーと同じ条件。扱えないドライバーでは、BUM フレームは tc モードの経路へ回り、`BUM_XDP_META_FAIL` を数えます。tc モードと同じく、リモートへのコピーは作られず、bridge のローカルの flood だけになります）と、redirect 先のデバイスがすべて XDP の redirect を受けられること（ドライバーが `ndo_xdp_xmit` を持つこと。veth は相手側に XDP program があるか GRO が有効なこと）が必要です。BD の devmap が送るデバイス（AC と uplink）への unicast の redirect もすべて egress program を 1 回通るので、そのぶん少し遅くなります。
- native XDP では、同じホストの vinbero 以外の XDP program から、BD の devmap が送るデバイスへ `bpf_redirect` しないでください。`bum_tx_map` を通らない redirect は、上の決まりを破ります。vinbero の plugin は `bpf_redirect` を呼べない（読み込み時の検査で拒否されます）ので、この心配はありません。
- flood の対象は BD の HeadendL2 で登録した AC だけです。bridge の他のポートや bridge 自身には届きません。
- AC の VLAN tag は、ローカルへのコピーでも既知 unicast でもリモートへのコピーでも、そのまま運びます。BD のすべての AC が同じ VLAN ID なら、これは bridge と同じ結果です（bridge のメンバーがポートそのものでも、ポート上の VLAN デバイスでも）。VLAN ID の違う AC が混ざる BD では、フレームが他の AC でどう見えるべきかは bridge の構成で決まります（ポート上の VLAN デバイスをメンバーにすれば、bridge は tag を付け替えます）。同じポートの別の VLAN どうしも、bridge を通らなければ届きません。そこで、このような BD は tc モードで動かします（前述）。
- devmap は 1 BD あたり 32 エントリー（ローカル AC のデバイスとリモートのスロット 8 つの合計）、xdp モードの BD は 4096 個までです。収まらない BD は tc モードで動かします。
- `bum_plan_ring` は CPU ごとに 96 KiB（96 バイト × 1024）を使います。
- egress program は出力デバイスを変えられません。FIB の結果が devmap の uplink と違うコピーは破棄し、`BUM_UPLINK_MISMATCH` を数えます。control plane が uplink をどう決め、変化にどう追従するかは「ECMP の underlay」の節を参照してください。
- egress program は、next hop の neighbor エントリーが解決していないコピーを kernel に渡して解決させることができません（tc モードやメインの program は `XDP_PASS` で渡します）。そこで control plane は、devmap を組み立てるたびに、各スロットの uplink の next hop（経路の gateway、on-link なら peer 自身）を managed の neighbor エントリー（`NTF_EXT_MANAGED`、`ip neigh` の `managed extern_learn`）にします。kernel は、通信がなくてもこのエントリーを解決し、解決したまま保ちます。next hop が応答しない間も定期的に解決を試みます（`extern_learn` は、失敗中のエントリーを neighbor の GC に消させないために付けます）。静的なエントリー（permanent、noarp）はそのままにします。managed にしたエントリーは、vinberod が止まっても残ります。まだ解決していないコピーは破棄し、`BUM_EGRESS_NO_NEIGH` を数えます。
- uplink の MTU は「内側フレーム + 外側 IPv6 + SRH」以上にしてください（devmap の MTU 確認は encap 前の長さで行われます）。

## ECMP の underlay

peer への経路が複数の uplink に分かれていても（ECMP）、xdp モードは各 peer に 1 本の経路で 1 コピーずつ送ります。tc モードと同じく、BUM の flow label は 0 で、peer ごとの経路はフレームごとには変わりません。uplink ごとの分散は「peer ごと」です。

kernel の multipath は、送信元、宛先、flowinfo、L4 ポートのハッシュで next hop を選びます。egress program の `bpf_fib_lookup` は、送信元に peer の encap 送信元、宛先に最初のセグメント、それ以外は 0 を渡すので、control plane が同じ peer の uplink を引くときも、同じ引数で同じ helper を呼ばなければ同じ答えになりません。`ip route get` の宛先だけの答えは、このハッシュの入力が違うため一致しません。そこで uplink は、次のようにして決めます。

- `bum_uplink_probe` という map を持たない XDP program を `BPF_PROG_TEST_RUN` で実行します。この program は egress program と同じ関数（`srv6_fib_lookup_v6_params`）で `bpf_fib_lookup` を呼びます。入力は `fib_params.ifindex` に BD の AC、`ipv6_src` に encap 送信元、`ipv6_dst` に最初のセグメントです。
- 出力の `fib_params.ifindex` が uplink、`ipv6_dst` が next hop です（経路に gateway がなければ宛先のままです）。`BPF_FIB_LKUP_RET_NO_NEIGH` でもこの 2 つは分かるので、そのまま使います。managed の neighbor エントリーは、この next hop に対して作ります。同じ ECMP の別の next hop を選んだ peer が増えれば、その peer の分のエントリーが増えます。
- 同じ BD に AC が複数あれば、AC ごとに引きます。ハッシュは入力デバイスを使いませんが、table の選択（AC への iif の ip rule や VRF）は AC に依存します。AC によって答えが割れる BD（一部の AC だけ経路がない場合を含みます）は 1 つの devmap では表せないので、ログに 1 回だけ警告を出し、最初の AC の答えを使います。ほかの AC から入ったコピーのうち経路の違うものは破棄されます（`BUM_UPLINK_MISMATCH` か `BUM_EGRESS_DROP`）。AC のデバイスが消えているときは、その AC は無視します。AC ごとに同じ uplink の別の next hop を選ぶ場合は、それぞれの next hop の neighbor エントリーを管理します。

経路が変わったときは、次の契機で全 BD の devmap を組み立て直します（200 ms の debounce を挟みます）。

- route の通知と、nexthop object（`RTNLGRP_NEXTHOP`）、IPv6 の ip rule（`RTNLGRP_IPV6_RULE`）の通知。group の member の削除や `nexthop_compat_mode=0` のように、route の通知が出ない変更があるためです。
- egress program が `BUM_UPLINK_MISMATCH` か `BUM_EGRESS_NO_NEIGH` を数えたとき（どちらも 1 秒ごとに確認します）。通知なしで peer の next hop が変わる場合があるためです。`fib_multipath_hash_policy` 3 の hash field やハッシュの seed の変更、hash-threshold の nexthop group で gateway の neighbor が FAILED や INCOMPLETE になったとき（その next hop は選ばれなくなり、戻ると元に戻ります）、carrier の変化、device を落としたときの nexthop の削除などです。組み立て直しで uplink と next hop を引き直し、neighbor エントリーも作り直します。neighbor が flush された場合（carrier の変化など）もここで回復します。これらの数え上げは `enable_stats` に関係なく働きます（`bum_uplink_resync`）。

組み立て直しても devmap の中身が変わらない BD は、map を差し替えず、neighbor エントリーの維持だけを行います。原因の解消しない破棄（応答しない gateway など）が続いても、毎秒の組み立て直しの負荷はこの程度に収まります。

組み立て直しの前に落ちたコピーは戻りません。経路が変わった直後は、少数のフレームがこれらのカウンタに数えられて落ちることがあります。

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
    device_mode: driver       # native XDP（generic でも動く）
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
| `BUM_UPLINK_MISMATCH` | FIB の出力先が devmap の uplink と違った（破棄して組み立て直す） |
| `BUM_PLAN_STALE` | コピーと plan の seq・送信元 AC・長さが一致しなかった（破棄） |
| `BUM_PLAN_SURPLUS` | uplink の plan に残りのスロットがないコピーだった（破棄） |
| `BUM_SHARED_BUFFER` | コピーが他のコピーとバッファを共有していた（2 つ目以降を破棄） |
| `BUM_EGRESS_NO_NEIGH` | uplink の next hop の neighbor エントリーが未解決で、コピーを破棄した（組み立て直して解決する） |
| `BUM_XDP_META_FAIL` | native XDP で、AC のドライバーが metadata を書かせず、BUM フレームを tc モードの経路へ回した（`BUM_XDP_FALLBACK` にも数える） |

split horizon で落としたコピーは、TC モードと同じ `SPLIT_HORIZON_TX` に数えます。
