# ECMP path group と fast reroute

## 概要

このドキュメントは、headend の転送先を複数 path に分散する ECMP path group のデータプレーン設計を説明します。同一 VPN prefix を複数の PE が広告したとき、従来の headend map は 1 prefix に 1 つの segment list しか持てず、後から適用された経路が前の経路を上書きしていました。ECMP path group はこれを最大 8 path の weighted な集合に拡張し、あわせて userspace の prober が path 単位の生死を 1 word の書き込みで反映できる仕組みを用意します。

この文書が対象にするのはデータプレーン (eBPF マップと XDP の選択ロジック、`pkg/bpf` の API) です。BGP からの path 集約、EVPN aliasing、prober 本体は後続の変更で入ります。

## マップ構成

group の定義は 3 つのマップに分かれます。書き手ごとにマップを分けることで、それぞれの更新が atomic な value 差し替えになります。

| マップ | キー | 値 | writer |
|------|------|------|------|
| ecmp_group_map | group_id (u32) | num_paths + weight[8] | control plane |
| ecmp_path_map | {group_id, path_index} | headend_entry (path 1 本の完全な encap 定義) | control plane |
| ecmp_live_map | group_id (u32) | u64 liveness bitmap (bit i = path i up) | prober |
| ecmp_group_owner_map | group_id (u32) | owner tag | control plane (userspace のみ) |

`headend_entry` には `group_id` フィールドが増えています。0 が sentinel で、従来どおりの単一 path エントリとして動きます。非ゼロなら dispatcher が group を解決し、選ばれた path の `headend_entry` を通常の tail call へ流します。path 側のエントリは書き込み時に `group_id` を 0 に強制するので、group が group を参照することはありません。

path が `headend_entry` そのものを値に持つため、path ごとに異なる mode、src_addr、policy_id を持てます。color 付き経路の SR Policy 合成 (`resolve_sr_policy`) も path 単位でそのまま機能します。

## 選択ロジック

dispatcher (`process_headend_v4/v6`) は headend map に hit したパケットの inner flow を jhash で hash します。入力は 5-tuple で、fragment や未知の protocol、extension header 付きの IPv6 は {src, dst, proto} の 3-tuple に落とします。TCP、UDP、UDP-Lite、SCTP、DCCP は先頭 4 byte が {sport, dport} なので同じ読み方で済みます。

path の選択は live bitmap でマスクした weight の累積に対する hash % total です。weight を変えれば UCMP になります。`ecmp_live_map` の lookup miss は「prober がいない」という意味で全 path live に fail open します。bitmap が全滅 (live な weight 合計が 0) の場合も全 path へ fail open します。BGP がまだその path 集合を保持している以上、劣化した可能性のある path に分散する方が drop より良い、という判断です。

group が解決できないとき (group_id はあるが `ecmp_group_map` に無い、または path slot が無い) は親エントリ自身の segment list に fallback します。親が segment を持たない純粋な group 参照であれば drop します。

## outer flow label entropy

同じ PE ペア間の encap トラフィックは outer の {src, dst} が全フローで同一になるため、underlay の途中ノードの ECMP が 1 本の経路に張り付きます。これを避けるため、dispatcher が計算した inner flow hash を RFC 6437 に従って outer IPv6 の flow label (20 bit) に書き込みます。Linux の IPv6 multipath hash は既定で flow label を含むので、途中ノードは設定なしで分散します。

flow hash は group の有無に関わらず headend を通る全パケットで計算し、H.Encaps 系と GTP 系の headend が flow label に反映します。L2 headend (H.Encaps.L2) と TC の BUM 複製は hash を計算しないため label 0 のままです。hash が非ゼロなら label も必ず非ゼロになるよう折り畳むので、ラベル付きフローと未ラベルフローを途中ノードが混同することはありません。

## 更新の atomicity

double buffer は使わず、書き込み順序の規約で更新中の不整合を吸収します。

- path 1 本の差し替えは `ecmp_path_map` への 1 回の Put で、HASH マップの value 差し替えは RCU で atomic です (`SetEcmpPath`)。
- group の拡張は path を先に書いてから `ecmp_group_info` を更新します。新しい num_paths を見た reader が path を miss しないためです。
- group の縮小は `ecmp_group_info` を先に更新してから余った path slot を消します。
- 更新の隙間で path lookup が miss しても、dispatcher は親エントリへ fallback するので数パケットが fallback path を通るだけで済みます。
- liveness の反映は `ecmp_live_map` の 8 byte value 1 つの差し替えです。prober と control plane が同じ要素を書くことはありません。

## 永続化と restart

`ecmp_group_map`、`ecmp_path_map`、`ecmp_group_owner_map` は pin 対象です。pin された headend map のエントリが group_id を参照し続けるため、group 定義も一緒に生き残る必要があります。`ecmp_live_map` は意図的に pin しません。restart 前の古い生死判定が path を blackhole しないよう、prober が再登録するまでは miss = fail open に倒します。

## pkg/bpf API

- `PutEcmpGroup(groupID, paths, weights, owner)` は group 全体の install と更新を行います。group_id 0 は拒否し、weight 0 の path も拒否します (0 は未使用 slot の印)。
- `SetEcmpPath(groupID, pathIndex, entry, owner)` は既存 group の path 1 本を atomic に差し替えます。num_paths の範囲外は拒否します。
- `SetEcmpLive(groupID, bitmap)` / `GetEcmpLive` / `DeleteEcmpLive` は prober の fast reroute 用で、owner 管理の対象外です。
- `DeleteEcmpGroup` は owner を検証して group info、path、liveness、owner を順に消します。`ForceDeleteEcmpGroup` は owner を無視します。
- `GetEcmpGroup` / `ListEcmpGroups` は introspection 用です。

owner tag は他の headend map と同じ仕組みで、group_id 単位に記録します。

## 容量設定

config の `settings.entries.ecmp_group.capacity` が `ecmp_group_map`、`ecmp_group_owner_map`、`ecmp_live_map` の容量になり、`ecmp_path_map` はその 8 倍 (path slot ぶん) になります。既定はそれぞれ 1024 と 8192 です。

## plugin との共有

plugin の shared map partition では `ecmp_group_map` と `ecmp_path_map` を read-only、`ecmp_live_map` を read-write に分類しています。将来 BPF 側 (たとえば TX エラー起点) で liveness bit を落とす実装が入っても、この分類のまま `__sync` 系の atomic 操作で書けます。

## 制約と今後

- `mup_uplink_v4/v6_map` の値も `headend_entry` ですが、behavior プログラム内で lookup されるため group 解決を通りません。この経路の `group_id` は 0 のままにします。
- L2 headend (FDB → bd_peer) の aliasing は EVPN RT1 の対応と同時に入れます。ESI から group_id を引く side table を足し、この group 機構をそのまま使う予定です。
- SR Policy の weighted segment list (RFC 9256 の複数 Segment List sub-TLV) は `sr_policy_value` に group_id を足し、`tailcall_ctx.flow_hash` で選択する形で拡張できます。tailcall_ctx に flow_hash を先に載せてあるのはこのためです。
- hash の seed は固定です。path 選択はノード内で per-flow に安定していればよく、固定 seed は BPF_PROG_TEST_RUN のテストを再現可能にします。
