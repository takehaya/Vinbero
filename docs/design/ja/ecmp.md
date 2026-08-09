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

path の選択は live bitmap でマスクした weight の累積に対する hash % total です。weight を変えれば UCMP になります。`ecmp_live_map` の lookup miss は prober がいないという意味で全 path live に fail open します。bitmap が全滅 (live な weight 合計が 0) の場合も全 path へ fail open します。BGP がまだその path 集合を保持している以上、劣化した可能性のある path に分散する方が drop より良い、という判断です。single-active な EVPN multihoming のように fail open が許されないケースのために、`ecmp_group_info.flags` の bit0 を fail-closed 用に予約してあります。

group の解決は `ecmp_resolve_headend` に集約しています。group が解決できないとき (group_id はあるが `ecmp_group_map` に無い、または path slot が無い) は親エントリ自身の segment list に fallback し、親が segment を持たない純粋な group 参照であれば NULL を返して呼び出し元が drop します。この契約を resolver 側に持たせているので、後続の呼び出し元 (EVPN aliasing など) が drop 判定を書き忘れることはありません。

## outer flow label entropy

同じ PE ペア間の encap トラフィックは outer の {src, dst} が全フローで同一になるため、underlay の途中ノードの ECMP が 1 本の経路に張り付きます。これを避けるため、dispatcher が計算した inner flow hash を RFC 6437 に従って outer IPv6 の flow label (20 bit) に書き込みます。Linux の IPv6 multipath hash は既定で flow label を含むので、途中ノードは設定なしで分散します。

flow hash は group の有無に関わらず headend を通る全パケットで計算し、H.Encaps 系と GTP 系の headend が `headend_ctx_flow_label` を通して flow label に反映します。GTP 系は TEID も混ぜます。GTP-U の port が固定の運用では outer 5-tuple が eNB と UPF のペアごとに 1 つの定数になり per-session の entropy が消えるためです。L2 headend (H.Encaps.L2) と TC の BUM 複製は hash を計算しないため label 0 のままです。hash が非ゼロなら label も必ず非ゼロになるよう折り畳むので、ラベル付きフローと未ラベルフローを途中ノードが混同することはありません。

service programming の復路も同じ理由で label を持ちます。End.AS と End.AD の復路は proxy circuit の outer が {src, dst} 固定なので、`ecmp_flow_hash_l3` で inner flow から hash を再導出して label に載せます。End.AM の復路はパケット自身の outer header をそのまま転送するため再導出しません。Ethernet circuit は inner が L2 フレームで hash を計算しないため label 0 のままです。詳細は [service programming](service_programming.md) を参照してください。

これはアップグレード時の wire 挙動の変更です。従来 outer flow label は常に 0 でしたが、この版から L3 と GTP の encap、および End.AS と End.AD の復路は非ゼロの label を持ちます。label のバイト一致を前提にした外部の検査やテストは更新が必要です。

## 更新の atomicity

double buffer は使わず、書き込み順序の規約で更新中の不整合を吸収します。

- path 1 本の差し替えは `ecmp_path_map` への 1 回の Put で、HASH マップの value 差し替えは RCU で atomic です (`SetEcmpPath`)。
- group の拡張は path を先に書いてから `ecmp_group_info` を更新します。新しい num_paths を見た reader が path を miss しないためです。
- group の縮小は `ecmp_group_info` を先に更新してから余った path slot を消します。
- 更新の隙間で path lookup が miss しても、dispatcher は親エントリへ fallback するので数パケットが fallback path を通るだけで済みます。
- liveness の反映は `ecmp_live_map` の 8 byte value 1 つの差し替えです。prober と control plane が同じ要素を書くことはありません。
- `PutEcmpGroup` で group を再定義すると liveness bitmap は削除され fail-open の既定に戻ります。bitmap の bit 位置は旧 path 集合を指しているので、残すと新しい path を prober の次の書き込みまで飢えさせます。prober は group 変更後に再登録します。
- group の削除は、その group を参照する headend エントリを先に消すか group 無しに書き換えてから行います。fallback segment を持たない純粋な group 参照は group が消えると設計どおり drop になり、この層は逆参照を追跡しません。

## 永続化と restart

`ecmp_group_map`、`ecmp_path_map`、`ecmp_group_owner_map` は pin 対象です。pin された headend map のエントリが group_id を参照し続けるため、group 定義も一緒に生き残る必要があります。`ecmp_live_map` は意図的に pin しません。restart 前の古い生死判定が path を blackhole しないよう、prober が再登録するまでは miss = fail open に倒します。

## pkg/bpf API

- `PutEcmpGroup(groupID, paths []EcmpPath, owner)` は group 全体の install と更新を行います。`EcmpPath` は path の encap 定義と weight を 1 つの構造体で束ねるので、並行する slice の index ずれが起きません。group_id 0 は拒否し、weight 0 の path も拒否します (0 は未使用 slot の印)。
- `SetEcmpPath(groupID, pathIndex, entry, owner)` は既存 group の path 1 本を atomic に差し替えます。num_paths の範囲外は拒否します。
- `SetEcmpLive(groupID, bitmap)` / `GetEcmpLive` / `DeleteEcmpLive` は prober の fast reroute 用で、owner 管理の対象外です。
- `DeleteEcmpGroup` は owner を検証して group info、path、liveness、owner を順に消します。`ForceDeleteEcmpGroup` は owner を無視します。
- `GetEcmpGroup` / `ListEcmpGroups` は introspection 用です。

owner tag は他の headend map と同じ仕組みで、group_id 単位に記録します。

## 容量設定

config の `settings.entries.ecmp_group.capacity` が `ecmp_group_map`、`ecmp_group_owner_map`、`ecmp_live_map` の容量になり、`ecmp_path_map` はその 8 倍 (path slot ぶん) になります。既定はそれぞれ 1024 と 8192 です。

## plugin との共有

plugin の shared map partition では `ecmp_group_map`、`ecmp_path_map`、`ecmp_live_map` の 3 つとも read-only に分類しています。liveness は userspace の prober だけが書く control plane 所有の状態で、plugin に書かせると prober が指示していない reroute を強制できてしまいます。将来 BPF 側 (たとえば TX エラー起点) で liveness bit を落とす実装が入る時点で `ecmp_live_map` を read-write へ再分類します。

`headend_entry` と `tailcall_ctx` のサイズが変わるため、この変更は plugin ABI break です。plugin SDK は v4 に bump し、旧 SDK でコンパイル済みの plugin ELF は `PluginRegister` の MapReplacements 互換チェックで弾かれるので、v4 ヘッダで再コンパイルしてください。

## BGP path identity

data plane が複数 path を持てても、受信側が path を区別できなければ group を組めません。gobgp は同一 NLRI に対する複数 PE の path をそれぞれ配送していますが、Vinbero の変換は送信元を捨てていたため、2 本目の PE の広告が 1 本目の更新と区別できませんでした。

そこで `RouteEvent` に `PathSource{Peer, PathID}` を載せます。`Peer` は学習元の neighbor で、自ノード発の path では zero 値になります。`PathID` は RFC 7911 の ADD-PATH 識別子で、ADD-PATH を negotiate していなければ 0 です。peer 内でのみ一意なので、path の識別は必ず 2 つ組で行い `PathID` 単体では行いません。

変換は `pathToRouteEvent` の 1 箇所に集約されていて、live の subscription と loc-rib snapshot の両方がここを通ります。したがって path identity は watch と `ListRoutes` と replay のすべてに同時に反映されます。

peer 設定の `add_paths_receive` で ADD-PATH の receive を negotiate します。route reflector 配下では必要です。reflector は既定で prefix ごとに best path だけを reflect するので、これを有効にしないと他の PE の path はそもそも届かず、受信側で何をしても復元できません。iBGP full mesh では各 PE が自分の path を直接送るため不要です。送信方向は有効にしません。Vinbero は自分の NLRI について複数 path を広告しないので、使わない capability を negotiate しないためです。

## L3VPN の path 集約

受信した VPN 経路は `{family, prefix}` 単位で 1 つの ECMP group に集約します。RD は key に含めません。同じ prefix を広告する PE はそれぞれ自分の RD を使うので、RD を key に入れると 2 台目の PE の経路が別エントリになり、1 台目を上書きしてしまうためです。

集約前は prefix をそのまま headend map に書き、owner を RD 込みにしていました。このため 2 台目の PE の書き込みは cross-owner チェックに掛かって失敗し、経路は単に捨てられていました。さらに 1 台目が withdraw すると、生き残っている PE の経路は再広告されるまで復活せず、その prefix は blackhole していました。集約と RD 非依存の owner でこの両方が解消します。

path の識別は `{rd, PathSource}` です。RD が PE を、`PathSource` が peer 内の path を区別するので、2 台の PE からの広告も、ADD-PATH で 1 peer から届く複数 path も、別々の path として保持できます。

program する member は SID で dedupe して SID 順に並べ、8 本で打ち切ります。並び順を固定するのは見た目のためではありません。data plane は member 数の剰余で path を選ぶので、Go の map 反復順に依存すると同じ path 集合でも reconcile のたびに flow の分散先が変わってしまいます。同じ SID に解決する path は転送結果が同じなので dedupe します。両方 program すると、その PE の取り分だけが黙って倍になります。

trigger エントリには group_id に加えて先頭 member の segments も入れます。data plane は group を解決できないとき trigger 自身の segments に fallback するので、reconcile の途中や再起動直後の窓で drop でなく単一 path 転送に degrade します。

group id は再起動を跨げません。owner tag は 64 バイトに収まる必要があり、prefix を入れると IPv6 で溢れるため、どの group がどの prefix のものだったかを記録できないからです。そこで起動時に自分が owner の group を sweep して世代ごとの orphan が積み上がるのを防ぎ、他の owner が持つ group と衝突しないよう、残っている id の上から採番を再開します。

## kernel FIB の multipath

BGP で学習した IPv6 unicast 経路は `pkg/fib` から kernel FIB に注入します。`Route` は next hop を複数持てるようになり、2 本以上あるとき netlink の `MultiPath` として渡します。

next hop が 1 本のときは multipath でなく通常の gateway 経路として書きます。kernel は要素 1 つの multipath を通常経路に正規化して返すので、multipath で書くと同じ経路が round trip 後に自分自身と一致しなくなるためです。

weight は 1 始まりの自然な値で扱い、netlink の境界で変換します。wire 上の `rtnh_hops` は weight より 1 小さいので、そのまま渡すと全 next hop の取り分が 1 つずつ増えてしまいます。境界で吸収しているので、上位のコードはこの差を意識しません。weight 0 は 1 と読みます。取り分ゼロの next hop を意図する呼び出し元は無いためです。

## 観測 API

`HeadendGroupService` で group を読めます。`vbctl headend-group list` が group 一覧、`vbctl headend-group get <group-id>` が member の segment list と weight と policy と生死を返します。書き込み API はありません。group は BGP 受信経路が経路の到着に応じて書くので、operator が作るものではないためです。

prefix は group 側に記録されていないため、headend map を走査して `group_id` が一致する trigger エントリから引きます。applier の in-memory 状態に依存しないので、group を誰が書いたかに関わらず同じ答えになり、再起動で applier の状態が消えても引けます。逆に trigger がまだ書かれていない group では prefix が空になり得ます。

liveness は「prober の報告がまだ無い」状態と「実際に全 path が生きている」状態を区別して出します。data plane はどちらも全 path を使うので挙動は同じですが、なぜトラフィックが動いたのかを調べるときに意味が違うためです。

## SR Policy の weighted segment list

candidate path は Segment List を複数持てて、まとめて weighted ECMP の集合になります (RFC 9256 2.2)。受信側はこれを全部 decode し、各 list の weight とともに `CandidatePath.SegmentLists` に載せます。従来は最初の 1 本だけ残して捨てていました。

Weight sub-TLV が無い場合は等分として扱います。RFC 9256 が既定値を 1 と定めているためです。

Weight sub-TLV があって値が 0 の場合は、その list を落とします。省略と明示的な 0 は別物で、同一視すると広告側の意図を上書きします。RFC 9256 は weight が 0 の segment list を invalid と規定しており、明示的な 0 は送信側がその list を ECMP 集合から外す意思表示です。既定値として読むと、送信側が無効化した list を復活させることになり、それが先頭なら実際に program される list になってしまいます。

壊れた list は、その list だけを落とします。list が 1 本しか無い前提なら、壊れていたら candidate ごと ineligible にするのが正しい判断でした。より低い preference の代替に steer するより、読めなかった list から組んだ経路に流す方が危険だからです。複数ある場合、他の list は同じ endpoint への独立した記述なので、1 本の破損で全部落とすとまだ使える policy を落とすことになります。全 list が使えない candidate は従来どおり ineligible になります。

segment を 1 つも指さない list も使えないものとして落とします。空のまま有効として扱うと、どこにも encap しない policy を install することになるためです。

program されるのは今のところ先頭の list だけです。data plane 側の weighted 選択は後続の変更です。

## EVPN RT1 の decode

RT1 Ethernet A-D を decode します。従来は decode 自体が無く、applier の default 分岐で捨てられていました。

1 つの NLRI 型が 2 つの異なる主張を運び、Ethernet Tag で区別します。per-ES (tag = MAX-ET) は segment 全体についての主張で、その withdraw が mass withdraw の signal になります。MAC を 1 つずつ withdraw するのを待たずに、障害リンクから収束できます (RFC 7432 8.2)。per-EVI (それ以外の tag) は 1 つの broadcast domain についての主張で、その SRv6 SID が aliasing を可能にします。他の PE からしか学習していない MAC 宛のトラフィックの送り先になるためです。

Single-Active bit は per-ES 経路の ESI Label extended community から読みます。これが立っていると aliasing は禁止です。single-active では DF だけが転送するので、ES を広告している PE 群に分散させると non-DF に届いた分が black-hole します。

transposition の取り出し元も 2 形式で違います。per-EVI は RT2/RT3 と同じく NLRI の MPLS label から取りますが、per-ES はその label を 0 にして、ESI Label extended community の 24-bit label に Argument を載せます (RFC 9252)。per-ES で NLRI label を読むと transposed bits が落ち、まったく別の場所を指す SID を組み立てます。gobgp は両者とも 3 バイトの raw 値として decode するので単位は揃っています。

現時点では decode までで、applier はまだ RT1 を消費しません。aliasing と mass withdraw は data plane 側の変更を伴うため後続にしています。

## 制約と今後

- `mup_uplink_v4/v6_map` の値も `headend_entry` ですが、behavior プログラム内で lookup されるため group 解決を通りません。`CreateMupUplinkV4/V6` が書き込み時に `group_id` を 0 に強制します。
- L2 headend (FDB → bd_peer) の aliasing は EVPN RT1 の対応と同時に入れます。ESI から group_id を引く side table を足し、この group 機構をそのまま使う予定です。
- SR Policy の weighted segment list は受信側の decode が済んでいます (上記)。data plane 側は `sr_policy_value` に group_id を足し、`tailcall_ctx.flow_hash` で選択する形で拡張します。tailcall_ctx に flow_hash を先に載せてあるのはこのためです。
- hash の seed は固定です。path 選択はノード内で per-flow に安定していればよく、固定 seed は BPF_PROG_TEST_RUN のテストを再現可能にします。
