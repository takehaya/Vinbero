# SRv6 Service Programming

## 概要

このドキュメントは SR-unaware / SR-aware なサービスを SRv6 chain に組み込む service programming の設計を説明します。仕様は draft-ietf-spring-srv6-service-programming で、Vinbero は 4 つの behavior を実装します。

| behavior | 種別 | 往路の処理 | 復路の処理 |
|---|---|---|---|
| End.AS | 静的 proxy | SR encap を剥がして service へ | 静的設定の CACHE で再 encap |
| End.AD | 動的 proxy | SR encap を剥がして service へ、outer を cache | cache した outer を前置 |
| End.AM | masquerading proxy | DA を最終 segment に偽装、SRH は残す | in-packet の SRH から DA を復元 |
| End.AN | SR-aware native | End と同一 (service が SRH を理解する) | なし |

SR-unaware なサービスは SRv6 を理解しないため、proxy behavior は 1 つの SID を 2 方向に分解します。往路は SID 宛の SRv6 パケットを受けてサービスへ渡し、復路はサービスから戻ってきた素のパケットを SRv6 に復元して次 segment へ送ります。

## 往路と復路の分離

往路は既存の `sid_endpoint_progs` dispatch に乗ります。SID 宛パケットは endpoint slot (AS=14, AM=15, AD=24, AN=25) の tail call target で処理され、decap または DA 書き換えのあと IFACE-OUT からサービスへ redirect します。

復路は `vinbero_main` の front door に置いた `try_service_return` が入口です。`resolve_ingress_vrf` の後、`try_l2_headend` の前に呼ばれ、`service_ingress_map` を `{ifindex, vlan}` で引きます。hit したら専用の PROG_ARRAY `service_return_progs` へ tail call します。miss は -1 を返して既存 pipeline へ素通しするので、非 proxy トラフィックのコストは hash lookup 1 回です。

`service_return_progs` への `bpf_tail_call` は `try_service_return` 内の 1 箇所だけに保ちます。同一 PROG_ARRAY への lexical site が 2 つ以上あると XDP_REDIRECT が silent drop する既知の問題があるためです。この不変条件は behavior を追加するときも守ります。

## IFACE-IN circuit

IFACE-IN はサービスからの戻りを受ける attachment circuit で、1 proxy segment 専用です。draft のとおり control plane が 1:1 を enforce します。`service_ingress_map` の bind は `CreateServiceIngress` が `UpdateNoExist` で行い、kernel 側の atomic な存在検査で二重 bind を弾きます。同一 SID の再 bind だけは update として許し、rollback 用に旧値を返します。

proxy SID の trigger_prefix を別 circuit に付け替えたり非 proxy action に作り替えたりしたときは、`createOneSidFunction` が旧 circuit を unbind します。front door は `try_l2_headend` より前段なので、放置すると旧 binding が orphan になり、そのポートが恒久的に black-hole になります。`SidFunctionServer` は create / delete / flush を mutation mutex で直列化し、capture-then-delete の順序が並行 unbind と race しないようにします。

flush は per-prefix の owner-scoped delete で回します。全 owner の SID から circuit を集めて一括 unbind すると、生きている BGP-owned proxy SID の circuit を奪ってしまい、decap 済みの平文が front door の miss で kernel に漏れます。

## マップ構成

| マップ | キー | 値 | writer |
|---|---|---|---|
| service_ingress_map | {ifindex, vlan} | behavior + inner type mask + 所有 SID + End.AS 静的 CACHE | control plane |
| ad_cache_map | {ifindex, vlan} | End.AD の動的 outer cache (seqlock 付き) | data plane (往路) |
| service_return_progs | SVC_RET_* | 復路 tail call target | control plane |

`service_ingress_map` は control plane が書き data plane が読むため read-only partition、`ad_cache_map` は往路の BPF が書くため read-write partition に登録します。`service_return_progs` は plugin から tail call させないため `ValidTailCallMaps` には含めません。容量は `settings.entries.service_ingress.capacity` で両マップまとめて設定します。

`service_ingress_map` は pin します。`ad_cache_map` は pin しません。再起動後の stale な cache header を、変更後の chain に replay しないためです。

## End.AS 静的 proxy

往路は SR encap を剥がして IFACE-OUT へ redirect します。decap は SL == 0 を要求しません。chain の状態は CACHE 側にあり、proxy は chain の途中に置かれるためです。inner type は IPv4 / IPv6 / Ethernet の 3 種に対応します。

サービスへの配送は 2 モードです。`service_mac` を設定すると静的 MAC 書き換え (source MAC は create 時に oif デバイスから解決)、省略すると inner destination の FIB lookup です。

復路は `service_ingress_entry.encap` に直埋めした `headend_entry` (outer src + segment list) で再 encap します。1 lookup で `tailcall_ctx_write_headend` に渡せます。outer IPv6 の payload_len はサービスの申告値ではなく on-wire の L3 長から作ります。IFACE-IN のサービスは信頼境界の外側なので、過大申告を許すと malformed な SR パケットをドメインに注入するためです。

## End.AD 動的 proxy

End.AS と同じ構造ですが、CACHE を静的設定でなく往路のパケットから学習します。往路は endpoint の標準処理 (SL 減算、DA 更新) を outer に行ったあと、前置できる完成形の outer IPv6 + SRH を `ad_cache_map` に IFACE-IN circuit 単位で保存します。復路は cache を前置して payload_len を再計算するだけです。

SL == 0 と reduced encap (SRH 無し) は drop します。次 segment が無い、または DA が proxy SID 自身になるため、有効な return 状態を構成できないためです。SRH は segments-only に限ります。`hdrlen == (first_segment + 1) * 2` で検証し、TLV や padding を含む SRH は cache を触る前に drop します。TLV 付き SRH を range 検査だけで通すと、cache row を無効化したまま copy に失敗して復路を恒久停止させる 1 パケット DoS になります。

### update-skip

安定した chain の cache line を毎パケット書き換えないため、outer IPv6 + SRH の全バイトが一致し hop limit の差が margin 以内なら更新をスキップします。比較から除外するのは per-packet で変わる payload_len と Traffic Class と flow label です。DA が同じでも深い segment が変わった chain 変更は cache を refresh します。

### seqlock

往路 (writer) と復路 (reader) は別 CPU に乗り得るうえ、208 バイトの header copy は atomic ではありません。torn read を検知するため `ad_cache_val` に seq を持たせます。seq は偶数が安定、奇数が writer 更新中です。

`ad_cache_map` は通常の HASH なので往路が複数 CPU から同一 row を同時更新し得ます。writer は 64bit の compare-and-swap で seq を偶数から奇数に翻す形で row を claim します。CAS に勝った 1 者だけが更新し、負けた writer はスキップします。BPF v1 ISA は 32bit atomic を持たないので seq は u64 です。CAS の対象を自然整列させるため `ad_cache_val` は packed にしていません。フィールド順が 8 バイトの header にちょうど収まるので layout は変わりません。

reader は copy の前に seq を読み、奇数なら drop、copy のあと seq を読み直して変化していれば drop します。compiler barrier で store 順序を固定します。BPF は最古サポート kernel に portable な release/acquire fence を持たないので、weakly-ordered CPU での保証は torn read を検知して drop することであり、torn read を観測しないことではありません。

## End.AM masquerading proxy

往路は SL を減算して DA を Segment List[0] (最終 segment) に書き換え、SRH を残したままサービスへ渡します。inner は L3 のみです。配送は静的 MAC 必須です。masquerade 後の DA は chain の最終宛先を指すため、FIB lookup するとサービスを素通りするためです。

復路は in-packet の SRH から DA を Segment List[SL] に復元して FIB へ渡します。SL は変更しません。書き換え前に DA が Segment List[0] であることを確認します。往路の masquerade が必ず DA = Segment List[0] を書くので、それ以外の DA を持つパケットはこの proxy を通っていません。検証を省くと、IFACE-IN にパケットを置ける者による任意宛先注入 primitive になります。

## fail-closed 方針

復路の各 target は !ctx / bounds 失敗 / slot 未実装 / ctx write 失敗ですべて XDP_DROP です。front door の tail call 失敗も drop に落とします。IFACE-IN は専用線なので、raw フレームを通常 pipeline に漏らさないためです。

FIB miss の扱いは AS / AD と AM で分けます。AS と AD は復路で新しい outer encapsulation を組み立てるため、FIB miss を XDP_DROP に統一します。組み立て済みの SR パケットを service 側の kernel stack に渡すのは意図した経路ではないためです。AM は service 由来の well-formed な SRv6 パケットの DA を書き換えるだけで新規に組み立てないため、FIB miss 時に kernel へ渡して routing させるのは妥当です。

front door は circuit の payload 型に合わないフレームを kernel に渡します。IPv4 circuit の ARP、IPv6 circuit の ND、L3 circuit の multicast / link-local 宛てを drop すると circuit の neighbour 状態が維持できないためです。proxy に入るのは circuit の payload 型に一致した unicast だけです。

## 信頼境界

IFACE-IN のサービスは信頼境界の外側として扱います。復路の length clamp と AM の DA 検証はこの前提に基づきます。加えて proxy SID は SR domain 内からのみ到達できる前提です。End.AD は往路のパケットから outer を丸ごと cache するため、domain 外から proxy SID 宛のパケットを届けられると cache を任意の segment list で上書きできます。RFC 8754 のドメイン境界 filtering で SID prefix 宛の外部トラフィックを落とす運用が前提になります。

## End.AN SR-aware native

SR-aware なサービスは SRH を自分で理解するため、パケット処理は End と同一です。専用 slot 25 は per-SID の統計と、将来の service liveness 連動の anchor として置きます。aux には NF catalog の metadata (`service_name`、printable ASCII 63 文字まで) を持たせ、SidFunctionList / Get を NF discovery の service registration point にします。往復の circuit も proxy 状態も持ちません。

## 復路 slot 統計

復路の behavior 別呼び出し回数は `slot_stats_service_return` PERCPU_ARRAY に記録します。index は復路 slot 番号 (`SVC_RET_AS`=0 / `SVC_RET_AD`=1 / `SVC_RET_AM`=2) で、tail call の epilogue が `DISPATCH_SERVICE_RETURN` を検出したときに 1 加算します。endpoint / headend の per-slot 統計と同じく `enable_stats` で gate し、無効時は verifier が加算コードを削ります。`vbctl stats slot show --type service_return` で behavior 名つきに整形して表示し、`vbctl stats slot reset --type service_return` で clear します。service_return は builtin slot 専用なので plugin の `--type` 候補には出しません。

## テスト

BPF_PROG_TEST_RUN は ingress_ifindex を loopback (1) に固定するので、往路の SRv6 パケットが front door に吸われないよう、circuit は VLAN で分離してテストします。往路は decap / DA 書き換えの byte 検証、復路は encap 出力の byte 検証を行います。負系は inner type 不一致、AD cache 未 seed、AD の TLV / 奇数 hdrlen、AD の odd seq、AM の SL=0 / SRH 無し / foreign DA、AS の過大申告長を drop で確認します。server は circuit lifecycle (orphan cleanup、owner-scoped flush、delete unbind) と field scope の検証を live map で行います。E2E は `examples/end-{as,ad,am,an}/` にあり、SR-unaware なサービス役を netns で立てて chain を通します。
