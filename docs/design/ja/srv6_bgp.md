# SRv6 over BGP 設計

## 概要

このドキュメントは、Vinbero が BGP control plane の上で SRv6 サービスをどう実現しているか、そのメンタルモデルを説明します。実装のクラスや関数の羅列ではなく、概念とデータの関係、そして Vinbero がどの役割分担で組んでいるかに焦点を当てます。

BGP でシグナルする SRv6 サービスは複数あり、この資料はそれらを 1 つの枠組みで捉える場所にします。現在カバーするのは次の 4 つです。

- L3VPN (VPNv4/VPNv6): RD/RT で経路を区別してインストールする
- color steering: 経路に付く color を SR Policy の path に紐付けて転送する
- EVPN (L2VPN): MAC を RD/RT で配り、SRv6 service SID で拠点をブリッジする (multi-homing を含む)
- SRv6 MUP (mobile user plane): モバイルの GTP-U セッションを BGP で配り、SRv6 の GTP behavior へ反映する

RD/RT による区別とインストールというメンタルモデルは、これらすべてに共通します。MUP は加えて、セッション経路 (T1ST/T2ST) が segment discovery 経路 (ISD/DSD) から SID を解決する仕組みを持ちます (詳細は [SRv6 MUP (mobile user plane)](#srv6-mup-mobile-user-plane))。

実装のシーケンスは [api_sequence.md](./api_sequence.md)、interop の検証構成は `examples/interop-clab/scenarios/` を参照してください。

## L3VPN (VPNv4/VPNv6) の概要

VPNv4/VPNv6 は、1 つの物理網の上で複数の顧客の閉じた IP 網を同時に運ぶ仕組みです。顧客ごとに prefix が重複してもよく、経路の配り先も顧客ごとに分離できます。これを成り立たせるために、次の要素があります。

- VRF: 顧客ごとに独立したルーティングテーブルです。
- RD (route distinguisher): 共有 BGP テーブル上で重複 prefix を一意にする名前空間です。どの VRF に入れるかは決めません。
- RT (route target): 経路の所属を表すタグです。VRF は import RT に一致した経路だけを取り込み、full mesh や hub-spoke といった配り方を決めます。
- service SID: SRv6 L3VPN では egress PE の VRF を service SID (End.DT4/DT6) で指します。ingress PE は service SID 宛に encap し、egress PE が decap して VRF へ渡します。

## VPNv4/v6 をどう実現するか

Vinbero は in-process の BGP speaker を持ち、PE 同士で VPNv4/VPNv6 の経路を交換します。受信した 1 つの VPN 経路を、どう区別してどう data plane に落とすかが、L3VPN 実現の中心です。

### 受信経路の区別とインストール

受信した VPN 経路は、次の順に解釈します。

1. RD で区別する。共有 BGP テーブルでは prefix が重複しうるので、NLRI は `RD:prefix` の組で持ちます。RD が違えば同じ prefix でも別経路として共存し、衝突しません。RD は所属を決めないので、ここでは取り込み先 VRF を判断しません。
2. RT で取り込み可否を決める。経路の RT が、登録済みのどれかの VRF の import RT に一致したときだけ取り込みます。一致しなければ破棄します。これが顧客ごとの経路分離の実体です。
3. service SID へ向ける encap として install する。取り込む経路には SRv6 service SID (End.DT4/DT6) が添えられています。Vinbero はこれを、この prefix 宛のパケットを service SID へ encap するという 1 つの転送指示に変換し、headend の encap エントリとして data plane に置きます。

RD は経路を一意にして取り消しを識別するために使い、転送先 VRF の判断には使いません。判断は RT だけで行います。この役割分担で、重複 prefix と経路分離を同時に実現します。

```mermaid
flowchart LR
    R["受信 VPN 経路<br/>RD 65000:100<br/>10.2.0.0/24<br/>RT 65000:200<br/>service SID S"]
    Q{"RT が VRF の<br/>import RT に一致?"}
    INST["install:<br/>10.2.0.0/24 → S へ encap<br/>(headend エントリ)"]
    DROP["破棄"]
    R --> Q
    Q -->|一致| INST
    Q -->|不一致| DROP
```

### Vinbero での実装

この区別とインストールを、Vinbero は次の役割分担で組んでいます。

- BGP speaker: default では gobgp を in-process で動かして実現します。gobgp が peer と VPNv4/VPNv6 を交換し、受信した経路を route handler へ渡します。BGP speaker は差し替え可能な interface で、gobgp はその default 実装です。
- route handler (applier): 受信経路ごとに RD・prefix・service SID・RT・next hop を取り出します。
- VRF と RT の対応: VRF ごとの RT は config か RPC で事前に登録し、VRF 名を鍵にした map で保持します。RPC で登録した binding は state file にも保存し、再起動では BGP session の起動より前に戻します ([persistence.md](persistence.md#vrf-の-bgp-binding))。binding は family (vpnv4 / vpnv6 / evpn / mup_ipv4 / mup_ipv6) ごとに RT と import/export の方向を持てます。applier は経路の RT を該当 family の import RT と照合し、どれにも一致しない経路を落とします。
- encap entry の生成: 一致した経路を H.Encaps の headend エントリ (segments = [service SID]) に変換し、{vrf_id, prefix} を鍵にした eBPF の LPM trie (headend map) へ、import RT が一致したすべての VRF の vrf_id で書きます。1 つの経路を複数の VRF が import すれば、それぞれの VRF に入ります。宛先は {VRF, family, prefix} ごとに 1 つの ECMP group を持ち、同じ VRF に入る別の PE (RD) の path だけが同じ group にまとまります。VRF の決定は RT だけで行い、RD は path を区別するためだけに使います。その family を RT 付きで宣言する binding が無い間は default-allow で、vrf_id 0 (global VRF) に書きます。書き込みには owner tag を付け、後で同じ owner の経路だけを正確に withdraw できるようにします。withdraw は RT を運ばないので、applier は path ごとに入れた VRF を記録しておき、記録したすべての VRF から外します。data plane は入口の AC が分類した VRF の entry だけを引くので、tenant の CE の口はその VRF の access circuit にします ([vrf.md](vrf.md#access-circuit-の無い-binding))。
- encap source: outer の送信元 IPv6 は、設定したローカル locator の prefix から取ります。`vbctl locator create` で登録した locator も state file に保存し、再起動では binding の適用と BGP session の起動より前に戻すので、`bgp.global.source_locator` と binding の `default_locator` は最初に届いた経路と最初の auto-advertise から解決できます ([persistence.md](persistence.md#locator))。auto-advertise の service SID は、戻した locator から起動時に割り当て直すので、値は再起動の前と同じとは限りません。

BGP の UPDATE は属性全体の暗黙の置換なので、applier は追跡済み NLRI の再広告が使えない内容になったときも withdraw と同じ撤去を行います。service SID が使えなくなった再広告 (空のほか、全ゼロの `::` のような routable でない値。decode 時の検証で不正と判定された場合を含む) は、L3VPN の headend エントリ、EVPN RT2 の FDB / bd_peer、RT3 の flood bd_peer、per-EVI A-D の aliasing 寄与、MUP ISD/DSD の discovery とその解決先のセッションを撤去してから読み飛ばします。EVPN RT2/RT3 の撤去は、その状態を教えた PE (next hop) からの再広告に限定します (per-EVI A-D は NLRI 単位で撤去します)。RT がどの import filter にも一致しなくなった再広告の撤去は、filter を持つ経路種別、つまり L3VPN、EVPN RT2/RT3 と per-EVI A-D (bridge-domain binding 不一致)、MUP の session route (T1ST/T2ST) に適用します。MUP の discovery route (ISD/DSD) は cross-VRF 解決のため import-RT filter を意図的に迂回するので、RT 不一致による撤去はありません。

```mermaid
flowchart LR
    PEER["BGP peer"]
    subgraph VB["Vinbero (control plane)"]
        SPK["BGP speaker<br/>(default: gobgp, in-process)"]
        APP["route handler (applier)"]
        VRFRT["VRF↔RT map<br/>VRF 名 → import/export RT"]
        LOC["locator<br/>encap source prefix"]
    end
    HM["headend map<br/>eBPF LPM trie ({vrf_id, prefix} 鍵)<br/>+ owner tag"]
    XDP["XDP data plane<br/>H.Encaps / decap"]

    PEER -->|VPNv4/v6 UPDATE| SPK
    SPK -->|受信経路| APP
    APP <-->|RT 照合| VRFRT
    LOC -->|encap source| APP
    APP -->|encap エントリを書く| HM
    HM -->|参照| XDP
```

広報方向も同じ BGP speaker を使い、ローカル prefix を service SID 付きで経路として出します。受信と広報で同じ data model を共有します。

XDP の data plane は、受信が headend エントリを引いて H.Encaps し、egress 側は service SID (End.DT4/DT6) で decap して VRF の table へ渡します。BGP は何を install するかを決め、XDP がそれを高速に実行する、という分担です。

### binding と locator の変更による再評価

受信経路の取り込み可否は、届いた時点で 1 度だけ判定します。gobgp の watch は同じ経路を送り直さないので、判定の材料が後から変わったときは、applier が gobgp の loc-rib にある受信済みの VPN 経路を受け取り直して評価し直します。結果は新しく届いた場合と同じになるので、取り込みと撤去の両方が起きます。

- binding の変更: vpnv4 / vpnv6 の RT を持つ binding が 1 つも無い family は、受信した経路をすべて取り込みます (default-allow)。binding の作成、更新、削除、RT や family の追加と削除でその family の import 判定が変わると、評価し直します。import RT が増えれば、それまで落としていた経路が入ります。RT や binding が減れば、どの VRF も import しなくなった経路が data plane から消えます。最初の binding で default-allow は終わり、global VRF に入っていた経路は import する VRF へ移ります。RT が import されるかどうかだけでなく、どの VRF が import するかが変わる変更 (別の VRF が既に import している RT を足す場合や、RT を別の VRF へ移す場合) でも評価し直します。経路は import しなくなった VRF から外れ、新しく import する VRF に入ります。同じ内容で bind し直すなど、判定が変わらない変更では評価し直しません。MUP の family (mup_ipv4 / mup_ipv6) の変更も同じように MUP の loc-rib を評価し直します。この評価し直しは非同期で、RPC は取り消しの完了を待ちません。import RT を外した直後は、外した VRF に経路が残っている間があります (後述の再試行で消えるまで)。
- source locator の登録: headend エントリの送信元は `bgp.global.source_locator` の locator から取るので、この locator が無い間に届いた経路は、取り込んでも書き込めません (L3VPN では prefix ごと、MUP ではセッションごとに 1 回 warning を出します)。`vbctl locator create` でこの locator を登録すると、その RPC の中で書き込みます。対象は追跡している L3VPN の経路と MUP のセッション経路 (T1ST/T2ST) で、EVPN は続けて loc-rib を受け取り直して書き込みます。書き込みに失敗した経路があれば log に残し、locator の登録は成功させたうえで、後述の再試行に任せます。
- source locator を別の prefix で登録し直したとき: 書き込み済みのエントリも、登録の RPC の中で送信元を新しい prefix に書き換えます。peer が経路を送り直す必要はありません。対象は、L3VPN の ECMP group と trigger、EVPN の RT2 (unicast) と RT3 (BUM) の bd_peer、EVPN aliasing の group と ES peer、MUP の T1ST と T2ST です。EVPN の bd_peer は同じ index のまま書き換えるので、FDB のエントリと BUM の flood の slot は変わりません。MUP T2ST の gate は送信元を持たないので書き換えません。ECMP group を書き換えると liveness の bitmap は初期化されますが、prober は登録し直す時点の down の判定を引き継ぎます。書き換えに失敗したエントリは、後述の再試行で書き直します (その間、bd_peer は元の送信元のまま、aliasing の segment は PE ごとの転送に戻ります)。bd_peer の書き換えは bridge domain ごとにまとめ、BUM の flood の状態はその BD について 1 回だけ作り直します。bd_peer_reverse_map のエントリは相手 PE の送信元を鍵に index と ESI を持つだけで、自分の送信元に依らないので書き換えません。同じ prefix で登録し直した場合は、何も書き換えません。`mup_gtp4_source_prefix` で VRF ごとの送信元を埋め込む GTP4 の T1ST は、locator を使わないので、その送信元のままです。plugin が src_addr を省略して宣言した headend エントリは、宣言したときの送信元のままで、plugin が宣言し直すまで変わりません。
- source locator の削除: 書き込み済みのエントリは、持っている送信元のまま転送を続けます。削除時に warning を 1 回出します。新しいエントリ (届いた経路の最初の書き込み) は、locator を登録し直すまで書き込みません。書き込み済みのエントリへの変更は待たせず、そのエントリが持っている送信元で書き込みます。ECMP や aliasing の group から抜けた member はすぐに外れ、MUP の SID の解決し直しや、書き込み済みの PE の背後で新しく学習した MAC もそのまま反映します。送信元が記録されていない aliasing の segment は、PE ごとの転送に戻します。経路が無くなったエントリの撤去も、locator が無くても行います。

> **binding を減らすときの注意**: `vbctl vrf-bgp unbind`、`vrf-bgp rt remove`、`vrf-bgp family remove` などで、vpnv4 / vpnv6 の RT を持つ binding が 1 つも無くなると、その family は default-allow に戻り、受信済みの経路がすべて data plane に入ります。binding が無いノードを起動したときと同じ結果です。このとき vinberod は warning を 1 回出します。ある tenant の経路を外したいだけなら、最後の binding を消す代わりに、残す側の import RT を持つ binding を置いてください。

binding の変更による評価し直しは、RPC とは別の goroutine で非同期に行い、RPC はその完了を待ちません。binding の変更は、どの経路で行われても binding の管理側が 1 回ずつ検出するので、後の変更で元に戻った変更も評価し直されます。実行中に届いた要求は次の 1 回にまとめます。評価し直しで落とした経路は、経路ごとではなく件数で 1 行だけ log に出します。

#### 書き込みに失敗したときの再試行

受け取り直し、locator の登録、受信経路の処理で data plane への書き込みや撤去に失敗した場合は、同じ goroutine が再試行します。再試行の中身は、失敗に必要なものだけです。

- applier が追跡している状態 (L3VPN の ECMP group、MUP のセッション、EVPN の bd_peer の書き換えと aliasing の segment) の書き込みや撤去の失敗は、追跡している状態を書き直す処理だけをもう一度行います。loc-rib は読み直しません。受信経路の処理で起きた失敗も、ここに入ります。
- EVPN の経路は書き込めるまで追跡しないので、受け取り直しの中で最初の書き込みに失敗した EVPN の経路は、EVPN の loc-rib の受け取り直しをもう一度行います。数えるのは、その受け取り直しが配った経路の失敗だけです。受け取り直しの間は受信経路の配送を止めているので、受信経路の失敗や別の処理の失敗は混ざらず、VPN だけの受け取り直しが EVPN の失敗で繰り返されることもありません。受け取り直しの外で最初の書き込みに失敗した EVPN の経路は、再試行しません。
- loc-rib を読めなかった場合は、その受け取り直し全体をもう一度行います。

再試行の間隔は 1 秒から倍々に延ばし、最大 30 秒です。再試行は 1 回の失敗につき 6 回まで (1、2、4、8、16、30 秒後で、合わせて約 1 分) で、それでも失敗する場合は、まだ失敗している書き込みの数を error で 1 行だけ log に出して止めます。flood の list が上限に達した bridge domain、別の owner が持つエントリ、満杯の map のように、待っても直らない失敗で loc-rib を読み続けないためです。新しい要求 (binding の変更、locator の登録) は、再試行の待ち時間を待たずにすぐ実行し、待っていた再試行もそこに含め、回数と間隔を最初から数え直します。受信経路の処理で書き込みに失敗したことによる要求は、数え直しません。再試行が続いている間はその次の再試行に含め、待ち時間と回数はそのまま数えます。再試行が止まった後は 5 分間、失敗による要求を受け付けません。失敗し続ける書き込みが、受信経路の更新のたびに再試行をやり直すことがないようにするためです。5 分たつか、binding の変更や locator の登録があれば、また再試行します。

### service SID の運び方 (transposition)

service SID は RFC 9252 §4 の transposition で運ばれ、SID の一部が MPLS label フィールドに転置されます。Vinbero は受信時に transposition を戻し、full SID を組み立ててから install します。これにより、egress PE がどんな割り当てで service SID を出しても、ingress 側は正しい full SID へ encap できます。

### 広報と取り消し

逆方向に、Vinbero はローカルの顧客 prefix を service SID 付きの VPN 経路として広報できます。広報した経路は family・prefix・RD の組で識別し、取り消し (withdraw) もこの識別で行います。VPNv4 と VPNv6 は family が違うだけで、同じ仕組みです。

広報は VRF ごとに行います。auto-advertise は binding の VRF の kernel table を見て、その VRF の RD、export RT、その VRF の End.DT4/DT6 の SID で経路を出します。2 つの VRF が同じ prefix を持っていても、RD が違えば別の経路として広報され、受信側では RT で別々の VRF に入ります。同じ RD を 2 つの VRF に付けると、同じ prefix の経路は BGP で 1 つになるので、VRF ごとに別の RD を使います。

auto-advertise は kernel の経路の event を購読してから、binding の table の既存の経路を別の request で読んで広報します。購読が終わったとき (受信 buffer の溢れなど) は、encap の next hop の keeper と同じ待ち方と log で購読し直し ([vrf.md](vrf.md#encap-の-next-hop-の-neighbour))、table を読み直します。広報済みで table から消えた prefix を先に取り消し、その間に増えた経路をそれから広報します (`max_prefixes` の枠を先に空けるためです)。table の読み込みが失敗したとき (kernel が dump を中断したときを含みます) は、購読し直しと同じ待ち方で読み直し、warning (`netlink listing incomplete; retrying`) を error が変わったときだけ出します。

## color: 通す経路の意図を付ける

color extended community (RFC 9012) は、経路に特定の path を通すという意図を付ける 32bit のタグです。VPN 経路に color が付いていると、その経路宛のトラフィックを、bare な service SID へ直行させるのではなく、指定の path 上に乗せたい、という意味になります。

color はあくまで意図 (どの path グループか) であり、path の中身そのものではありません。path の中身 (通すべき transport segment の並び) は SR Policy が持ちます。color が 0 の経路は steering されず、service SID へ直行します。

## SR Policy

### モデル

SR Policy は path の定義で、{color, endpoint} で識別します (RFC 9256)。endpoint は steering の到達点で、L3VPN では egress PE です。color と endpoint の組が、color 付き経路と SR Policy を結ぶ鍵になります。

1 つの SR Policy は複数の candidate path を束ね、active を 1 つ選びます。candidate path は次を持ちます。

- preference: 大きいほど優先されます (未指定なら 100)。
- origin: 由来 (operator 定義の local、BGP 学習、PCEP) を表し、local > BGP > PCEP の順に強くなります。
- segment list: 通すべき transport segment (SRv6 SID) の並びです。

candidate は BGP で運ぶときは NLRI {distinguisher, color, endpoint} と Tunnel Encapsulation 属性で表します (RFC 9830, SAFI 73)。distinguisher は同じ {color, endpoint} に対する複数の出し手を区別します。

### active の選び方

同じ {color, endpoint} に複数の candidate があるとき、preference の高い順、次に origin の強い順、最後に distinguisher の小さい順で active を 1 つ選びます (RFC 9256 §2.9)。segment list が空、または長すぎて転送に乗せられない candidate は選びません。

operator がローカル定義した SR Policy と BGP で学習した SR Policy は、同じ {color, endpoint} のテーブルで競合し、同じ規則で active を決めます。

## color 紐付け (auto-steering) のメンタルモデル

### 経路と SR Policy を結ぶ

受信した VPN 経路に color が付いていると、その color と経路の next hop から {color, endpoint} を作り、同じ鍵を持つ SR Policy を探します。endpoint は経路の next hop と一致する必要があります。SRv6 over IPv6 では service SID へ向かう next hop が常に IPv6 なので、endpoint も IPv6 であることを要求します。

### policy_id という間接参照

経路と SR Policy を直結させず、間に policy_id という不透明な番号を置きます。{color, endpoint} ごとに policy_id を 1 つ割り当て、それを経路側 (encap エントリ) に書きます。transport segment の並びは policy_id を鍵にした eBPF の hash (sr_policy_map) に置きます。{color, endpoint} と policy_id の対応や candidate の集合は、in-process の SR Policy table ({color, endpoint} を鍵にした in-memory の map) が持ちます。

この間接参照のおかげで、SR Policy の中身が変わってもテーブル 1 本を書き換えるだけで済み、その policy_id を指すすべての経路に一度に反映されます。経路側のエントリは触りません。

```mermaid
flowchart LR
    VR["color 付き VPN 経路<br/>color=100, next hop=PE2<br/>service SID=S"]
    KEY["{color, endpoint}<br/>= {100, PE2}"]
    PID["policy_id = N"]
    HE["encap エントリ<br/>service SID=S<br/>policy_id=N"]
    POL["transport テーブル<br/>policy_id N → [T1, T2]"]

    VR -->|color と next hop から鍵を作る| KEY
    KEY -->|割り当て| PID
    PID -->|経路側に書く| HE
    KEY -->|SR Policy の中身| POL
```

経路と SR Policy の到着順は問いません。経路が先なら policy_id を予約し、その時点ではテーブルが空なので転送は service SID へ fallback します。後から SR Policy が来れば同じ policy_id に transport が入り、経路を書き換えずに steering が始まります。逆順でも同じ番号に収束します。

policy_id は、それを指す経路の数で参照を数えます。経路も candidate も無くなった {color, endpoint} は table から外し、空いた番号は free list (slice) に戻して次の {color, endpoint} で再利用します。

### 転送時の合成

転送のときに初めて、transport と service SID を合成します。policy_id があれば transport テーブルを引き、その transport segment の並びの末尾に、経路自身の service SID をつなげます。これが実際にパケットへ載せる segment list です (RFC 9252 §8)。

```mermaid
flowchart LR
    T["transport (SR Policy)<br/>T1, T2"]
    S["service SID (経路)<br/>S = End.DT4"]
    C["合成 segment list<br/>T1, T2, S"]
    W["パケット<br/>outer 宛先 = T1 (最初の hop)<br/>最後に S で VRF へ decap"]

    T --> C
    S --> C
    C --> W
```

最初の transport hop がパケットの外側の宛先になり、segment を 1 つずつ辿って最後に service SID へ着き、そこで VRF に decap します。policy_id を引いてテーブルが無い場合 (SR Policy 未着、取り消し、合成が長すぎる) は、合成せず service SID へ直行する fallback になります。

## EVPN (L2VPN) over SRv6

### 概要

EVPN (RFC 7432) は、複数拠点の L2 セグメントを 1 つの broadcast domain として束ねる L2VPN です。Vinbero は EVPN を SRv6 で運び (RFC 9252 §6)、顧客の MAC を BGP で配って拠点間のフレームを SRv6 でブリッジします。コントローラも別の signaling もなく、PE 同士が iBGP で MAC と flood 宛先と Ethernet Segment を交換します。

L3VPN と同じく RD で経路を一意にし、RT で取り込み先を決めます。違いは取り込み先が VRF でなく bridge domain (bd) であることだけです。AFI/SAFI は L2VPN-EVPN (25/70) を使い、service SID は L3VPN と同じく Prefix-SID の L2 Service TLV に載せ、transposition で運びます。

### route type と service SID

EVPN は経路の種類 (route type) で役割が分かれます。Vinbero が扱うのは次の 4 つです。

- RT1 (Ethernet A-D): multi-homed segment についての集合的な主張を配ります。per-ES 形式 (Ethernet Tag = MAX-ET) は mass withdraw の signal と Single-Active bit を、per-EVI 形式は aliasing の着地先になる End.DT2U SID を運びます。詳細は [ecmp.md](./ecmp.md) の EVPN RT1 の節を参照してください。広報は `vbctl bgp advertise-evpn-ad` で、per-ES と per-EVI を対で出します。
- RT2 (MAC/IP advertisement): 1 つの顧客 MAC の所在を配ります。End.DT2U service SID に紐付け、その MAC 宛ての unicast フレームを SID へ encap します。
- RT3 (Inclusive Multicast): BUM (broadcast / unknown-unicast / multicast) の flood 宛先を配ります。End.DT2M SID に紐付け、PMSI 属性で Ingress Replication を示します。
- RT4 (Ethernet Segment): multi-homing で、1 つの顧客が複数 PE に接続していることを配ります。service SID は載せず、ES-Import RT で同じ segment に接続する PE 同士を結びます。

```mermaid
flowchart LR
    RT2["RT2 MAC/IP"] --> DT2U["fdb_map[bd, MAC]<br/>→ bd_peer(End.DT2U SID)"]
    RT3["RT3 Inclusive Mc"] --> DT2M["bd_peer(End.DT2M SID)<br/>+ PMSI Ingress Replication"]
    RT4["RT4 Ethernet Segment"] --> ESI["esi_map に DF を書く<br/>(service SID なし)"]
```

### 受信経路のインストール (RT2 / RT3)

受信した RT2/RT3 は、L3VPN と同じ流れで bd へ落とします。

1. RD で区別する。同じ MAC でも RD が違えば別経路として共存します。
2. RT で取り込み先の VRF を決め、その VRF の bridge facet から bd を得る。経路の RT が binding の import RT に一致し、かつ binding の VRF に bridge facet が付いているときだけ取り込みます (facet の無い binding は fail-closed で match しません)。
3. service SID へ向ける install にする。RT2 なら相手の End.DT2U SID を segment に持つ bd_peer を作り、`fdb_map[bd, MAC]` をその peer へ向けます。以後その MAC 宛ての L2 フレームは XDP headend が SID へ H.Encaps.L2 します。RT3 なら相手の End.DT2M SID への flood 用 bd_peer を作り、BUM をそこへ複製します。

RT と VRF の対応は config か RPC で事前に登録し、bd はその VRF の bridge facet (vrf bridge-attach) が唯一の出所です。import 面がそろう前に届いて drop された route は、VrfBridgeAttach / vrf-bgp bind が面を広げた時点で gobgp loc-rib の snapshot から再適用されます (自 node が広告した route は local-origin として skip)。広報方向も同じ data model で、ローカルの顧客 MAC を End.DT2U SID 付きで RT2、flood 宛先を End.DT2M SID 付きで RT3 として出します。

```mermaid
flowchart LR
    PEER["BGP peer"]
    subgraph VB["Vinbero (control plane)"]
        SPK["BGP speaker<br/>(default: gobgp, in-process)"]
        APP["route handler (applier)"]
        BIND["VRF↔RT binding<br/>import RT → VRF → bridge facet の bd"]
    end
    FDB["fdb_map[bd, MAC]<br/>→ bd_peer(End.DT2U SID)"]
    MC["bd_peer(End.DT2M SID)<br/>BUM flood"]
    DP["XDP / TC data plane<br/>H.Encaps.L2 / flood"]

    PEER -->|RT2 / RT3 UPDATE| SPK
    SPK -->|受信経路| APP
    APP <-->|RT 照合| BIND
    APP -->|RT2: MAC を install| FDB
    APP -->|RT3: flood 宛先を install| MC
    FDB --> DP
    MC --> DP
```

### multi-homing (RT4 / DF election / split-horizon)

1 つの顧客を 2 つの PE にぶら下げると (multi-homing)、BUM が両 PE から顧客へ二重に届いたり、片方が受けた BUM をもう片方経由で顧客へ送り返してループになったりします。これを防ぐのが Designated Forwarder (DF) と split-horizon です。

- Ethernet Segment (ES) は ESI (10 byte の識別子) で表し、同じ ES に接続する PE は RT4 を ES-Import RT 付きで広報し合います。各 PE は、受信した RT4 の送信元 PE と自分を候補集合にして、RFC 8584 の default DF election (候補を encap source で整列し index = ETag mod N) を独立に走らせます。ELAN は ETag 0 なので encap source が最小の PE が DF になります。全 PE が同じ membership から同じ結果を出すので、合意のための調停はいりません。
- ESI は 10 octet で、先頭の 1 octet が type です (RFC 7432 §5)。vinberod が受け付けるのは次の形だけで、`vbctl es create`、`bgp advertise-evpn-mac` / `advertise-evpn-es` / `advertise-evpn-ad`、`hl2 create`、`bd-peer create` の `--esi` が同じ検査を通ります。それ以外はエラーを返し、値を直して通すことはしません。エラーには、誤っている octet と、その type の並びを示します。
  - type 0 (任意): 続く 9 octet は何でもかまいません。全 0 は single-homed を表します。
  - type 1 (LACP): system MAC 6 octet、port key 2 octet、最後の 1 octet は 0x00 です。
  - type 2 (bridge protocol): bridge MAC 6 octet、priority 2 octet、最後の 1 octet は 0x00 です。
  - type 3 (MAC): system MAC 6 octet、local discriminator 3 octet です。予約された octet はありません。
  - type 4 (router ID): router ID 4 octet、local discriminator 4 octet、最後の 1 octet は 0x00 です。
  - type 5 (AS): AS 番号 4 octet、local discriminator 4 octet、最後の 1 octet は 0x00 です。
  - type 6 以上は定義がないので受け付けません。
  - 最後の octet が 0x00 でない type 1、2、4、5 の ESI は、受信した GoBGP が UPDATE を不正として session を切ります。そのため 1 つの誤った入力が、その経路を受け取るほかの node の BGP session を落とします。type 6 以上は GoBGP の受信側は通しますが、RFC 7432 に type が無いので vinberod は広告しません。
- BUM が来たとき、DF だけが顧客へ流し、非 DF は drop します (data plane の dt2m_non_df_drop)。これで二重配送が消えます。
- split-horizon (RFC 9252 Local Bias) は、ある PE が受けた BUM を、同じ ES の別 PE 経由で共有顧客へ再 flood しないようにします。受信フレームの outer source (相手 PE の encap source) を鍵に、その PE 向けの flood を抑えます。

```mermaid
flowchart TB
    SRC["BUM (remote PE から)"]
    DF["End.DT2M (DF = pe1)"]
    NDF["End.DT2M (非 DF = pe2)"]
    CE["共有 CE<br/>1 回だけ受信"]
    DROP["drop<br/>(dt2m_non_df_drop)"]
    SRC -->|RT3 で両 PE へ flood| DF
    SRC -->|RT3 で両 PE へ flood| NDF
    DF -->|forward| CE
    NDF --> DROP
```

### DF election の収束 (RT4 と es create の到着順)

DF election が書き込むのは、operator が local 接続を宣言した (es create) ESI だけです。spoof された RT4 で phantom な ES を作らせないためです。ただし RT4 と es create の到着順は決まりません。そこで membership (RT4 で学習した PE の集合) は local 接続の有無に関わらず常に記録し (件数に上限を設けて crafted RT4 の氾濫を防ぎ)、es create を契機に election を再実行します。RT4 が es create より先に来ても membership に残るので、後から local 接続を宣言した時点で正しい DF を選べます。逆順なら RT4 受信時の election で収束します。どちらの順序でも同じ DF に落ち着きます。

```mermaid
flowchart TB
    subgraph O1["RT4 が先 (es create より前)"]
        direction TB
        A1["RT4 受信"] --> A2["membership に記録<br/>未 attach なので election は保留"]
        A2 --> A3["es create"] --> A4["ReelectDF"]
    end
    subgraph O2["es create が先"]
        direction TB
        B1["es create"] --> B2["election<br/>(member まだ無し)"]
        B2 --> B3["RT4 受信"] --> B4["election"]
    end
    A4 --> R["同じ DF に収束<br/>esi_map に DF を書く"]
    B4 --> R
```

### data plane の分担

control plane は何を install するかを決め、eBPF/XDP の data plane がそれを高速に実行します。XDP headend が unicast フレームを End.DT2U SID へ H.Encaps.L2 し、End.DT2 / End.DT2M で decap して bridge domain へ渡します。BUM は TC の clone-to-self で各 flood 先へ複製し、DF drop と split-horizon をここで効かせます。interop の検証構成は `examples/interop-clab/scenarios/evpn-2site` (RT2/RT3) と `evpn-multihoming` (RT4 DF + split-horizon) を参照してください。

```mermaid
flowchart LR
    F["顧客フレーム (bd)"]
    Q{"宛先 MAC を<br/>fdb_map で解決?"}
    U["unicast<br/>End.DT2U へ H.Encaps.L2"]
    B["BUM<br/>TC clone-to-self で<br/>全 End.DT2M peer へ複製"]
    EU["egress: End.DT2 で decap → bd"]
    EB["egress: End.DT2M で decap<br/>DF だけ転送 / split-horizon で抑制"]

    F --> Q
    Q -->|"解決 (unicast)"| U --> EU
    Q -->|"未解決 / BUM"| B --> EB
```

## SRv6 MUP (mobile user plane)

### 概要

SRv6 MUP (RFC 9433、draft-mpmz-bess-mup-safi) は、モバイルの GTP-U セッションを SRv6 へマッピングするサービスです。5G では gNB と UPF の間 (N3) を GTP-U で運びますが、これを SRv6 segment に載せ替えると、コアを純粋な IPv6/SRv6 fabric にでき、per-UE のトンネル状態をコアの中間ノードから排除できます。

役割は 3 つに分かれます。MUP Controller (MUP-C) が UE セッション状態を BGP で配り、MUP Gateway (MUP-GW) が access 側で GTP-U と相互接続し、MUP Provider Edge (MUP-PE) が data 側で DN へ届けます。AFI/SAFI は MUP (1/85) を使い、L3VPN/EVPN と同じく RD で経路を一意にし、RT で VPN の所属を決め、SID は Prefix-SID で運びます。

### route type と方向

MUP は経路の種類で役割が分かれ、方向ごとにペアになります。

- T1ST (session transformed type 1): per-UE の downlink セッションです。UE prefix・TEID・QFI・gNB endpoint を運び、MUP-PE が消費します。
- T2ST (session transformed type 2): uplink の aggregate セッションです。endpoint と可変長の TEID prefix を運び、MUP-GW が消費します。
- ISD (interwork segment discovery): interwork segment の到達性です。MUP-GW が広報し、T1ST の SID 解決に使います。
- DSD (direct segment discovery): direct segment の到達性で、MUP Extended Community の segment id を持ちます。MUP-PE が広報し、T2ST の SID 解決に使います。

ペアは downlink が T1ST + ISD、uplink が T2ST + DSD です。T1ST は TEID を exact 値で運びますが、T2ST は TEID を可変長 prefix で運び (EndpointAddressLength が endpoint と TEID の有効ビットを覆う)、1 経路で TEID 範囲を集約できます。これが uplink の data plane の選択を決めます。

```mermaid
flowchart LR
    T1ST["T1ST (downlink)"] --> ISD["ISD (MUP-GW 広報)<br/>endpoint で SID 解決"]
    T2ST["T2ST (uplink)"] --> DSD["DSD (MUP-PE 広報)<br/>segment id で SID 解決"]
    ISD --> ENC["MUP-PE: UE prefix へ<br/>H.Encaps (interwork SID)"]
    DSD --> FTE["MUP-GW: F-TEID lookup<br/>(direct SID)"]
```

### セッション経路の取り込み

T1ST/T2ST のセッション経路は、L3VPN と同じく RT で取り込み可否を決められます。どれかの VRF binding が MUP family (mup_ipv4 / mup_ipv6) を宣言すると、その family のセッション経路は、どれかの binding の import RT に一致するときだけ取り込み、一致しなければ落とします。ISD/DSD の discovery 経路はこのフィルタを通しません。gateway や PE 自身の RT で届き、VRF をまたいだ解決の材料になるためです。withdraw もフィルタを通さず、先に受理した経路を必ず撤去できるようにします。

その family を宣言した binding が 1 つもなければ、すべてのセッション経路を受け入れます。bgp.global.mup_default_allow を立てると、宣言があってもこの default-allow を維持できます。

### SID 解決 (segment discovery)

L3VPN/EVPN は service SID を経路自身の Prefix-SID で運びますが、MUP は加えて、セッション経路が segment discovery 経路から SID を解決できます (RFC 9433 §3)。controller はセッション状態だけを配り、SID は各 gateway/PE が相手の discovery 経路から引きます。

- T1ST → ISD: gNB endpoint を含む ISD prefix の longest-match で interwork SID を解決します。
- T2ST → DSD: 同じ segment id を持つ DSD から direct SID を解決します。
- セッション経路が自分の Prefix-SID を載せる構成も可能で、その場合は discovery で解決できないときの fallback になります。

解決は同じ VPN の中に限定します。所属の判定は L3VPN と同じく RT で行い、セッション経路と discovery 経路の RT リストが少なくとも 1 つ重なるときだけ解決の候補にします。RD は広報者ごとに経路を一意にする鍵であって VPN の境界ではないので、cross-vendor 構成で同じ VPN の経路が別々の RD で届いても解決できます。別 VPN の経路がより具体的な prefix や同じ segment id を広報して他セッションの SID を奪うことは、RT が重ならない限り起きません。

BGP は到着順を保証しないので、discovery 経路が後から届いたら同型の全セッションを再解決し、deferred だったものを install、discovery を withdraw したら依存セッションを撤去します。解決は一意に決まるよう実装し、ISD の longest-match が同じ長さで並んだときも DSD の segment id が衝突したときも最小の SID を決定的に選び、map の反復順でデータプレーンが揺れないようにします。

### 広報の wire format

ISD/DSD を広報するとき、Prefix-SID には SID とともに endpoint behavior を載せます。ISD なら End.M.GTP4.E / End.M.GTP6.E、DSD なら End.DT4 / End.DT6 です。behavior を見て downlink の合成可否を決める受信実装があるためです。SID が登録済みの locator に属するときは、その locator の構成から SID Structure sub-sub-TLV (RFC 9252) を導いて合わせて載せます。SID の locator block で next hop tracking する受信実装が、構造の分からない SID を unreachable と扱うためです。複数の locator prefix が同じ SID を含むときは longest-match の locator から導き、locator に属さない SID では省略します。

T1ST の NLRI framing は draft-mpmz-bess-mup-safi の版で異なります。Vinbero は source 付きの -03 形式と source なしの -01 形式の両方を decode し、source なしの広報は -01 の形式 (末尾の SourceAddressLength を省略した 23 byte) で出します。-01 だけを話す peer との interop のためです。

### data plane の分担

downlink と uplink で lookup キーが非対称で、これはセッション経路が運ぶ情報に対応します。

- downlink (T1ST): MUP-PE が UE prefix に対し、interwork SID へ Args.Mob.Session (gNB、TEID、QFI) を合成して H.Encaps します。受信側 MUP-GW の End.M.GTP4.E が SID 宛先から gNB/TEID/QFI を実行時に読み、GTP-U を gNB へ送ります。SID がセッション情報を内包するので、End.M.GTP4.E はセッション非依存に一度設置すれば足ります。GTP6 も同型で、Args.Mob.Session には TEID と QFI だけを載せ、gNB の IPv6 は End.M.GTP6.E 側の aux 設定から取ります。
- uplink (T2ST): MUP-GW が 2 段で dispatch します。まず endpoint に H.M.GTP4.D_TEID の gate を置いて GTP-U を変換対象と認識させ、次に GTP-U の TEID で mup_uplink_v4_map (LPM) を最長一致 lookup して direct SID へ encap します。T2ST が TEID を可変長 prefix で運ぶため、exact HASH でなく LPM になります。受信側 MUP-PE の End.DT4 が inner IP で DN へ届けます。GTP6 も同型で、H.M.GTP6.D_TEID と mup_uplink_v6_map を使います。

uplink の状態は VRF 単位に分離できます。VRF に `vbctl vrf ac-add` で ingress access circuit ({interface, VLAN}) を宣言すると、その VRF は vrf_id を持ち (`vrf.Manager` が allocate)、ingress front door が `ingress_vrf_map` を {ifindex, vlan} で引いて vrf_id を決め `tailcall_ctx.vrf_id` に載せます。import RT が一致した T2ST の F-TEID エントリはその vrf_id をキーに含めて install されるので、複数の VRF が同じ N3 endpoint アドレス空間と TEID 空間を使っても衝突しません。gate も headend エントリなので、入口の VRF で引かれます。そのため gate はセッションの VRF に置き、{VRF, endpoint} ごとに参照を数えます。同じ endpoint でも VRF が違えば別の gate です。VRF 間の fallback は無く、自 VRF に gate かセッションが無い GTP-U はそのまま素通しになります。T1ST の downlink も、セッションの VRF に {VRF, UE prefix} で書きます。DN 側の口はその VRF の AC にします。1 つのセッションは 1 つの VRF にだけ入り、import RT が複数の VRF に一致すれば VRF 名が最小のものです。binding の無い MUP family (default-allow) と `mup_default_allow` で受け入れたセッションのうち、どの binding にも一致しないものは global VRF (vrf_id 0) に入ります。BGP binding の RT 変更や unbind は、セッションが一致する VRF が変わり得るので、install 済みの T1ST と T2ST を新しい VRF へ移します (新しい VRF に書いてから古い VRF のものを消します)。どの binding にも一致しなくなったセッションは撤去し、MUP の loc-rib を評価し直すので、後から import した binding には受信済みのセッションが入ります。ingress 分類は VRF object の facet で、BGP binding (`vrfbgp`) は同じ VRF を name で Ensure する別 facet です。interop の検証構成は `examples/interop-clab/scenarios/mup-2site-multivrf` で、同一の {endpoint, TEID} を持つ 2 つの VPN が ingress access interface だけで分離されることを assert します。

GTP4 の downlink では、outer IPv6 の送信元が GTP-U の外側 IPv4 送信元の運び手を兼ねます (RFC 9433 §6.6)。VRF binding に mup_gtp4_source_prefix を設定すると、セッションの RD から binding を引き、その prefix の直後に UPF の IPv4 anchor を埋め込んだアドレスを outer 送信元にします。受信側 MUP-GW の End.M.GTP4.E は、prefix 長の位置 (v4src position) から IPv4 を取り出して gNB へ送る GTP-U の送信元にします。Vinbero の End.M.GTP4.E では sid create の gtp_v4_src_position でこの位置を設定すると抽出し、代わりに gtp_v4_src_addr を設定すると静的な送信元を使います。position は BGP でシグナルされないので、embed 側の prefix 長と受信側の設定位置は運用で一致させます。anchor は同じ RD の T2ST のうち TEID prefix がこのセッションの TEID を覆うものの endpoint から取るので、controller が UPF の N3 アドレスをセッション状態として配れば追加の設定はいりません。prefix が VRF binding 単位なので、VRF ごとに別の source pool と v4src position を使えます。prefix 未設定や anchor 未着のときは locator 由来の encap source に fallback し、binding を変更したらその RD の install 済み downlink を再 reconcile して、embed のやり直しや plain source への復帰を反映します。

egress 側の End.M.GTP4.E / End.M.GTP6.E は、SRH 付きの encap に加えて、SRH を省いた reduced encap (RFC 8986 §4.1.1) の単一 SID パケットも受理します。H.Encaps reduced で出す送信側との interop のためです。

interop の検証構成は `examples/interop-clab/scenarios/mup-2site` を参照してください。MUP-C・MUP-GW・MUP-PE・gNB・DN を模し、controller が SID なしの T1ST/T2ST を、各 gateway/PE が SID 付きの ISD/DSD を広報して、解決だけで双方向の GTP-U ⇄ SRv6 が通ることを検証します。downlink の outer 送信元が per-VRF prefix で UPF anchor を embed していることも、ここで assert します。

```mermaid
flowchart LR
    UP["uplink: gNB GTP-U"] --> GW["MUP-GW<br/>gate + F-TEID lookup"]
    GW -->|direct SID で SRv6| PE["MUP-PE<br/>End.DT4 → DN"]
    DN["downlink: DN → UE prefix"] --> PE2["MUP-PE<br/>H.Encaps (interwork SID)"]
    PE2 -->|Args.Mob.Session で SRv6| GW2["MUP-GW<br/>End.M.GTP4.E → gNB GTP-U"]
```

## 広報方向

Vinbero は経路や SR Policy を受け取るだけでなく、広報もできます。ローカルの顧客 prefix を service SID 付きで VPN 経路として広報し、ローカル定義の SR Policy を SAFI 73 で広報できます。広報した SR Policy は {distinguisher, color, endpoint} で管理し、取り消しもこの鍵で行います。MUP も同じく広報でき、MUP-C は T1ST/T2ST を、MUP-GW/MUP-PE はそれぞれ自分の ISD/DSD を出します。

## 今後の BGP SRv6 サービス

この資料は SRv6 over BGP の置き場所なので、今後追加するサービスもここに積みます。いずれも本文と同じメンタルモデル (RD/RT による区別とインストール、color と SR Policy の steering、MUP の segment discovery 解決) が下敷きになります。新しいサービスを足すときは、本文の VPNv4/v6・EVPN・MUP の節と同じ粒度で、何を RD/RT で区別し、何を service SID に紐付け、Vinbero がどの役割分担で install するかを書き足します。

## 参照 RFC

- RFC 9252 — BGP ベースの SRv6 services (L3VPN service SID と transposition、§6 EVPN と Local Bias、§8 steering)
- RFC 9256 — SR Policy アーキテクチャ (candidate path、§2.9 active 選定、protocol-origin)
- RFC 9830 — Advertising SR Policies in BGP (SAFI 73 NLRI、Tunnel Encap、Segment Type B)
- RFC 9012 — Tunnel Encapsulation 属性 (§4.3 Color Extended Community)
- RFC 8986 — SRv6 Network Programming (End / End.DT4 / End.DT6 / End.DT2U / End.DT2M / H.Encaps)
- RFC 9831 — SR Policy の segment type 拡張 (Type C〜K、現状は範囲外)
- RFC 7432 — BGP MPLS-Based Ethernet VPN (EVPN の route type RT2/RT3/RT4)
- RFC 8584 — EVPN の default DF election (ordinal modulo)
- RFC 9433 — SRv6 Mobile User Plane (End.M.GTP4.E / End.DT4 / Args.Mob.Session ほかの GTP behavior、§6.6 の IPv4 source address embed)
- draft-mpmz-bess-mup-safi — BGP MUP SAFI (85) による MUP route (ISD/DSD/T1ST/T2ST) のシグナリング
- draft-ietf-dmm-srv6-mobile-uplane 系 — SRv6 MUP のアーキテクチャ
