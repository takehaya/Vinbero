# Control plane plugin

Vinbero の control plane を operator が拡張するための機構です。data plane
plugin が eBPF bytecode を受け取るのに対し、control plane plugin は
WebAssembly module を受け取ります。どちらも daemon に upload され、登録時に
検証されます。WASM 側の書き込みは宣言した capability と scope の範囲に host が
強制します。eBPF 側は operator が review した semi-trusted な artifact が
前提で、検査は best-effort です (data plane 境界の節)。

## 何のためにあるか

オペレータが独自の SRv6 endpoint behavior を持ち込み、ネットワークとして
機能する状態までを plugin だけで完結させることが目標です。

1. 転送は data plane plugin が endpoint slot に実装します。これは既存の
   plugin SDK でできます。
2. control plane plugin がその behavior codepoint を claim します。
3. plugin が local SID を要求します。host が locator から address を確保
   し、plugin の slot を指す dispatch entry を書き、address を event で
   plugin に返します。名前は plugin が付け、値は host が選びます。記憶を
   失って戻ってきた plugin が同じ名前を宣言すると同じ address が返ります。
   この安定性は 1 つの daemon run の中で、同じ名前を同じ locator から
   宣言し直す限りの話です。instance の作り直しや同名 upgrade では保たれ、
   locator を変えた宣言は別の address を割り当て直します。daemon 再起動を
   跨ぐと保証されません (local SID と daemon 再起動の節)。
4. plugin がその SID を SID TLV に自分の codepoint を載せて広告します。
5. 対向でその経路を受けた plugin が headend の状態を宣言します。
6. Vinbero 自身の applier はその経路を見ません。codepoint を見ずに service
   SID から entry を作るので、知らない codepoint を素の SID と誤読して
   しまうためです。

これで両ノードは Vinbero も BGP も知らない behavior で通信します。実例は
`sdk/examples/cplane-custom-behavior` にあり、この 6 段を実装しています。

この 6 段を 2 ノードに割り付けると次の流れになります。node A が behavior を
実装して広告する側、node B がそれを受けて headend を張る側です。

```mermaid
sequenceDiagram
    participant OpA as operator (node A)
    participant PA as cplane plugin (node A)
    participant VA as vinberod (node A)
    participant BGP as BGP session
    participant VB as vinberod (node B)
    participant PB as cplane plugin (node B)

    OpA->>VA: data plane half を endpoint slot に register
    OpA->>VA: cplane half を register (capability と scope と behavior claim)
    Note over VA: claim 済み codepoint の経路は built-in applier に配らない
    PA->>VA: local SID を宣言 (名前と locator と slot)
    VA->>VA: locator から address を確保し dispatch entry を書く
    VA-->>PA: 確保した address を event で返す
    PA->>VA: その SID を自分の codepoint 付きの SID TLV で広告を宣言
    VA->>BGP: VPN 経路として advertise
    BGP->>VB: 経路が届く
    Note over VB: built-in applier には配らず plugin だけに配送
    VB-->>PB: event として配送
    PB->>VB: headend の状態を宣言 (encap 先 = node A の SID)
    Note over VB,VA: node B の customer traffic が encap され node A の SID に届き dispatch entry が plugin の slot へ渡す
```

新しい AFI/SAFI は要りません。endpoint behavior は SID TLV の中の 16bit
codepoint なので、独自 codepoint の広告は vpnv4 や EVPN といった既存
family にそのまま載ります。

## 全体像

```mermaid
flowchart LR
    subgraph kernel
        MAPS[(BPF maps)]
        NL[netlink events]
    end

    subgraph vinberod
        GOBGP[gobgp session]
        DEMUX[event demux<br>single Subscribe<br>local-origin filter + claim]
        APPLIER[built-in applier]
        OPS[capability ops<br>desired-set apply + lease]
        subgraph RT[wazero runtime]
            W1[plugin worker + instance]
        end
        GOBGP --> DEMUX
        NL --> DEMUX
        DEMUX --> APPLIER
        DEMUX -->|queue| W1
        APPLIER --> OPS
        W1 -->|host function| OPS
        OPS --> MAPS
    end

    CLI[vbctl plugin cplane register] --> RT
```

## 経路の配送

gobgp の watch は daemon ごとに 1 回しか開けません。Subscribe ごとに
current=true の WatchEvent が開き、2 回目は loc-rib を後から attach した
consumer へ replay してしまいます。そこで daemon が唯一の subscription を
持ち、consumer は demux (`pkg/bgp/demux`) に登録します。

demux が引き受ける規則は 2 つです。

- local-origin path を live stream と snapshot replay の両方で落とします。
  plugin が広告を始めると自ノードの経路が post-policy stream に還流し、
  consumer が self-pointing な状態を作ってしまうためです。
- consumer が宣言した family だけを配ります。

配送は plugin ごとの worker goroutine で行います。demux の handler は BGP
watch goroutine で走り、そこは block してはいけない契約です。call budget
いっぱい使う plugin が 1 つあると built-in applier を含む全 consumer が
止まるので、handler は queue に積んで返ります。queue が溢れた分は drop
して数えます。`Manager.DroppedEvents` で確認できます。

drop は plugin の view に穴を空けます。desired set を宣言する consumer に
とってこれは遅延より悪く、次の宣言が見えていない状態を prune します。
そこで drop は snapshot debt として記録し、rib から view を作り直します。
replay は plugin ごとに 1 本だけ走らせます。2 本が 1 つの queue に押し込む
と順序が無く、古い copy が新しい copy の後に届いて plugin が古い値を持ち
続けます。drop している plugin は定義上遅いので、drop ごとに replay を
起動すると積み上がりもします。実行中に来た要求は debt を立て直し、完了後に
返します。
snapshot の配送は drop せず block します。replay は BGP watch goroutine
ではないので block してよく、一部を落とすと目的そのものを損ねるためです。
snapshot も live と同じ queue を通し、replay の間に届いた live event は
worker が保留して、snapshot と end of replay を積み終えてから流します。
rib を走査している間に同じ NLRI の update が queue に割り込めないので、
snapshot の中の copy を、それを追い越した update より後に見ることは
ありません。保留が queue の深さを超えた分は drop して snapshot debt を
立て直すので、追い越しではなく再修復に倒れます。これは配送順序の保証で、
snapshot 自体が rib のある一瞬を写した atomic な cut だという保証では
ありません。走査は family ごとに rib を読むだけなので、走査中に変わった
分は snapshot に混ざり得ますが、その変化の event は保留されて snapshot の
後に届くので、plugin の view はそこで揃います。保留の解放時にも queue に
収まらなかった分は drop されて snapshot debt に戻るため、この一致は
過負荷が続く間は次の replay へ先送りされます。追い越しはしませんが、
恒常的に溢れている plugin の view は遅れ続けます。

replay の先頭には start of replay の event を置きます。replay は何が在る
かを述べる手段であって、何が無くなったかは述べられません。plugin が聞いて
いない間に withdraw された経路は replay に現れないので、view を持ち越すと
その経路を宣言し続け、以後どの event でも消えません。start of replay を
受けた plugin はその source について知っていることを捨て、続く event から
組み立て直します。これで replay が merge ではなく修復になります。宣言は
end of replay まで待ちます。replay の最中に空集合を宣言すると、その間だけ
転送が落ちるためです。

drop から修復までの流れをまとめます。

```mermaid
sequenceDiagram
    participant D as demux (BGP watch goroutine)
    participant R as replay (snapshot の作り手)
    participant Q as plugin worker queue
    participant G as plugin instance

    D->>Q: live event を積む (block しない)
    Q->>G: 順に配送
    D--xQ: queue が満杯なら drop して snapshot debt を記録
    Note over R: debt を見て replay を plugin ごとに 1 本だけ起動
    R->>Q: 保留開始。以後の live event は pending に貯める
    R->>Q: start of replay
    R->>Q: rib の copy を block しながら積む
    R->>Q: end of replay
    R->>Q: 保留解除。pending を流し、収まらない分は drop して debt に戻す
    Q->>G: start で view を破棄し end まで宣言を保留して再構築
```

## behavior の claim

plugin は登録時に claim する codepoint を宣言します。claim 済みの経路は
built-in applier に配りません。

- claim は all-or-nothing です。途中で失敗した plugin が behavior を半分
  だけ持つ状態を作りません。
- 衝突は配送時ではなく登録時に弾きます。
- codepoint 0 は behavior 無しの意味なので claim できません。
- 標準化済みの codepoint は claim できません。受信側は codepoint を見ずに
  service SID から entry を作るので、Vinbero が originate しない End.DT46
  や End.DX4 も現在正しく扱えています。それらを claim 可能にすると本物の
  L3VPN 経路が built-in から逸れます。運用上の規則は「標準 codepoint は
  Vinbero のもの、plugin は割り当て外の codepoint を使う」です。

UPDATE で behavior が変わった場合も担当を切り替えます。built-in に渡した
path が claimed へ変わったら、以前の配送内容を withdraw として渡してから
新しい UPDATE を plugin に配ります。VPN は RD が違っても同じ family と
prefix が headend の同じ key を使うので、その prefix の path に claimed が
1 本でもあれば built-in へ渡した path をすべて撤去します。通常の path の
UPDATE でこの抑止を抜けることはできず、最後の claimed path が消えたら
残っている通常の path を built-in に再配送します。

claim 取得時の明示的な RIB 再走査では、現在の demux が built-in に配送した
履歴が無くても withdraw を渡します。前の daemon が pinned map に残した
状態や、独立した replay で入った状態も、plugin が引き継ぐ前に撤去します。
登録に失敗して claim を戻した場合も、demux が保持する最新の path を再評価
して built-in の担当を戻します。登録中に withdraw 済みの path は復活させません。

withdraw には path attribute が一切載りません。BGP は消える NLRI しか
送らないので、advertise 時の behavior は経路が消えるときの wire に存在せず、
そのままでは claim が advertise 側にしか効きません。demux は ledger を
持ち、claim 済み behavior の advertise はその NLRI と path を記録し、記録の
ある path の withdraw を claim 済みとして扱います。記録は path 単位です。
route reflector 2 台や ADD-PATH では 1 つの NLRI が複数 path で届いて複数回
withdraw されるためです。

## plugin が書ける面

`bpf.MapOperations` は 101 method の全能オブジェクトなので plugin には
渡しません。capability ごとに narrow interface を切り、宣言した capability
に対応する host function だけを link します。宣言に無い能力は「呼べない」
のではなく存在しません。

書き込みの基本形は owner ごとの desired-set apply です。plugin は望ましい
集合を丸ごと宣言し、core が現状との差分を計算して適用します。core だけが
差分を持つので、途中で死んだ plugin は同じ集合を宣言し直すだけで収束し、
順序付き編集列のどこまで送ったかを覚える必要がありません。

apply は transaction ではありません。BPF map に複数 entry を atomic に書く
手段が無いため、途中失敗は前の write を残します。冪等なので retry で収束
します。順序は prune を先に回し、貼り替え中の prefix が二重に存在する瞬間
を作りません。ABI の `apply_begin` が開く「transaction」は宣言 chunk を
積むための staging の単位で、commit までは何も適用されないという意味です。
map への適用が atomic だという意味ではありません。

同一 key を 2 owner が書く状況は宣言時に fail-closed で弾きます。desired
set は owner ごとに差分を取るので、2 owner が同じ key を宣言すると互いに
自分の集合としては一貫した view を持ったまま 1 つの map entry を奪い合い
ます。BPF map については per-entry owner map が最終的な enforcement で、
lease は早期に、相手の名前を添えて落とすための前線です。

owner と lease が扱うのは同じ key の奪い合いだけです。他人の key に触れずに
それより強い key を作る形は別の問題で、scope の章で扱います。

## ABI

境界を渡るのは linear memory 上の byte buffer で、構造は protobuf が持ち
ます (`proto/vinbero/v1/cplane_plugin.proto`)。buffer は guest 所有で、host
は guest の alloc に確保させてから書きます。呼び出しが返った後、host は
guest memory への参照を持ちません。linear memory は grow で移動しうる
ためです。

guest が export するもの。

| export | 意味 |
|---|---|
| `vinbero_abi_version() -> i32` | 対応する ABI version。不一致は登録時に拒否 |
| `alloc(size) -> ptr` | host が書き込む領域を確保 |
| `free(ptr, size)` | 領域を解放 |
| `configure(ptr, len) -> i32` | operator 設定を受け取る。省略可 |
| `handle_events(ptr, len) -> i64` | event batch を処理。戻りは status の (ptr, len) |
| `on_tick(now_ns)` | 定期呼び出し。省略可 |
| `_initialize()` | reactor initializer。言語 runtime が使う |

host が提供するもの。すべて `vinbero` module から import します。

| host function | 意味 |
|---|---|
| `log(level, ptr, len)` | daemon log へ出力 |
| `now_monotonic() -> i64` | `on_tick` と同じ clock による単調増加の ns |
| `apply_begin(kind) -> i64` | desired-set transaction を開く (headend v4/v6、advertise、local SID) |
| `apply_put(gen, ptr, len) -> i32` | 宣言の chunk を積む |
| `apply_commit(gen) -> i32` | 差分を適用する |
| `apply_abort(gen)` | transaction を捨てる |

`log` と `now_monotonic` は determinism をあえて壊す穴です。sandbox には
stdout も filesystem も無いので log が無いと plugin 作者に調査手段があり
ません。clock が無いと liveness 系のロジックが書けません。それ以外の
非決定入力は必要になるまで足しません。

daemon では `on_tick` と `now_monotonic` が起動時からの同じ clock を共有し、
instance を作り直しても原点を変えません。harness では `Tick(elapsed)` で
進めた時刻を host function からも読み、restart 後にも引き継ぎます。

## capability

plugin は登録時に何をしてよいかを宣言し、host はそれが覆う host function
だけを link します。link は 2 段のうちの粗い方です。何も書けない plugin に
は apply 関数がそもそも link されず、呼ぶと失敗するのではなく到達できない
関数になります。書ける plugin に対しては、apply 関数が宣言の種類をまたいで
共有なので、種類ごとの判定を transaction を開くところで行います。

| capability | 許すこと |
|---|---|
| `headend` | headend の encap entry を宣言する |
| `advertise` | BGP 経路を originate する |
| `local_sid` | locator から SID を確保し自分の slot に向ける |

`log` と `now_monotonic` は常に link します。どちらも状態を変えず、無いと
plugin 作者が何も調べられなくなるためです。

desired-set の apply 関数は宣言の種類をまたいで共有なので、link は「何か
1 つでも書ける capability があるか」で決まります。種類ごとの判定は
transaction を開くところで再度行います。これが無いと advertise だけを
granted された plugin が同じ扉から headend の transaction を開けます。

何も granted されていない plugin も登録できます。観測と log だけをする
plugin は実際に有用で、それが capability を宣言しなかった plugin の安全な
既定です。

## scope

capability は種類しか絞りません。どこに書いてよいかを決めるのが scope で、
両方が揃わないと plugin は何も書けません。scope を宣言しなかった登録は、
capability が何であれ観測と log だけをする plugin になります。

scope が必要なのは、owner tag と lease が守るのが「他人が持っている鍵を
上書きしないこと」だけだからです。この 3 面はどれも、他人の鍵に触れずに
それより強い鍵を新しく作れます。headend map は LPM trie なので長い prefix が
lookup に勝ち、VPN 経路は受信側の PE で more specific が勝ちます。所有は
object 単位の性質なので、この形は表現できません。

| 宣言 | 範囲 | 理由 |
|---|---|---|
| `local_sid` | locator 名の集合 | 宣言が locator 名を持ち、割り当ては `pkg/locator` が管理する |
| `local_sid` の decap_vrf | VRF 名の集合 | plugin dispatch の built-in decap を許可済み VRF へ縛る (advertise と同じ集合) |
| advertise の vpnv4 と vpnv6 | VRF 名の集合 | RD と RT を binding から導出する |
| advertise の ipv6_unicast | 許可された locator の配下 | plugin がここで広告する正当なものは自分の SID である |
| `headend` | trigger prefix の list | 縛れる名前が存在しない |

加えて、plugin が所有する PROG_ARRAY slot を宣言します。headend は v4 と v6 の
map が別の PROG_ARRAY で slot 番号を共有するので、grant も別にします。v4 の
slot 16 を渡しても v6 の slot 16 は渡しません。endpoint は 1 つです。plugin A が
plugin B の slot に entry を向けると、B の program は A の aux bytes を自分の
layout として読むためです。

slot は plugin をまたいで排他にします。同じ slot を 2 つの plugin に渡すと、
一方の SID がもう一方の program に dispatch して aux を取り違えるので、behavior
claim と同じく登録時に拒否します。locator も同じく排他にします。VPN や
ipv6_unicast の広告で SID を locator 配下に閉じ込める抑えが安全なのは、その
locator が 1 つの plugin だけのものであるときだけで、共有した locator では別の
plugin や built-in service SID の配下を指す広告を止められないためです。slot と
locator の排他はどちらも登録時に拒否します。prune や restore に失敗した plugin は
running registry から外れますが、state と claim を map に残したままなので、その
slot と locator も forget されるまで予約し続けます。そうしないと別名の plugin が
同じ grant を取り、残存 state と衝突するためです。prefix scope は排他にしません。
operator が意図的に重ねることがあり、実際の衝突は per-entry の owner と lease が
調停します。

locator の排他は名前で見ます。別名で prefix を入れ子にした locator を別々の
plugin に渡すと、広い locator を持つ plugin が狭い locator 配下の SID も
`Contains` 判定で広告できてしまいます。prefix の重なりの調停は locator の登録側
(`pkg/locator`) の領分で、scope が名前しか持たない登録時には実 prefix が未登録の
こともあるため、ここでは名前の排他に留めます。operator は入れ子の locator を
別々の plugin に割り当てないことを前提とします。

### VPN 広告は照合ではなく導出

plugin は VRF 名だけを宣言し、RD と RT は host が binding から埋めます。
輸入を決めるのは RD ではなく RT なので、RD だけを照合しても余分な RT を
付ければ束縛されていない VRF に経路を注入できます。導出にすると、その経路が
構造として消え、RD の表記揺れを scope 側で正規化する必要も無くなります。
宣言に RD や RT が入っていたら、黙って無視せず拒否します。

binding が受信専用で RD を持たない場合は、その VRF への広告を拒否します。
operator が選んでいない RD で経路を出すことになるためです。同じく、binding が
その family の export RT を 1 つも持たない場合も拒否します。RT が空だと誰も
import しない経路になり、成功したように見えて誰にも届かないためです。

RT の導出が決めるのは経路を誰が import するかで、経路が実際にどこへ向かうかは
prefix-SID TLV の SRv6 SID が決めます。導出だけでは、VRF blue に scope された
plugin が blue の prefix を VRF red の service SID の裏に広告して blue の traffic を
red へ流せます。そこで VPN 経路の SID は、plugin が自分で確保した SID
(`LocalSIDSet.LiveSIDs`) に限ります。同じ `locator.Manager` から built-in の
auto-exporter や operator の service SID も同一 locator 内に確保されるため、locator の
配下という照合だけでは他人の SID を裏に広告できてしまい、locator 名の plugin 間排他
だけでは built-in や operator の確保を止められないためです。確保した SID の address を
持つのは host なので、この照合は owner の live SID 集合を知る apply 経路で行います。
まだ確保していない SID は失敗し、local SID の宣言が適用された後の reconcile が
やり直します。next hop や grant 内の segment を縛らない理由は、次の節でまとめます。

### scope が縛る軸と grant 内の自由

scope が縛るのはどの traffic を扱えるかで、grant の中で経路がどこへ向かうかは
縛りません。この線引きは意図したもので、境界を跨げる値だけを scope で抑えます。

next hop はこの grant 内の自由に当たります。VPN 経路の next hop は import した
peer が到達性を解決するためのもので、encap source は locator address であって
BGP transport とは限らず、daemon に妥当な推測がありません。next hop を locator に
縛ると正当な interop 構成を壊すため、元の挙動のまま自由にします。VPN SID を
locator に閉じ込めたのは、SID が別 VRF の decap の裏へ逃げて scope の VRF grant を
跨げるからで、next hop にはその跨ぎがありません。

同じ理由で、plugin が渡された locator の配下に組む segment list の中身も grant 内の
自由です。segment はすべて自分の locator に属し、他人の VRF や locator へ抜ける
出口が無いので、個々の segment を scope で照合しません。segment list が built-in
state の layout を跨いで別 VRF の decap を起こせるのは data plane half の話で、
これは scope ではなく shared map の partition と aux discriminator で抑えます
(後述の data plane 境界の節)。

binding の `MaxPrefixes` は plugin の広告にも適用します。VRF を渡すことが
無制限の VRF を渡すことにならないようにするためです。

binding は plugin が動いている間に operator が編集するものなので、導出した値は
binding が変わった時点で再導出します。unbind も同じで、binding が消えた VRF の
経路は wire から降ろします。RD と RT と上限は宣言を適用した時点で
刻まれるため、これが無いと export RT を変えても plugin が次に宣言し直すまで
古い RT を載せた path が wire に残ります。event 駆動の plugin は長く宣言し直さ
ないことがあります。宣言経路では範囲外を集合ごと拒否しますが、この再導出では
上限を超えた分を withdraw します。operator が上限を下げたときに拒否すると経路が
全部残り、頼んだことと逆になるためです。

### headend だけ prefix で縛る

`headend_v4_map` の key は `lpm_key_v4` で prefixlen と addr しか持たず、
VRF も locator も key に入りません。名前で縛れる対象が無いので、operator が
prefix を並べます。未指定なら headend の宣言を拒否するので、`::/0` の
catch-all は書けません。

将来は「claim した behavior で自分に配送された経路の prefix」を scope の
要素として並べられるようにする余地を残しています。いまは採っていません。
demux の絞り込みが family と claim だけで import RT を見ないため配送集合が
built-in の処理対象より広く、withdraw で縮み restart で作り直す派生状態でも
あるからです。

### 検査する場所

scope は chunk を decode した時点ではなく、集合を apply する時点で検査します。
scope が参照する locator と VRF binding は daemon 起動後に RPC で登録される
ので、restore された plugin がそれらより先に宣言するのは普通に起きます。
apply 時に失敗させれば、既存の retry 機構がそのまま修復に使えます。

範囲外の要素が 1 つでもあれば集合ごと拒否します。宣言は集合についての表明
なので、残りを適用すると plugin が求めていない状態を入れることになります。

### scope を狭めたとき

狭める操作だけは desired-set の模型では直りません。plugin が同じ宣言を
続けると集合ごと拒否されるので reconcile が走らず、広い scope の下で書いた
状態が残ります。そこで登録の時点で host が範囲外の状態を prune します。再登録に
限らず restore でも走らせます。daemon 再起動をまたいだ状態は pinned map に残って
おり、狭い scope で restore した plugin はそれを 1 つも触れないためです。
実装は「まだ許される部分集合を desired set として apply する」形で、残りは
既存の reconcile が落とします。

この prune の視界は同一 run 内の再登録と restore で違います。headend は
どちらの場合も BPF map を owner ごとに列挙して見えます。local SID と広告は
in-memory の集合からしか見えないので、再登録では 3 面とも prune され、
restore 直後は headend しか prune されず、local SID と広告は届かないまま
残ります (既知の限界の節)。つまり restore を跨いだ scope の縮小は、いまは
headend に対してだけ認可の失効として働きます。

manifest の format version は 2 です。scope は認可情報なので、scope を持たない
version 1 の manifest (scope 導入前の build が書いたもの) を空 scope で restore
すると、その plugin が書いた転送状態を boot 時に消してしまいます。そこで version 1 は
restore を拒否し、状態を pinned のまま残して plugin を unrestored に落とします。
この機構は未リリースなので migration は用意せず、plugin store をクリーンにしての
起動を upgrade の前提とします。behavior claim は version に関係なく予約するので、
その codepoint の経路は built-in に渡らず withhold されます。

prune に失敗したら登録も失敗させます。成功を返すと、実際には効いていない認可
境界が効いていると言うことになるためです。このとき store と claim と registry が
食い違わないよう、1 つの結末に揃えます。新しい登録を persist するので、再起動時の
restore が prune を再試行し、広い scope へ戻りません。behavior claim は新しい集合の
まま残します。plugin は死んでも書いた状態は map に残るので、その codepoint の
経路は built-in applier へ渡さず withhold し続けます。plugin は running registry から
外して unrestored に記録するので、running と unrestored に二重に載らず、operator は
`forget` で諦められます。

### data plane 境界と aux

plugin の local SID の aux (`aux_raw`) は plugin が並べた bytes で、`sid_aux_entry`
という union に載ります。この union は SID の action で判別され、built-in behavior は
自分の variant として読みます。End.DT4 は先頭 4 byte を VRF ifindex として読み、
End.B6 は segment list 全体を読みます。plugin の data plane half は任意の built-in
slot へ tail call できるので、そのまま渡すと built-in が plugin の bytes を自分の
layout として解釈し、scope の VRF grant を破って任意の VRF へ decap できます。

そこで built-in の aux 参照を分けます。built-in 用の lookup は、処理中の SID の
action が plugin slot 域 (endpoint なら 32 以上) なら aux を NULL にします。plugin の
handoff で built-in に入ったときは aux を読みません。plugin が自分の program で
自分の aux を読む経路はそのままなので、plugin の aux は plugin だけが解釈します。

aux を NULL にすると built-in End.DT4/DT6/DT46 は VRF ifindex を失うので、その VRF を
host が別に渡します。plugin が制御する aux を再び信頼するのではなく、host が書き
全 program から read-only な (`BPF_F_RDONLY_PROG`) 専用の grant map
`plugin_endt_vrf_map` を用意し、そこから VRF を引きます。key は dispatch entry の
aux index で、両路 (SRH 有りと reduced-encap) で `tailcall_ctx` から取れます。control
plane は decap_vrf を持つ plugin の local SID に必ず非ゼロの aux index を確保し、VRF 名を
kernel の L3 device ifindex に解決して `{ifindex}` を grant map へ書き、SID の解放で
消します。grant が無ければ built-in decap は ingress table へ暗黙に fallback せず明示的に
drop します。暗黙 fallback は ingress table に偶然一致する経路があると意図しない routing
domain へ転送しうる曖昧な挙動なので、fail-closed にします。plugin ELF は kernel が
`BPF_F_RDONLY_PROG` で書き込みを構造的に拒むので、`checkROWrites` の best-effort より
強く grant を偽造できません。decap_vrf は plugin の scope の VRF 集合に含まれること
(advertise と同じ集合) を host が確かめます。

grant の書き込みと VRF 削除は 1 本の leaf lock を共有します。plugin の local SID
install は VRF 名を ifindex へ解決してから grant を書くまでこの lock を持ち、VrfDelete
は grant 参照チェックから kernel device teardown までを同じ lock で囲みます。これで grant
が解放中の ifindex を指すことがなくなります。install が先なら VrfDelete のチェックが
grant を見て削除を拒み、VrfDelete が先なら device が消えて install の解決が失敗します。
この lock は最内側でだけ取り、内側では VRF manager 自身の lock と BPF map しか触らないので
applyMu や VRF mutation mutex と deadlock しません。VRF mutation mutex をそのまま grant lock に
流用すると deadlock します。binding 更新は mutation mutex を持ったまま `ReconcileAdvertised`
で applyMu を取り (mutation mutex から applyMu)、plugin install は applyMu を持ったまま
mutation mutex を取る (applyMu から mutation mutex) ので、この 2 経路が逆順になるからです。
VrfDelete 自身は applyMu を取りませんが mutation mutex を binding 側と共有するため、流用すれば
同じ輪に巻き込まれます。専用の leaf lock はこの逆転に関与しないので安全に閉じられます。
install 側の resolve は manager の記録に加えて kernel の device 実在も照合します。teardown が
netlink まで済んで state の persist だけ失敗した VrfDelete は error を返して manager に旧記録を
残すので、manager だけを信じると解放済み ifindex へ grant を書けてしまうためです。

この lock が閉じるのは 1 つの daemon run の中の窓です。daemon 再起動をまたぐと pinned map の
grant は残り、再起動後に VRF device が作り直されて ifindex が変わっていれば古い grant は stale な
番号を指します。これは owner plugin の最初の Apply の sweep で dispatch entry ごと回収されるまで
続き、その間は ifindex-keyed な参照が持つ従来どおりの残余 (dead ifindex への fib-lookup miss で
drop) に留まります。起動時に grant map を kernel と突き合わせて刈る reconcile は今後の課題です。

この判別は `tailcall_ctx_map` の `sid_entry.action` を読むので、plugin がその map を
書けると action を偽造して判別を欺けます。共有 map は MapReplacements で plugin に
渡す都合上 kernel から見れば RW で、`tailcall_ctx_map` は vinbero 自身が packet ごと
書くため `BPF_F_RDONLY_PROG` にもできません。よって plugin の書き込みを止めるのは
ELF の静的検査 (`checkROWrites`) です。判別と scope が信頼する map (`tailcall_ctx_map`
`sid_aux_map` `sid_function_map` と dispatch PROG_ARRAY) への書き込みは、migration 対象の
RO map と違って `ro_enforce=warn` でも downgrade せず常に fatal にします。検査は entry
body だけでなく到達する subprogram も走査し、map pointer への定数・register 加算でも
map identity を保つので、offset や noinline helper で書き込みを隠せません。map を書くのは
store 命令だけではないので、`bpf_map_update_elem` / `bpf_map_delete_elem` などの map 変更
helper も第一引数の map provenance で検査します。entry body で解決できない書き込みは
integrity map でないと証明できないため fail-closed で fatal にします。

ここで plugin ELF の trust model を明示します。plugin ELF は operator が install し
review する semi-trusted な artifact として扱い、`checkROWrites` は accidental な誤用の
検出であって、敵対的 ELF に対する sandbox ではありません。map value pointer を stack に
spill して reload する、あるいは call 引数として渡し callee 内で書く形は register
provenance が切れ、subprogram 内では正当な helper (epilogue の slot_stats_inc が引数の
map pointer を書く) との誤検知を避けるため素通ります。これを完全に塞ぐには
inter-procedural / stack-slot の provenance 追跡が要り、既知の限界として別途扱います。
つまり scope 認可のうち、WASM の desired set 側は host が強制しますが、ELF data plane 側は
semi-trusted 前提の best-effort です。第三者や tenant 提供の ELF を許す運用に広げる場合は、
integrity map を plugin から参照させない host-owned な grant map など構造的な隔離が要ります。

## claim と built-in state の関係

claim は demux が経路を配る先を決める述語なので、claim が立つ前に届いた
経路は built-in applier が処理してしまいます。built-in は service SID を
behavior を読まずに解釈するため、plugin 用の codepoint を持つ経路も普通の
service SID として自分の owner で install します。plugin が同じ prefix に
書こうとすると owner が衝突して弾かれます。

そこで claim の取得と解放を、経路の流れと突き合わせます。

- 起動時は、store にある plugin の behavior を demux の start より前に予約
  します。start は rib の replay を伴うので、予約が後だと必ずこの窓に入り
  ます。restore に失敗した plugin の claim は保持します。Register 自身は
  失敗時に claim を巻き戻しますが、これは operator の登録に対して正しい
  挙動で、restore は事情が違います。予約は「実装するものが無い codepoint の
  経路を built-in に渡さない」ために取ったものなので、巻き戻しをそのままに
  すると誤った意味での install に戻ります。
- claim 取得後の retract は、plugin が build されて subscribe まで済んでから
  行います。retract は元に戻せない副作用なので、admission で弾かれた module の
  ために既存の経路を built-in から消してしまうと、実装するものが無いまま
  取り残されます。
- unregister では owner の状態の flush が成功してから claim を解放します
  (lifecycle の節)。解放は取得と対称ではありません。取得時は rib を遡って
  built-in から withdraw しますが、解放時に rib を built-in へ流し直すことは
  しません。解放後に届く advertise は built-in に配られ、素の service SID と
  して扱われます。flush が先なので、claim が防いでいた owner 衝突 -- plugin の
  書き込みと built-in の install が同じ prefix を奪い合い、誤った意味の entry が
  traffic を運び続けること -- は起きません。ただし flush が保証するのは衝突が
  無いことまでです。built-in が作るのは既定の単一 SID の H.Encaps で、plugin が
  headend で宣言していたかもしれない mode や segment list や source は再現され
  ません。unregister 後の churn で入る entry は旧 plugin のものと転送の形が違い
  得るという運用上の条件は残ります。rib に残っている経路は次に churn したときに
  built-in へ渡ります。
- 取得・解放・restore 失敗の扱いは 1 つの不変条件の面です。claim の寿命は
  plugin の状態の寿命に合わせます。状態が map にある間はその codepoint の
  経路を built-in に渡さず (restore 失敗で claim を保持するのはこのため)、
  状態が消えた後は普通の経路に戻します (unregister が flush の後に解放する
  のはこのため)。この対応が破れる場合と operator の対処は、節末の表に
  まとめます。
- restore に失敗した plugin の claim は解放しません。解放すると built-in が
  実装できない codepoint の経路を service SID として install してしまいます。
  黙って誤った転送をするより、operator が直すまで転送されない方がましです。
  claim を保持したことは warning に出します。restore に失敗した plugin は
  `vbctl plugin cplane stats` に別枠で出します。動いていないのに daemon は
  その state と claim を持ち続けるので、running な plugin だけを見せると
  「単に居ない」ようにしか見えません。戻ってこないと判断したら
  `vbctl plugin cplane forget` で claim と store の登録を落とせます。map に
  残った state には触れません。それが何のためのものかを daemon は知らない
  ためです。

- claim を取った時点で、rib の中にその behavior を持つ経路があれば、
  built-in applier に withdraw として配り直します。claim は本来これから
  届く経路の行き先しか決めませんが、先に届いた経路は既に built-in が
  service SID として自分の owner で install しており、plugin が同じ prefix
  に書こうとしても owner が衝突して弾かれます。残るのは誤った意味の entry で、
  それがトラフィックを運びます。withdraw は applier が普段から扱う経路なので、
  それぞれが何をどう保持しているかを demux 側が知る必要はありません。claim は
  plugin を build する前に取るので、最初の宣言時には prefix が空いています。
  この配り直しは withdrawal ledger には記録しません。記録すると後から来る
  本物の withdraw を処理済みと誤判定します。

### 保証と破れと対処

上の散文を、保証されること・破れる場合・operator の対処の 3 列に
まとめ直します。

| 保証されること | 破れる場合 | operator の対処 |
|---|---|---|
| 起動時は store にある behavior claim を demux の start より前に予約する。restore に失敗しても claim を保持し、実装するものが無い codepoint の経路を built-in に渡さず withhold する。 | restore 失敗そのものではこの保証は破れない。 | warning と stats の unrestored 枠を確認する。復旧させないなら forget で claim と store を落とし、map の残存 state は operator が引き受ける。 |
| claim 取得後の retract は plugin の build と subscribe が済んでから行い、rib にある対象 behavior の経路を built-in から withdraw して最初の宣言より前に prefix を空ける。 | admission など publish 前に失敗した module では retract を行わない。元に戻せない副作用だけが残ることを防ぐ。 | 不要。 |
| unregister は owner state の flush が成功してから claim を解放する。flush が失敗した場合は claim と store を保持し、plugin を registry に dead として戻す。 | flush は面ごとに進み部分削除を rollback しない。また built-in が後から作るのは既定の単一 SID の H.Encaps で、plugin が宣言していた mode や segment list や source は再現されない。 | flush 失敗は unregister を retry する。unregister 後の churn で転送の形が変わり得ることは運用条件として扱う。 |
| upgrade は behavior claim を新しい集合へ 1 回で置換し、途中で別の plugin に codepoint を取られて巻き戻せなくなる形を避ける。publish 前の失敗は前の集合へ戻す。 | behavior を減らす upgrade では、外した codepoint の claim が旧 state の reconcile より先に返り、その間に届いた経路は built-in に渡る。 | 窓を避けたい場合は unregister で flush してから新しい集合で登録し直す。address は取り直しになる。 |
| 通常の unregister は in-memory の inventory から owner state を flush してから claim を返す。 | daemon 再起動直後、plugin が local SID を宣言し直す前に unregister すると、前の run の pinned dispatch entry が flush の視界に入らず、残したまま claim が解放される。 | plugin owner の entry は SID 削除 RPC の owner 検査が拒み、force-delete の RPC も無いので、operator が消す手段はいま無い。残存を確認したら、その slot と locator を再利用しないでおく。owner ごとの inventory から flush する形は繰越し。 |
| manifest と state が揃っていれば、再起動時にも claim を予約して pinned state と built-in の対応を保つ。 | 新規登録や behavior を足す upgrade が manifest の rename 前に persist で失敗すると、その run は instance と claim と state を持って動くが、再起動時は manifest が無いので claim が予約されず、pinned state の codepoint が built-in へ流れる。 | persist 失敗の error を受けたら、登録を retry して manifest を揃えるか、unregister で state ごと flush する。 |
| claim の寿命は plugin の状態の寿命に合わせる、が全体の不変条件である。 | forget は operator が明示的にこの対応を破る操作で、daemon が消し方を知らない状態を残したまま claim と予約を返す。 | 残存 state を確認し、force-delete の経路が入るまでは返された slot と locator を再利用しない。以後の残存 state は operator が引き受ける (既知の限界の節)。 |

## 広告の所有権

lease は plugin どうしの所有権を調停します。その下にもう 1 枚あり、gobgp
session は 1 つの NLRI につき local path を 1 本しか持たないので、経路を
出した producer を記録します。plugin ごとに別の producer 名を与えるので、
lease と producer は失敗の仕方が違います。lease 衝突は何も送る前に拒否され、
producer 衝突は誤って lease を手放したときに他の plugin の経路を守ります。

session は auto-advertise の exporter や operator の RPC とも共有なので、
vinbero 自身の originator にも producer 名を与えています。exporter は
`vinbero:export`、operator の RPC は `vinbero:operator` です。片方が routing
table に従って出す経路で、もう片方は operator が明示的に頼んだ経路なので、
同じ名前にすると後から出した方が黙って上書きし、上書きされた側は広告中の
つもりのまま残ります。plugin の producer 名は owner tag なので、`vinbero:`
前置と衝突しません。

producer 名を持つ view は、名前を載せられる surface だけを提供します。
session を embed すると EVPN と MUP と SR Policy の interface も満たして
しまい、それらの method は producer を運ばないので無名で書きます。compiler
は黙って通すので、embed しない形にしています。

session 側で producer を記録し、withdraw は自分が出した経路にしか効かない
ようにしています。これが無いと、後から届いた withdraw が別の producer の
生きた経路を消し、消された側は広告し続けているつもりのままになります。

重複した advertise も拒否します。1 NLRI に 1 path しか無いので、上書きは
先に出した producer の UUID を捨てることになり、後から出した側が withdraw
すると経路自体が消えるのに、先に出した側は広告中のつもりで戻しません。
先に出した方が保持し、拒否された側には理由を返します。

## 既知の限界

reconcile は owner の現在の集合を map の全走査で求めます。lease 表は同じ
情報を持っているので置き換えられますが、置き換えていません。全走査は
lease と entry がずれたときにそれを捕まえる唯一の場所でもあり、本設計の
review で実際に見つかった不具合はどれもそのずれでした。速さのために backstop
を外す判断は、いまの証拠と逆を向いています。

その結果、reconcile の時間は map の大きさに比例します。reconcile は plugin
をまたいで applyMu で直列化され、guest の call budget は host を待つ時間も
数えるので、大きな map と多数の plugin が揃うと、隣の plugin の reconcile を
待つ間に自分の budget が尽きて instance を失うことがあります。budget 超過は
instance を作り直して収束するので転送は保たれますが、隔離としては不完全です。
map が大きい環境で plugin を多数動かす場合は、call budget を map の規模に
見合う値に上げてください。

binding の `MaxPrefixes` は、plugin の広告と auto-advertise の広告を別々に
数えます。exporter の経路数は `pkg/bgp/export` の側にあってここからは見えない
ためで、両方が動く VRF はそれぞれの上限まで持てます。

EVPN と MUP と SR Policy の advertise は producer 名を持ちません。SR Policy と
MUP は書き手が 1 つしか無いので分けるものがありませんが、EVPN は
auto-advertise の exporter と operator の RPC の 2 つがあり、いまは同じ無名の
producer です。さらに EVPN の withdraw は producer を見ずに path を消すので、
名前を付けるだけでは足りず withdraw 側の作り直しが要ります。別の変更として
残しています。

conformance harness は scope のうち daemon 無しで判定できる部分だけを見ます。
prefix が locator に含まれるかと、VRF に binding があるかは daemon の状態に
依存するので harness では判定しません。harness には scope を operator と同じ
文字列の形で渡し、`ParseScope` を通します。daemon が拒否する scope (4-in-6 の
prefix や範囲外の slot) は harness でも拒否され、harness が daemon より緩くなる
のを防ぎます。

restore-time の prune は headend map しか読みません。`LiveSIDs` と `LiveRoutes` は
in-memory の集合を読むので、再起動直後は空で、前の run が確保した local SID や
広告経路は prune の視界に入らず orphan になります。local SID は plugin が次に
local SID を宣言したときの sweep で片付きますが、scope を狭められた plugin は
その宣言をしなくなるので、それまで残ります。map から owner ごとに読む形へ広げるのは
繰越しです。

どの surface がどこで追跡され、prune と flush のどこから見えるかをまとめます。

| surface | 追跡場所 | restore 直後の prune | 再登録の prune | unregister の flush |
|---|---|---|---|---|
| headend | BPF map。owner ごとに全走査する | 見える。restore-time prune が扱える唯一の surface | 見える | 見える。広告と local SID の後に消し、失敗した entry と lease は残る |
| local SID | in-memory の live 集合。dispatch entry 自体は pinned map に残り得る | 見えない。再起動直後は空で、前の run の entry は次の宣言時の sweep まで残る | 見える | 通常は見える。restore 直後で再宣言前の pinned entry だけ視界に入らない |
| 広告 | in-memory の live 集合。wire の所有は gobgp session の producer が追跡する | 見えない。再起動直後は空で、wire 側も session ごと消えている | 見える | 見える。最初に withdraw する |
| behavior claim | demux の claim registry。withdraw の判定は path 単位の ledger も使う | prune の対象外。起動時に manifest から demux start より先に予約する | prune の対象外。upgrade は instantiate より前に新集合へ置換する | flush の対象外。flush 成功後に解放する |
| lease | in-memory の lease table。per-entry の owner map が最終 enforcement | headend の owner 走査からは見え、local SID と広告の分は見えない | owner state と一緒に見え、prune に伴って減る | owner state と一緒に消える。消せなかった entry の lease は残す |

forget は claim と store と slot / locator の予約を返しますが、map の状態は
残します。daemon はそれが何のためのものかを知らないためです。返った slot を
別の plugin に渡すと、残った dispatch entry の SID がその新しい program へ
dispatch し、新 program は旧 plugin の aux bytes を自分の layout として読み
ます。予約が防いでいた取り違えを forget は operator の判断で外すことになり
ますが、plugin owner の entry は SID 削除 RPC の owner 検査が拒み、force-delete
の RPC も公開していないので、operator に消す手段がいまはありません。できるのは
残存 state を確認して、その slot と locator を再利用しないでおくことだけです。
owner ごとの inventory から強制的に片付ける形と force-delete 経路は繰越しです。

control plane half と data plane half は機構としては結ばれていません。同一
plugin であることの照合も、slot に program が載っているかの readiness 確認も、
upgrade の順序の強制もありません。前提は operator の導入順序で、data plane
half を slot に register してから、その slot を scope に指定して control plane
half を register します。逆順や片方だけの更新では、SID の確保と広告が成功して
いるのに slot に受け手が居らず、traffic が落ちる期間ができます。scope の slot
排他が防ぐのは別の plugin との取り違えで、同名の 2 half の版ずれは防ぎません。
identity と readiness を結ぶ機構は今後の課題です。

## 登録時の検証

module は allowlist で検証します。

- import は `vinbero` module からのみ。WASI はこの規則で弾かれます。
- memory は guest が定義して export する 1 つだけ。imported memory は拒否。
- 必須 export が signature まで一致すること。
- ABI version が一致すること。
- `_start` の自動実行は無効化し、reactor initializer だけを host が明示的
  に呼びます。

capability と scope の食い違いも登録時に弾きます。食い違いとは、scope を
一部だけ宣言しながら、granted した capability が書き先を決めるのに要る対象を
欠いた組のことです。locator だけ並べて `headend` を granted した登録がそれで、
plugin が動いて宣言し、その宣言が全部拒否されるという形で失敗します。壊れた
plugin のように見えるので、operator の手元で断ります。scope を丸ごと宣言
しない登録は食い違いではありません。空の scope は意図的な deny-all で、
capability が何であれ観測と log だけをする plugin として起動します
(scope の節)。弾くのは中途半端な scope だけです。

## lifecycle

- 同名での再登録は in-place upgrade です。古い instance を止めて新しい
  ものを同じ owner tag で始めるので、古いものが書いた状態は残り、新しい
  module が宣言し直して差分が吸収されます。
- plugin が configure から宣言した内容は、登録が成立するまで保留します。
  configure は instantiate の途中で走るので、そこで適用すると instantiate
  が失敗したときに誰も消せない state が残ります。upgrade では更に悪く、
  失敗した新 instance は走行中の旧 instance と同じ owner tag を持つので、
  その宣言が生きている plugin の entry を prune します。
- unregister は意図的な撤去なので owner の状態ごと消します。順序は配送
  停止、instance close、状態削除です。
- trap や budget 超過では状態を消しません。instance を作り直し、rib の
  snapshot を配ってから収束させます。新しい instance は何も覚えていない
  ので、replay しないと最初の宣言が restart 後に届いた event だけの集合に
  なり、それ以外の entry を全部 prune します。連続失敗が上限を超えたら
  状態を残して止めます。上限は連続失敗の数で、成功配送でリセットします。
  止めた後の広告と headend は fail-static で、以後の network の変化を映し
  ません。短時間の障害では撤去より安全ですが、長く放置すると古い経路を
  広告し続けることになります。この判断は daemon が下せないので operator に
  返します。止まった plugin は stats に出るので、戻さないと決めたら
  unregister が広告ごと撤去します。停止からの経過で広告だけ落とすような
  自動の段階的撤去は入れていません。
- daemon の shutdown では flush しません。
- unregister は flush が成功してから claim と store を手放します。先に
  手放すと、flush が失敗したときに retry する手段が無くなります。claim を
  先に返せば plugin の state が残ったまま経路が built-in に戻り、store を
  先に消せば再起動しても後始末をする plugin 自体が居なくなります。flush が
  失敗した plugin は registry に戻すので、operator が retry できます。
- upgrade は、走っている plugin に触る前に subscribe まで済ませます。
  subscribe が失敗する可能性がある間に旧 instance を止めると、demux に
  断られただけでどちらの版も登録されていない状態になり、閉じた旧
  instance は復元できません。subscribe から旧 instance の停止までの間は
  同じ名前に 2 つの subscription がありますが、handler は名前で plugin を
  引くので配送先は 1 つで、重複した event は desired set が吸収します。
- instance の入れ替えでは、instance に属する状態を作り直します。宣言した
  SID の address を伝えたかどうかの記録がそれで、引き継ぐと交代した
  instance は自分の持つ SID を知らないまま広告できなくなります。publication
  も同じで、交代中の宣言は保留し、instantiate が失敗したら適用しません。
  これが無いと、起動に失敗した instance の空宣言が前の instance の state を
  prune したまま残ります。
- 宣言には commit 順の番号を振り、同じ kind でより新しい宣言が適用済みなら
  古い方は適用しません。宣言は集合そのものの宣言なので、retry や staged の
  drain で古い集合が新しい集合を上書きするのを防ぎます。
- publication は worker が end of replay を正常に処理し終えた後に行います。
  snapshot 対応の source では登録時の replay の有無によらず manager 自身の
  snapshot を使います。guest call が成功して status だけが不正な場合は、
  status を警告として無視し、replay の完了は有効とします。
  queue に積み終えた時点では適用しません。旧 instance 向けの完了通知では
  新 instance の宣言を公開できません。宣言はそれまで保留されるので、
  最初に適用される宣言は queue にたまたま入っていた event ではなく network
  全体を述べたものになります。desired set を宣言する plugin にとって、この
  違いは収束するか自分の持ち物を全部 prune するかの違いです。
- publication 前に同じ kind を何度 commit しても、保持するのは最新の集合
  だけです。open transaction と各集合の entry 数と byte 数の制限に加えて、
  staged の保持数も kind 数に制限されます。instance が替わると以前の pending
  宣言も破棄し、replay 前に旧 instance の宣言を retry することはありません。
- 公開前に宣言され、公開時に適用できなかった transaction は捨てずに保持し、
  次の配送の前に再試行します。保留されている数は stats に出し、最初の失敗は
  warning に出します。何かを待っている plugin は、配送の counter だけ見ると
  暇な plugin と区別が付きません。restore された plugin は daemon の起動途中に
  configure から宣言するので、operator が後から RPC で登録する locator を
  名指しした宣言はその時点では失敗します。plugin は言うべきことを既に言い
  終えているため、再試行が無いと SID と広告が restart から戻りません。

wazero に fuel metering はありません。走っている guest を止める手段は
context の cancel だけで、それは module を閉じます。よって budget 超過は
call ではなく instance を失います。budget を call 単位にしているのはその
ためです。

instantiate 自体も同じ budget の下で走らせます。WebAssembly の start
section は spec 上 instantiate 中に実行されるので、これも guest の code
です。budget を掛けないと、start section で無限 loop する module が登録を
永久に止め、operator の RPC が返りません。

各遷移で plugin の持ち物がどうなるかをまとめます。map の状態には lease も
含みます。lease は owner の状態と一緒に増減するためです。表は各遷移が成功
したときの姿で、部分失敗で残る形は表の後にまとめます。

| 遷移 | behavior claim | store | running registry | map の状態と広告 |
|---|---|---|---|---|
| register (新規) | 取得。instantiate 前の失敗では巻き戻す | 成立後に persist | 追加 | 宣言に従って作る |
| restore 成功 | 起動時の予約のまま | 保持 | 追加 | map は pinned のまま、replay 後の宣言が差分を吸収。広告は宣言で作り直す |
| restore 失敗 | 保持 (withhold 継続) | 保持 | publish 前の失敗は載せず unrestored に記録。publish 後の persist 失敗は動いたまま unrestored にも載る (下記) | prune 前の失敗は触らない。prune まで進んだ失敗は削除できた分だけ減る。slot と locator の予約は manifest から scope が読めた分だけ残る |
| upgrade (同名再登録) | 新しい集合に置換。外した codepoint は旧 state の reconcile より先に返る | 更新 | instance を入れ替え (owner tag は同一) | 残したまま新 module の宣言が差分を吸収 |
| unregister | flush 成功後に解放 | flush 成功後に削除を試みる。失敗は warning で unregister は成功のまま | 削除。flush 失敗時は戻す | owner の状態を削除し広告を withdraw |
| forget (未走行のみ) | 解放 | 削除 | unrestored から削除 | 触らない。slot と locator の予約は返る |

部分失敗はそれぞれ次の形で残ります。

- register と upgrade の instantiate 前の失敗 (claim 衝突、検証、admission) は
  claim を巻き戻して何も残しません。publish の後の persist 失敗は違います。
  instance は動いていて claim も新しい集合のまま、error だけが返ります。
  restart に何が見えるかは失敗の段階次第です。manifest の rename 前に失敗
  すれば store は未更新のままで、新規登録は restart を生き残らず、upgrade は
  旧版に戻ります。rename 後の directory sync で失敗した場合、新版の manifest は
  現在の namespace には見えているので daemon の再起動は新版を restore します。
  ただし durability を確立する処理そのものが失敗しているので、machine の
  crash を挟むとどちらの版が見えるかは保証されません。scope prune の失敗は
  claim を新しい集合のまま plugin を unrestored に落とします
  (scope を狭めたときの節)。restore の途中でこの persist 失敗を踏むと、
  plugin は publish 済みで動いているのに、restore は Register の error を
  一律に restore 失敗として記録するので、running と unrestored の両方に
  同じ plugin が見えます。実害は表示の混乱に留まり、Forget は running の
  plugin を拒むので状態は壊れませんが、二重表示の解消は繰越しです。
- restore と再登録の prune は面ごと・entry ごとに進み、途中の失敗を
  rollback しません。prune で失敗した restore の map は「触らない」では
  なく、削除できた分だけ減った状態で残ります。
- unregister の flush は広告の withdraw、local SID、headend の順に進み、
  失敗した面を飛ばして残りも試みます。消せなかった分は lease ごと残り、
  rollback はしません。plugin は registry に dead として戻るので operator が
  retry できます。flush 成功後の store 削除の失敗は warning に留めます。
  削除は manifest、module、directory の sync の順に進むので、どの段階で
  失敗したかで結果が分かれます。manifest の unlink 前なら restart が
  plugin を持ち帰り (状態は flush 済みなので空から再開するだけです)、
  unlink 後なら restart には既に見えません。
- forget は claim を解放してから store を消すので、store 削除が失敗すると
  error を返しつつ claim だけが先に失われます。unrestored の記録と slot /
  locator の予約と map の状態は残ります。store 側は失敗の段階次第で、
  manifest の unlink 前なら丸ごと残り、unlink 後なら restart が読む
  manifest は既にありません。

### 状態遷移図

ここまでの遷移と部分失敗を 1 つの状態機械にまとめます。各状態が manifest と
registry と claim をどう持つかは図の下の凡例に書きます。

```mermaid
stateDiagram-v2
    state "未登録" as Absent
    state "保存済み未起動" as Stored
    state "稼働中" as Running
    state "稼働中 persist 未確立" as VolatileRunning
    state "fail-static で停止" as Dead
    state "restore 失敗" as Unrestored
    state "稼働中かつ unrestored 表示" as RunningUnrestored
    state "flush 済み manifest 残存" as FlushedStored
    state "forget 後の残存 state" as Forgotten
    state "forget 部分失敗" as ForgetPartial
    state "claim 予約なしの pinned state" as Orphaned

    [*] --> Absent

    Absent --> Running: register 成功
    Absent --> Absent: publish 前の失敗は claim を巻き戻す
    Absent --> VolatileRunning: publish 後の persist 失敗

    Running --> Running: upgrade 成功。owner tag を保って instance 交換
    Running --> Running: upgrade の publish 前失敗。claim を前の集合へ戻し旧 instance を維持
    Running --> VolatileRunning: upgrade の publish 後 persist 失敗
    Running --> Running: trap や budget 超過。instance を作り直し snapshot から収束
    Running --> Dead: 連続失敗が上限を超え fail-static
    Running --> Dead: instance の作り直し自体に失敗。上限を待たず fail-static
    Running --> Stored: daemon shutdown。flush しない
    Running --> Absent: unregister。flush 成功
    Running --> FlushedStored: unregister。flush 成功後の store 削除失敗
    Running --> Dead: unregister の flush 失敗。dead として registry に戻す

    Dead --> Stored: daemon restart。manifest から再試行
    Dead --> Absent: unregister の retry 成功
    Dead --> Dead: retry の flush 失敗。部分削除は rollback しない

    Stored --> Running: restore 成功
    Stored --> Unrestored: restore の publish 前失敗
    Stored --> RunningUnrestored: restore の publish 後 persist 失敗

    Unrestored --> Running: 再登録または次回 restore の成功で unrestored を消す
    Unrestored --> Forgotten: forget 成功。claim と store と slot / locator の予約を解放
    Unrestored --> ForgetPartial: forget の途中失敗。claim だけ先に失う

    RunningUnrestored --> Running: 登録の retry 成功で unrestored を消す
    RunningUnrestored --> RunningUnrestored: forget は running のため拒否

    FlushedStored --> Running: 次回起動の restore。空の state から再開

    VolatileRunning --> Running: 登録の retry で manifest を揃える
    VolatileRunning --> Stored: daemon restart で残った版の manifest を読む
    VolatileRunning --> Orphaned: daemon restart で manifest が見えない
    VolatileRunning --> Absent: unregister。flush 成功
```

非自明な状態の中身は次のとおりです。

- 稼働中 persist 未確立は、publish 後の persist 失敗のまま動いている状態です。
  instance と claim と state はこの run にありますが、store の manifest は
  無いか旧版か durability 未確立の新版で、restart に何が見えるかは失敗の
  段階次第です。
- claim 予約なしの pinned state は、その restart で manifest が見えなかった
  結末です。pinned state だけが残り、claim が予約されないのでその codepoint の
  経路は built-in へ流れます。不変条件の表の persist 失敗の行が対処です。
- flush 済み manifest 残存は、unregister の flush が成功した後に store 削除
  だけ失敗し、かつ manifest の unlink 前だった状態です。restart は空の
  state で plugin を持ち帰ります。unlink 後の失敗なら manifest は無いので
  未登録と同じです。
- forget 部分失敗は claim だけ先に失われた状態で、unrestored の記録と slot /
  locator の予約と map の状態は残ります。

restore 中に publish 後の persist 失敗が起きたときの二重表示は、instance が
動いたまま restore 側が一律に失敗を記録するためです。実害は表示の混乱に
限られ、forget は running の plugin を拒みます。

## 運用

```sh
vbctl plugin cplane register --name custom-behavior --wasm plugin.wasm \
    --behavior 0xFE01 --family vpnv4 \
    --capability headend --capability advertise --capability local_sid \
    --locator main --vrf vpn-a \
    --headend-prefix 10.7.0.0/16 --endpoint-slot 33
vbctl plugin cplane list
vbctl plugin cplane stats
vbctl plugin cplane unregister --name custom-behavior
```

capability と scope はどちらも省略できますが、片方でも欠けた plugin は何も
宣言できません。observe と log しかしない plugin はそれで正しく、宣言する
plugin には両方を与えます。`stats` は動いている plugin と、restore に失敗して
claim だけ残っている plugin の両方を出し、scope は本体の表とは別の block に
出します。後者は `vbctl plugin cplane forget --name <plugin>` で落とせます。

behavior は 10 進でも 0x 前置でも書けます。RFC 8986 は codepoint を hex で
振っているので、0x0013 を 10 進の 13 と読むと別の behavior を claim して
しまいます。

## plugin を書く

例は `sdk/examples/cplane-custom-behavior` にあります。TinyGo で書いて
います。生成された Go binding は reflection を要求し、TinyGo の WebAssembly
target はそれを持たないので、protobuf codec は手書きです。

daemon 無しで試すための harness が `sdk/go/cplaneharness` にあります。
daemon と同じ runtime を回し、capability 面だけ記録用に差し替えます。
replay、restart、commit 拒否といった本番で耐える必要のある流れを method
として提供します。

TinyGo は次の flag で使えます。

```sh
tinygo build -o plugin.wasm -target=wasm-unknown \
    -scheduler=none -gc=conservative -panic=trap -no-debug .
```

`-no-debug` は artifact を再現可能にします。付けないと TinyGo が絶対 path を
DWARF に埋めるので、同じ source から作った .wasm が machine ごとに変わり、
committed の artifact と source が一致しているかを CI で見られなくなります。

`gc=conservative` は必須です。WASI を link しない target の既定は
`gc=leaking` で memory を一切回収しません。control plane plugin は daemon
と同じ寿命で走り、ネットワークの経路変化を全部見るので、回収しない
plugin は memory 上限に到達します。harness の churn test は live set を
一定に保ったまま advertise と withdraw を繰り返すので、増える分は garbage
だけです。この test を leaking build は途中で落ち、conservative build は
1 MiB のまま完走します。

## local SID と daemon 再起動

local SID の名前は host の memory にしかありません。pin された map では
前回起動の entry が残りますが、どの宣言がその address を入れたのかを
辿る手段がありません。同じ名前を宣言し直した plugin に同じ address が
戻る保証は無く、別の address になった古い entry は誰も dispatch せず
誰も消せないまま残ります。

そこで owner ごとに 1 回だけ sweep します。その owner のもので、今回の
run が入れたのではない entry を消します。address の安定性は 1 回の daemon
実行の中では保たれ、再起動を跨ぐと保証されません。allocator は空から
作り直すので、割り当ての順が同じなら偶然同じ address が戻ることもあり、
それを当てにはできません。

## まだ無いもの

EVPN と MUP の desired set は実装していません。用途が先に無いという理由
だけでなく、前提が揃っていないためです。

MUP の uplink map (`mup_uplink_v{4,6}_map`) の entry は owner tag を持ち
ません。packet が運ぶ F-TEID が key なので、そういう設計になっています。
owner が無い store では、どの entry が誰のものかを reconcile が判定でき
ません。plugin に触らせる前に owner 追跡を足す必要があります。

EVPN は owner の問題は無いものの、bd_peer と FDB の状態は DF election、
split-horizon、ESI の不変条件と組で成り立っています。plugin が entry を
直接宣言できるようにすると、その不変条件を壊す形の宣言が書けてしまいます。
DF election のような判断ロジックそのものの差し替えは本設計の非目標に置いて
あり、EVPN の desired set はその判断と不可分です。用途が具体化したときに、
何を宣言させるのが安全かを決めてから足します。

## 開発の進め方

この機構は `feature/cplane-plugin` に積んで育てます。main には直接入れず、
まとまった時点で feature branch から main への PR を別に立てて判断します。

初回投入は 3 本の stack に割ってあります。1 本にすると 18.8k 行になり、
Copilot が行数上限でレビューできないためです。以後の追加も、レビューを
受けられる大きさに割って feature branch を base にします。

| branch | 内容 |
|---|---|
| `cplane-plugin-1-foundation` | BGP demux と behavior claim の土台 |
| `cplane-plugin-2-runtime` | WASM runtime と desired-set apply |
| `cplane-plugin-phase-a` | advertise / local SID / capability / quota / interop |
| `cplane-plugin-b1` | scope / vinbero 自身の producer 分離 / eBPF half を持つ interop |

次に足す候補は次のとおりです。

- EVPN と MUP の desired set (上記の前提を揃えてから)。
- Rust の SDK shim。
- EVPN advertise の producer 分離。exporter と operator の RPC の 2 つの書き手が
  あるのに無名の producer を共有しています。EVPN の withdraw は producer を
  見ずに path を消すので、名前を付けるだけでは足りません。
- restore-time prune の local SID / 広告への拡張。いまは map から読める headend
  しか片付けられません。
- binding 再導出を RPC の critical section の外へ出し、retry と counter を足す。
  いま commitBinding は共有 mutex を握ったまま全 plugin の経路を再広告し、失敗は
  log するだけです。
- 起動時に decap-grant map を kernel と突き合わせて stale な grant を刈る
  reconcile (data plane 境界の節)。
- control plane half と data plane half の identity と readiness の結合
  (既知の限界の節)。
- owner ごとの inventory による、forget 後の残存 state の強制 cleanup
  (既知の限界の節)。
- restore 中の persist 失敗で plugin が running と unrestored の両方に載る
  二重表示の解消 (lifecycle の節)。

## 参照

- data plane plugin SDK: `docs/design/ja/plugin-sdk.md`
- 永続化の既定モデル: `docs/design/ja/persistence.md`
