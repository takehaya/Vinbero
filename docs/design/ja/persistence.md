# Persistence (永続化) と再起動時の挙動

「daemon (`vinberod`) を落とした / 再起動した後、何が残り、何が消え、何が自動で戻るか」をまとめたドキュメントです。運用スクリプトや構成管理 (Ansible / etc.) で **どのリソースを何度も投入し直す必要があるか** を判断する基準になります。

## TL;DR

再起動の後に何から戻るかで分けた表です。`state.json` の行は `pin_maps` の有無にかかわらず戻ります。`pin_maps` の行は `pin_maps: true` のときだけ残り、`pin_maps: false` (default) では消えるので、再起動の後に API から入れ直します。BGP の行は経路を受信し直すと戻ります。

| リソース | 戻る元 | 復旧の仕方と注意 |
|---|---|---|
| `vinbero.yml` (設定ファイル) | disk | そのまま再ロード |
| Bridge / VRF デバイスと bridge member (`vrf create`、`vrf bridge-attach` など) | `state.json` (kernel にも残る) | 起動時に **自動 reconcile** |
| VRF の vrf_id と実行時 AC (`vrf ac-add`) | `state.json` | XDP attach より前に復元 |
| VRF の ingress policy (`vrf policy`) | `state.json` | XDP attach より前に復元。config が `vrfs.default_deny` か `vrfs.deny_action` を書いていれば config が優先 ([VRF の ingress policy](#vrf-の-ingress-policy)) |
| 実行時に attach した device (`device attach`) | `state.json` | 起動時に attach し直す。`internal.devices` は config から |
| 実行時の vrf-bgp binding (`vrf-bgp bind` など) | `state.json` | BGP より前に復元。同じ VRF を config が bind していれば config が優先 |
| 実行時の locator (`locator create`) | `state.json` | binding の適用と広告より前に復元。同じ名前か prefix の locator を config が宣言していれば config が優先 ([locator](#locator)) |
| L2 headend の回線 (`hl2 create`) と ESI | `state.json` | VRF table を閉じるかの判断と XDP attach より前に復元 ([L2 headend の回線](#l2-headend-の回線)) |
| Ethernet Segment (`es create`、`es df-set` / `df-clear`) | `state.json` | 回線より前、XDP attach より前に復元 ([Ethernet Segment](#ethernet-segment)) |
| cplane plugin の module、SID 名と割り当て | cplane store (有効時) | locator 登録より前に予約を復元。dispatch と grant は再宣言で作り直す |
| auto-advertise の service SID (End.DT4 / DT6 / DT46、End.DT2U / DT2M) と広告 | binding と locator から作り直す | 起動時に exporter が割り当て直す。値は再起動の前と同じとは限らない ([locator](#locator)) |
| SID function / aux (`sid create`)、SID owner | `pin_maps` | `locator_ref` で割り当てた SID は、locator の割り当て状態 (使用中の function) が戻らない ([locator](#locator)) |
| Headend v4 / v6 (`hv4` / `hv6 create`) | `pin_maps` | BGP を有効にした起動では、BGP の applier が書いた entry を全 VRF から消す ([vrf.md](vrf.md#起動時の-bgp-の-entry-の削除)) |
| BD peer / VLAN table / 静的 FDB (`peer`、`vt`、`fdb create`) | `pin_maps` | FDB は学習でも埋まる。BGP を有効にした起動では、BGP の applier が書いた EVPN の FDB と peer を消す。peer の index の範囲に合わない entry が残っていれば起動を拒否する ([BD peer の index](#bd-peer-の-index)) |
| BGP で受信した経路 (headend、EVPN の FDB と peer、ES の member と DF 選出、SR Policy) | BGP | session が上がって経路を受け直すと書き直す |
| operator の BGP 広告 (`bgp advertise-*`)、MUP route (`mup create`)、local SR Policy (`sr-policy`) | 戻らない | `pin_maps` の有無にかかわらず、再起動の後に API から入れ直す |
| 登録済み plugin (`PROG_ARRAY`) | 戻らない (pin しない) | register RPC を再実行 |
| XDP プログラムの attach | 戻らない (fd とともに消える) | 起動時に `internal.devices` と `state.json` の device に attach し直す |
| Global stats / per-slot stats | 戻らない (pin しない) | 自然増加で埋まる |

API だけで組んだ L3 tenant (VRF device、AC、device attach、binding、locator、auto-advertise) と、EVPN auto-advertise で組んだ L2 segment (bridge facet、member、AC、回線、binding、locator) は、`pin_maps: false` でも再起動の後に何も入れ直さずに戻ります。`sid create` と `bgp advertise-evpn-*` で手で組んだ L2 segment は、SID が `pin_maps` でだけ残り、BGP 広告はどちらでも残らないので、入れ直しが要ります。

デフォルトは **外部コントローラが source of truth** として振る舞う設計 (`pin_maps: false`)。SRv6 制御状態は API クライアント側で保持します。`pin_maps: true` に切り替えれば kernel 側に BPF マップを残せるので、daemon 単体でステートフル運用できます。

## 永続化層: `state.json`

`state.json` に永続化するのは **Network Resource (Bridge / VRF)、実行時に attach した device、VRF オブジェクトの vrf_id と実行時に足した AC、API で作った VRF の BGP binding、L2 headend の回線、locator、Ethernet Segment、VRF の ingress policy** です。保存先は `settings.state_path` (デフォルト `/var/lib/vinbero/state.json`)。

control-plane plugin の module と登録内容は別の [cplane store](cplane-plugin.md)
に保存されます。store 有効時は `local-sids/state.json` に local SID の名前と address、
locator 定義、dispatch 宣言も保存し、`local-sids.version` で導入済みを記録します。
`pin_maps` の有無にかかわらず、起動時に割り当てを予約し、plugin の再宣言で同じ SID に
entry を再作成します。aux index と VRF ifindex はその時点で求め直します。inventory が
欠落・破損している場合は起動を拒否します。store 無効時の SID 名は memory のみです。
詳細は [local SID と daemon 再起動](cplane-plugin.md#local-sid-と-daemon-再起動) を参照してください。

`pkg/netresource/manager.go` の ResourceManager が:
1. 起動時に `state.json` を読み込み、記録されていた Bridge / VRF デバイスを netlink で確認
2. 欠けていれば再作成 (`ip link add` 相当)
3. 存在するものは Create と同じ検証と収束で adopt する (link 種別の確認、up、不足 member の enslave、VRF table の unreachable default、ifindex の更新)
   - VRF の record は unreachable default の設定 (`no_unreachable_default`) と、Vinbero が自分で足した経路の family (`unreachable_default_added`) を持ちます。設定の無い古い record は未決定として扱い、起動時に config の値 (宣言が無ければ既定) で決めて書き戻します
4. 稼働中に `vinbero vrf create` や `vinbero vrf bridge-attach` で変更があれば都度 disk に flush (VRF device も bridge も VrfService 経由で、vrf_id を持つ一級 VRF object の facet として管理される。bridge の state record は owning VRF 名も持つ)

これにより、`sudo reboot` した後でも `vinbero vrf show` の BRIDGE / BD_ID 列に以前と同じ Bridge が見えます (daemon が自動で restore する)。

堅牢性は次の 3 点で担保します。

- 書き込みは atomic です。同一ディレクトリの temp file に書いて fsync してから rename するので、書き込み途中の crash や ENOSPC でも直前の state.json が無傷で残ります。
- 保存の失敗は RPC エラーとして返ります。device、bridge、VRF の RPC は kernel device とメモリ上の記録を巻き戻さず、次に成功した保存が全量を書き直して収束します。VRF の BGP binding、L2 headend の回線、locator、Ethernet Segment、VRF の ingress policy の RPC は何も変えずに失敗します (後述)。
- boot の reconcile は fail-closed です。state の entry が実体化できない場合 (member NIC の消失、名前を別種の link に取られた等) は、entry 名と修復手順 (デバイスの復旧か entry の削除) を示すエラーで起動を拒否します。stale な ifindex のまま続行すると FDB watcher / EVPN / SID 参照ガードが誤った index で動くためです。parse できない state.json も同様に起動を拒否します (空 state で始めると管理下のデバイスを黙って放棄することになるため)。

VRF オブジェクトは `vrf_objects` に保存します。`next_vrf_id` は次に割り当てる id、`entries` は VRF 名ごとの `vrf_id` と `runtime_acs` です。kernel device を持たない VRF もここに入ります。`config` は、その VRF を起動時の読み込み (config file か、device / bridge の record) が作ったことを示します。API で作った VRF には付きません。

```json
"vrf_objects": {
  "next_vrf_id": 3,
  "entries": [
    {"name": "tenant-a", "vrf_id": 1, "runtime_acs": [{"interface": "vb1a2b3c", "vlan": 0}]},
    {"name": "tenant-b", "vrf_id": 2, "config": true}
  ]
}
```

`vrf_objects` が無い state も読めます。その場合は起動時に id を割り当て、次の保存から記録します。次の state は起動を拒否します。いずれも削除済みの VRF の id や予約済みの id 0 を別の VRF に渡すおそれがあるためです。

- `vrf_objects` があるのに `next_vrf_id` (1 以上) か `entries` が欠けている
- `next_vrf_id` が上限の 4294967294 を超えている
- `next_vrf_id` 以上の `vrf_id` を持つ entry がある

pin した map に state.json が記録していない vrf_id の状態が残っている場合 (state.json を失った、保存できなかった、などで)、起動時はその id より上から割り当て、その id の headend entry を消します。起動時の順序と、interface が消えた AC の扱いは [vrf.md](vrf.md#永続化と-boot) を参照してください。

state.json フォーマットは内部実装扱いで、手編集は非推奨です。`vinbero` CLI 経由で操作してください (例外は上記の修復手順と、bridge record の owning VRF 付け替え)。

### VRF の BGP binding

`vbctl vrf-bgp bind`、`vrf-bgp update`、`vrf-bgp rt add` / `rt remove`、`vrf-bgp family add` / `family remove` (CNI の ADD が作る binding を含む) で作った、または変えた binding は `runtime_vrf_bindings` に保存します。L3 (vpnv4 / vpnv6 / mup_ipv4 / mup_ipv6) と L2 (evpn) を区別せず、binding 全体を保存します。`vrf-bgp unbind` はここから消します。config の `bgp.vrf_bindings` は保存しません。

```json
"runtime_vrf_bindings": [
  {
    "vrf_name": "tenant-a",
    "rd": "65100:1",
    "import_rts": ["65000:100"],
    "export_rts": ["65000:100"],
    "families": {"vpnv4": {"route_targets": [{"rt": "65000:100", "direction": "both"}]}},
    "redistribute": ["static"],
    "default_locator": "LOC1"
  }
]
```

保存するのはメモリ上の binding そのものです。`families` の RT は登録した順で、方向は `import` / `export` / `both` のいずれかです。`import_rts` / `export_rts` は `families` から導かれる一覧ですが、順序も含めて同じに戻すために保存します。RT を持たない family も残します。起動時はこれを正規化し直さずに戻すので、`vbctl vrf-bgp list` の結果は再起動の前後で同じです。`max_prefixes`、`mup_gtp4_source_prefix` も、設定していれば保存します。

起動時の扱いは次のとおりです。

- config が同じ VRF を `bgp.vrf_bindings` で bind していれば config を使い、保存した binding は捨てて state.json から消します。warning を 1 行出します。後で config からその binding を消しても、保存していた binding は戻りません
- config が bind している VRF に API で加えた変更 (bind し直し、RT や family の追加と削除、unbind) は、メモリと data plane には反映しますが保存しません。次の起動で config の binding に戻ります
- 復元は BGP の有無に関係なく行い、BGP session の起動、経路の受信、auto-advertise、plugin の復元より前に終えます。最初に受信した経路から、復元した binding で import 先を決めます
- binding が名前を挙げる VRF は、config が宣言しなくなっても、その vrf_id のまま残ります
- binding が `default_locator` に挙げる locator は、API で登録したものも binding より前に戻るので ([locator](#locator))、保存した binding はそのまま auto-advertise を始めます
- 保存した binding の auto-advertise を有効にできない場合 (挙げる locator が無い: config に負けて捨てた、locator を保存しない版の state.json から起動した、など) は、warning を出して起動を続けます。binding は残り、auto-advertise だけが止まります。locator を登録してから、同じ内容で `vbctl vrf-bgp bind` を実行すると広告を始めます。config の binding では、これまでどおり起動を止めます

binding の RPC は、state.json への書き込みが成功したときだけ成功を返します。書き込みに失敗した RPC は binding を変えません。メモリ、data plane、state.json は直前の状態のままで、エラーには state file を書けなかったことが出ます (`vrf-bgp bind` / `unbind` は VRF ごとの `errors`、それ以外は `internal`)。同じ RPC を繰り返せばやり直せます。bind では、state.json に書いてから経路の import と広告に使い始めます。unbind では、state.json から消してから外します。どちらも、成功を返していない変更が再起動で現れることはありません。bind が新しく作った VRF は、書き込みに失敗しても VRF として残ります。例外として、state.json の rename が済んだ後に directory の fsync だけが失敗した場合は、エラーを返しても file が新しい内容を持つことがあります。次に state.json を書いたときに、メモリの内容にそろいます。

- `runtime_vrf_bindings` が無い state.json は、保存した binding が無いものとして読みます
- この版が知らない field を binding の record に持つ state.json は、起動を拒否します。新しい版が書いた import の制限を黙って捨てると、別の tenant の経路を取り込むおそれがあるためです。field を消すか、書いた版で起動してください
- `runtime_vrf_bindings` を知らない版の vinberod は、この field を読まずに起動し、次に state.json を書くときに消します。その版に戻す前に state.json を控えておき、binding は config で宣言するか、起動後に bind し直してください

### L2 headend の回線

`vbctl hl2 create` (`HeadendL2Create`、CNI を含む) で作った回線は `runtime_l2_circuits` に保存します。`hl2 delete` と `hl2 flush`、interface の削除 (link watcher が回線ごと消します) はここからも消します。

```json
"runtime_l2_circuits": [
  {
    "interface": "vb1a2b3c",
    "ifindex": 12,
    "mac": "02:5e:10:00:00:01",
    "vlan": 0,
    "mode": "SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2",
    "src_addr": "fc00:1::1",
    "segments": ["fc00:3::3"],
    "bd_id": 100,
    "esi": "00:11:22:33:44:55:66:77:88:99"
  }
]
```

回線は `headend_l2_map` と同じく ifindex と VLAN で決まります。`interface` と `mac` は、作成した時点 (または daemon が見た rename の後) の interface の名前と hardware address です。起動時は、保存した ifindex の interface が今も同じ名前と hardware address を持つときだけ回線を戻します。推測では戻しません。

- interface が消えている、同じ名前の interface が別の ifindex で作り直されている、ifindex を別の interface が使っている (名前か hardware address が違う): 回線を戻さず、記録を消し、warning を出します。pin した map にその key の entry が残っていれば、それも消します。新しい interface が古い回線を引き継がないためです。回線が要るなら、その interface で作り直します
- 一致する: entry と ESI を書き直します。pin した map では entry が残り ESI (`headend_l2_ext_map`) は消えているので、ここで ESI が戻ります

稼働中の rename と hardware address の変更は、link watcher が記録に反映します。daemon が止まっている間の rename では回線は戻りません。

復元は state を読んだ直後、VRF table の reconcile と XDP attach より前に行います。table を閉じるかの判断は `headend_l2_map` を見るので、pin の有無にかかわらず保存した回線のある table は開けておきます ([vrf.md](vrf.md#encap-の外側の経路))。

RPC は、`headend_l2_map` と `state.json` の両方を書けたときだけ成功を返します。

- 作成: map に書いてから保存します。保存に失敗したら map を作成前の状態 (上書きした回線があればその回線) に戻し、エラーを返します
- 削除: 回線の記録に削除中の印 (`deleting`) を付けて保存し、map から消し、記録を消して保存します。最初の保存に失敗したら何も変えずにエラーを返します。map の削除か最後の保存に失敗したら、記録は削除中のままエラーを返します。同じ削除を繰り返すか次の起動で、削除が完了します。起動時は削除中の回線を戻さず、pin した map の entry を消します
- `hl2 flush`: 全回線に削除中の印を付けてから map を空にし、記録を消します。失敗時の扱いは削除と同じです
- interface が消えた回線の削除: 名前がもう解決できなくても、その名前と VLAN の記録が残っていれば (link watcher が消す前など) 消して成功を返します。記録も entry も無ければ従来どおり `not_found` です

binding と同じく、state.json の rename が済んだ後に directory の fsync だけが失敗した場合は、エラーを返しても file が新しい内容を持つことがあります。次に state.json を書いたときに、メモリの内容にそろいます。

作成の map への書き込みと保存の間で daemon が強制終了すると、pin した map には記録の無い entry が残ります。RPC は成功を返していません。記録の無い entry (この field を知らない版が pin した map に残したもの) は取り込まず、そのまま残します。作り直すと記録されます。

- `runtime_l2_circuits` が無い state.json は、保存した回線が無いものとして読みます
- この版が知らない field を持つ記録、同じ ifindex と VLAN の記録が 2 つある state.json、mode や ESI を解釈できない記録は起動を拒否します
- この field を知らない版の vinberod は、field を読まずに起動し、次に state.json を書くときに消します。その版に戻す前に state.json を控えておき、回線は作り直してください

### locator

`vbctl locator create` (`LocatorCreate`) で登録した locator は `runtime_locators` に、登録した順で保存します。`locator delete` (`--force` を含む) はここから消します。config の `bgp.locators` は保存しません。

```json
"runtime_locators": [
  {
    "name": "LOC1",
    "prefix": "fd00:200::/48",
    "block_len": 32,
    "node_len": 16,
    "function_len": 16,
    "argument_len": 64,
    "behavior": "classic",
    "function_auto_start": 1,
    "function_auto_end": 65535
  }
]
```

`prefix` は host bit を落とした形、`behavior` は `classic` か `usid` です。

起動時の扱いは次のとおりです。

- 復元は BGP の有無に関係なく、登録した順に行います。cplane plugin の SID 予約の復元と config の locator の登録の後、BGP の applier、exporter、plugin、session、RPC server の前です。予約の後なので、plugin が持つ function は locator を戻した時点で使用中になります。binding の適用と広告より前なので、auto-advertise の SID、受信した経路の encap source (`bgp.global.source_locator`)、plugin の locator 参照は、最初から戻した locator を使います
- config が同じ名前の locator を `bgp.locators` で宣言している、または config の locator が同じ prefix を持つ場合は config を使い、保存した locator は捨てて state.json から消します。warning を 1 行出します。後で config から消しても、保存していた locator は戻りません
- config が宣言する名前の locator を API で作る (BGP を無効にして起動したときなど)、または消す変更は、メモリには反映しますが保存しません。名前は BGP の有無に関係なく config のものです
- 戻した locator からの割り当ては、起動の後に改めて行います。binding の auto-advertise が作る End.DT4 / DT6 / DT46 と EVPN の End.DT2U / DT2M は、exporter が起動時に割り当て直します。値は割り当ての順で決まるので、再起動の前と同じとは限りません。config の locator も同じです
- `sid create --locator-ref` で割り当てた SID の entry は `pin_maps` でだけ残り、locator 側の使用中の印は戻りません (config の locator も同じです)。pin した map にそうした SID が残る構成では、再起動の後に自動の割り当て (auto-advertise の SID など) が同じ値を取ることがあります。pin で持ち越す SID は、`function_auto_start` から `function_auto_end` の外の `function` を明示して割り当てると、自動の割り当てと重なりません
- uSID locator の作成で行う uA の CSID の取り込みは、起動時の復元では行いません (config の locator と同じです)。pin した uA の CSID も、同じく自動の割り当ての範囲の外に置いてください

RPC は、state.json への書き込みが成功したときだけ成功を返します。作成は、locator を登録して uA の CSID を取り込んだ後に保存し、保存に失敗したら登録と取り込みを戻してエラーを返します。source locator の登録で走る経路の書き直しは、保存の成功後にだけ行います。削除は、使用中かどうかの確認の後、locator を消す前に保存します。保存に失敗したら何も消しません。どちらも、同じ RPC を繰り返せばやり直せます。

- `runtime_locators` が無い state.json は、保存した locator が無いものとして読みます
- この版が知らない field を持つ記録、名前が空・prefix や behavior を解釈できない・bit 長が合わない記録、同じ名前か同じ prefix の記録が 2 つある state.json は起動を拒否します。cplane plugin の SID 予約と layout が合わない記録も起動を拒否します (API の作成なら拒否される値です)
- この field を知らない版の vinberod は、field を読まずに起動し、次に state.json を書くときに消します。その版に戻す前に state.json を控えておき、locator は config で宣言するか登録し直してください

### Ethernet Segment

`vbctl es create` (`EsCreate`) で作った Ethernet Segment は `runtime_ethernet_segments` に ESI の順で保存します。`es df-set` / `es df-clear` は記録の DF を書き換え、`es delete` はここから消します。

```json
"runtime_ethernet_segments": [
  {
    "esi": "01:00:00:00:00:00:00:00:01:00",
    "local_attached": true,
    "redundancy_mode": "ESI_REDUNDANCY_MODE_ALL_ACTIVE",
    "local_pe_src_addr": "fc00:1::1",
    "df_pe_src_addr": "fc00:2::2",
    "rd": "65000:1"
  }
]
```

`df_pe_src_addr` は operator が `es create` / `df-set` / `df-clear` で決めた DF です。BGP の DF 選出が書いた DF は記録しません。`rd` は RT4 の auto-advertise に使う RD で、`esi_map` には無いのでここにだけ残ります。

`esi_map` は pin しないので、Ethernet Segment は `pin_maps` の有無にかかわらず state.json から戻ります。

- 復元は state を読んだ直後、L2 headend の回線の復元の前に行います。VRF table の reconcile、EVPN の掃除、XDP attach、BGP より前です。ESI を持つ回線の最初のフレームから split horizon と DF の判定が効き、BGP の DF 選出は最初に受信した RT4 から local attach を見ます
- Ethernet Segment の記録は interface を持たないので、照合せずにそのまま戻します。ESI を持つ回線は回線の規則 (ifindex、名前、hardware address の一致) で戻るかどうかが決まり、interface が消えた回線は戻りませんが Ethernet Segment は戻ります。稼働中に interface を消したときも、消えるのは回線だけで Ethernet Segment は残ります
- BGP を有効にした起動では、session の起動の後に、local attach の Ethernet Segment の DF を選び直し、EVPN auto-advertise が有効で `rd` を持つものの RT4 を広告します (`es create` の後と同じです)
- state.json の Ethernet Segment または L2 headend の回線の ESI が、受け付ける形 ([srv6_bgp.md](srv6_bgp.md) の ESI の type ごとの並び) を満たさないときも起動は止まりません。どちらも data plane に戻しますが、警告に ESI を示します。Ethernet Segment は起動時の DF の選出と RT4 の広告を行いません (ほかの PE の RT4 を受信したときの DF の選出は通常どおり走ります。type 6 以上の ESI は GoBGP の受信側が通すためです)。`vbctl es delete` (回線は `hl2 delete`) で消して、正しい ESI で作り直してください

RPC は、`esi_map` と state.json の両方を書けたときだけ成功を返します。

- 作成 (上書きを含む): map に書いてから保存します。保存に失敗したら map を作成前の状態に戻し、ESI ごとのエラーを返します。DF の選び直しと RT4 の広告は保存の成功後に行います
- 削除: map から消してから保存します。保存に失敗したら entry を書き戻してエラーを返します。RT4 の取り下げは保存の成功後に行います
- `df-set` / `df-clear`: map の DF を書き換えてから保存します。保存に失敗したら前の DF に戻し、`internal` を返します

`esi_map` は pin しないので、map の書き込みと保存の間で daemon が強制終了すると、次の起動は state.json の内容で始まります。成功を返していない作成は戻らず、成功を返していない削除は取り消されます。

- `runtime_ethernet_segments` が無い state.json は、保存した Ethernet Segment が無いものとして読みます
- この版が知らない field を持つ記録、ESI (全 0 を含む)、address、`redundancy_mode` を解釈できない記録、同じ ESI の記録が 2 つある state.json は起動を拒否します
- この field を知らない版の vinberod は、field を読まずに起動し、次に state.json を書くときに消します。その版に戻す前に state.json を控えておき、Ethernet Segment は作り直してください

### VRF の ingress policy

`vbctl vrf policy` (`VrfSetPolicy`) で決めた ingress policy (default-deny と deny action) は `runtime_vrf_policy` に保存します。policy は daemon 全体で 1 つです。

```json
"runtime_vrf_policy": {"default_deny": true, "deny_action": "drop"}
```

- config file に `vrfs.default_deny` か `vrfs.deny_action` の key があれば、値が既定と同じでも policy は config のものです。そのとき `vrf policy` の変更はメモリと data plane には反映しますが保存せず、次の起動で config の値に戻ります。保存した policy があれば捨てて state.json から消し、warning を 1 行出します
- config が policy を書いていなければ、起動時に config の VRF を読んだ後、`ingress_vrf_map` と policy を書く前 (XDP attach より前) に保存した policy を戻します。attach の後の最初のパケットから戻した policy が効きます

RPC は、data plane と state.json の両方を書けたときだけ成功を返します。保存に失敗したら、メモリと data plane を前の policy に戻し、`internal` を返します。

- `runtime_vrf_policy` が無い state.json は、保存した policy が無いものとして読みます (config の値を使います)
- この版が知らない field を持つ記録、`deny_action` が `drop` / `pass` 以外の記録は起動を拒否します
- この field を知らない版の vinberod は、field を読まずに起動し、次に state.json を書くときに消します

locator、Ethernet Segment、policy の保存も、binding と同じく、state.json の rename が済んだ後に directory の fsync だけが失敗した場合は、エラーを返しても file が新しい内容を持つことがあります。次に state.json を書いたときに、メモリの内容にそろいます。

### 1 つの host で複数の vinberod

1 つの host で複数の vinberod を動かすときは、`settings.state_path` をそれぞれ別にします。同じ file を共有すると、ほかの daemon の回線を自分の interface と照合して消し、ほかの daemon の locator、Ethernet Segment、policy を自分のものとして戻します (examples は daemon ごとに別の file を使います)。

## BPF マップ: in-memory vs pinned

SRv6 制御状態 (`sid_function_map`, `sid_aux_map`, `headend_*_map`, `fdb_map`, `bd_peer_map`, `bd_peer_reverse_map`, `dx2v_map`, `sr_policy_map`, `ecmp_group_map`, `ecmp_path_map`, `ecmp_group_owner_map`) は daemon が所有する eBPF マップです。`settings.pin_maps.enabled` で挙動が切り替わります。

### `pin_maps.enabled: false` (default)

- **daemon 終了 = map 消滅 = データ消滅**
- 次回起動時は空の map でスタート
- 既存エントリの引き継ぎは一切なし
- クライアント側 (API caller) が残りの状態を保持している前提

大量の SID を扱う運用では外部 DB / etcd / Kubernetes CRD 等に正本を置き、daemon 起動時に一括再投入する "external SoT" モデルが向きます。

### `pin_maps.enabled: true`

cilium/ebpf の `PinByName` で、対象の制御マップ (`pkg/bpf/bpf.go` の `pinnedControlMaps`) を `/sys/fs/bpf/<path>/<map_name>` に pin します (`path` はデフォルト `/sys/fs/bpf/vinbero`)。

挙動:
- **daemon 起動時**: pin dir に map が無ければ新規作成して pin、既にあれば [互換条件](#pin-の互換条件) を確かめて既存 map を reuse
- **daemon 終了時**: ユーザ側 FD は閉じるが、bpffs の pin が FD を保持しているため **kernel map は生き残る**
- **daemon 再起動**: 同じ pin dir を指定すれば、前回書き込んだエントリは全部見える

```yaml
settings:
  pin_maps:
    enabled: true
    path: /sys/fs/bpf/vinbero
```

前提: `/sys/fs/bpf` が bpffs でマウントされていること (`mount -t bpf bpf /sys/fs/bpf/`)。netns 内で動かす場合はその netns の mount namespace でも同様にマウントが必要。

### pin しないマップ

以下は永続化対象外です:
- `stats_map`, `slot_stats_*` (3 本): カウンタは再起動でリセットするのが自然
- `scratch_map`, `tailcall_ctx_map`: per-CPU の ephemeral 一時領域
- `sid_endpoint_progs`, `headend_v4_progs`, `headend_v6_progs` (PROG_ARRAY): プログラム FD が毎回異なるので pin しても意味がない
- `ecmp_live_map`: prober の生死判定は意図的に pin しません。restart 前の古い判定が path を blackhole しないよう、prober が再登録するまでは miss = 全 path live に倒します

### in-memory の採番と pin された参照

pin されるのはマップだけで、control plane 側の採番状態は再起動で消えます。`sr_policy_map` の policy_id は applier が in-memory に採番しますが、その id を参照する `headend_*_map` のエントリは pin で生き残ります。素朴に 0 から採番し直すと、生き残ったエントリが指す id を新しい policy に割り当ててしまい、その prefix が無関係な policy の transport SID list に steer されます。BGP が再広告してエントリを上書きするまで誤転送が続きます。

そこで applier は起動時に `HighestSRPolicyIDInUse` で、pin された状態がまだ参照している最大の policy_id を調べ、その上から採番を再開します。参照元は 2 つあります。`sr_policy_map` の key は install 済み policy を示し、`headend_v4/v6_map` のエントリが持つ policy_id は実際の参照を示します。誤転送を防ぐうえで本質的なのは後者です。policy が withdraw 済みで `sr_policy_map` に entry が無くても、headend 側が id を指したままなら再利用は危険だからです。

生き残った id は使い切りで、対応する policy が再広告されると新しい id を取ります。id は uint32 なので枯渇は実質問題になりません。

### pin の互換条件

起動時に pin dir に同じ名前の map があると、Vinbero はそれを使う前に、この build が宣言する map と次の 5 点が一致するかを確かめます。

- map の型
- key のサイズ
- value のサイズ
- `max_entries`
- flags

これらは BPF map の作成後に変えられないため、1 つでも違えば load は失敗し、daemon は起動しません。pin された map を自動で削除したり、entry を別の layout に変換したりはしません。エラーには合わない map の名前と pin dir、cilium/ebpf が報告する差分 (例: `KeySize: 8 changed to 12`) が出ます。

```
pinned maps in /sys/fs/bpf/vinbero do not match this build (headend_v4_map, headend_v4_owner_map): stop vinberod, remove the pin directory and apply the configuration again: ...
```

key のサイズも互換条件に含まれます。たとえば `headend_v4_map` / `headend_v6_map` とそれぞれの owner map の key は `{prefixlen, vrf_id, prefix}` で、IPv4 が 12 byte、IPv6 が 24 byte です (layout は [plugin-sdk.md](plugin-sdk.md#headend-map-の-key) を参照)。key の layout が違う build で作られた pin は、本体と owner map のどちらも key サイズの不一致で拒否されます。本体だけを消しても起動は直りません。

不一致になる典型は次のとおりです。

- `settings.entries.*.capacity` を変えた (`max_entries` が変わる)
- map の key か value の struct layout が違う Vinbero に入れ替えた。plugin SDK の `VINBERO_SDK_VERSION` が BREAKING として上がる版がこれにあたります
- マップ名が変わった (古い pin は使われずに残ります)

不一致のときは daemon を止めて pin dir を削除し、起動してから状態を入れ直してください。

```bash
sudo systemctl stop vinberod
sudo rm -rf /sys/fs/bpf/vinbero
sudo systemctl start vinberod
```

pin dir を消すと、SID、headend、owner、SR Policy、ECMP group など、pin されていた制御状態がすべて消えます。RPC や vbctl で入れた entry と plugin の宣言は投入し直し、BGP 由来の entry は session が上がって経路を受け直すと戻ります。

### BD peer の index

`bd_peer_map` の index は範囲ごとに役割が決まっています (0〜7 が flood スロット、8〜31 は空けてある範囲、32〜63 が Ethernet Segment の peer、64〜127 が RT2 などの unicast だけの peer。[bum_mode.md](bum_mode.md#flood-スロットと-bd-の-node-数))。key と value の形は同じなので、[互換条件](#pin-の互換条件) では違いを検出できません。そこで起動時、XDP の attach の前に次を行います。

1. BGP を有効にした起動では、BGP の applier が書いた EVPN の FDB と peer を消します (index に関係なく owner で判断します)。あわせて、Ethernet Segment の peer の範囲 (32〜63) と、flood スロットと RT2 の peer が 0〜7 を共有し Ethernet Segment の peer を 8〜39 に置く配置で書かれた範囲 (8〜39) から、owner の無い peer とそれを指す FDB を消します。消した peer を指していた学習済みの MAC (owner が無く static でない remote の FDB) も消します。残すと、同じ index に後から入る別の peer (別の PE の flood peer など) へ既知 unicast が届くためです。
2. BGP の有無にかかわらず、空けてある範囲 (8〜31) に peer、owner の記録、reverse entry、remote の FDB の参照が残っていれば、起動を拒否します。どれも推測では消しません。エラーには BD、index、owner が並びます。

```
the pinned bridge-domain maps use peer indices of the reserved flood [8, 32) range, which the peer index layout keeps free (1 in all): peer {bd 300, index 10} (bgp:v1:asn=65001:evpn). ...
```

拒否されたときは、その owner の ASN で BGP を有効にして起動する (その applier が自分の entry を消します) か、daemon を止めて pin dir を消し、状態を入れ直してください。index 0〜7 の operator の peer (`vbctl peer create`) は flood スロットのまま使われ続けます。

### Aux index の allocator recovery

pin 有効時は特に重要なメカニズム (`pkg/bpf/maps.go::RecoverAuxIndices`):

Phase 2 で `aux_owner_map` (BPF ARRAY map) を `sid_aux_map` と同じ keyspace で導入しました。各 index に対し owner タグ (`builtin:v1` か `plugin:v1:<mapType>:<slot>`) を持ち、`pinnedControlMaps` の一員として pin されます。

起動時のフロー:

1. `aux_owner_map` が空でなければそれを iterate して owner を再構築 (Phase 2 path)。**独立 PluginAux も復元される**ため、SID に bind されていない索引も daemon 再起動を跨いで生存します。
2. 空のときは fallback として `sid_function_map` を iterate して owner を再構築 (Phase 1d 互換)。再構築後 `aux_owner_map` に書き戻し、次回起動以降は Phase 2 path を取ります (legacy → v1 forward migration)。

pin 無効時は `aux_owner_map` も in-memory なので、allocator は fresh start します。

owner タグ format は `pkg/bpf/maps.go::AuxOwnerVersion` で版数管理しており、`ParseAuxOwnerTag` は legacy の unversioned format (`plugin:endpoint:32` / `builtin`) と v1 の versioned format (`plugin:v1:endpoint:32` / `builtin:v1`) の両方を受理します。

#### 独立 PluginAux は復元される (Phase 2)

Phase 1d までは `vbctl plugin aux alloc` で払い出した「独立 aux」(SID に未 bind の index) は daemon 再起動で失われていました。Phase 2 で `aux_owner_map` の pin を導入したため、`pin_maps.enabled: true` の構成では独立 aux も含めて owner と index 使用状況が再起動を跨いで保持されます。

実装詳細は `pkg/bpf/maps.go::RecoverAuxIndices` を参照。

#### PluginUnregister は aux を解放しない (PluginAuxPurge で明示解放)

`PluginUnregister` は PROG_ARRAY スロットと server の registry エントリを消すだけで、**そのスロットが所有していた aux index の自動解放は行いません**。これは「同じ slot で再 register したときに前回の状態を予期せず継承しない」ための明示的な設計です。サーバ側ではこの状態を検知すると `plugin slot unregistered with live aux entries` の warn ログを出します。

取り残し index を解放するには Phase 2 で導入した RPC を使います:

- `vbctl plugin aux list --map-type <mt> --slot <n> --match-slot`: 取り残し index を列挙
- `vbctl plugin aux purge --map-type <mt> --slot <n>`: 取り残し index をまとめて解放

`PluginAuxPurge` は `sid_aux_map` の zero-write と allocator slot 解放、`aux_owner_map` のクリアを 1 RPC で行います。Phase 1d までは daemon 再起動まで回収されない問題がありましたが、Phase 2 ではオンライン回収が可能です。

## XDP program の attach

`ip link set dev eth0 xdp off` しない限り、カーネルは XDP プログラムを持ち続けます。ただし:

- `link.AttachXDP()` が返す `link.Link` は daemon のプロセス lifetime に縛られる
- daemon が **正常終了**: `Close()` で明示的に XDP detach (`pkg/vinbero/vinbero.go::Close`)
- daemon が **異常終了** (OOM kill / SIGKILL 等): kernel が fd を reap し自動 detach
- daemon が **別プロセスとして再起動**: attach 済みと衝突するとロードエラー。対処: `ip link set dev <iface> xdp off` で前の XDP を剥がしてから起動。`make remove-ebpfmap` も補助的に使える

現状は bpf_link ベースで attach しているので、daemon がいない状態で XDP が残ることは基本的にありません。

`vbctl device attach` で実行時に attach した device は `state.json` の `devices` に記録され、次の起動で attach し直されます。interface が消えている entry は起動を止めずに捨てます。詳細は [device_attach.md](device_attach.md) を参照してください。

## Plugin 登録

`vinbero plugin register` で登録したカスタム BPF プラグインも **PROG_ARRAY (`sid_endpoint_progs` / `headend_v{4,6}_progs`) 経由の in-memory 登録**です:

- daemon が持つ `ebpf.Collection` がプログラムと map を所有 (`pkg/server/plugin.go`)
- daemon 終了 → Collection Close → PROG_ARRAY slot が空 → tail call fail (パケット DROP)
- 再起動後、**同じ ELF で `plugin register` を再実行**する必要あり

プラグイン登録を自動化するなら、daemon の systemd unit に `ExecStartPost=` で CLI 呼び出しを並べるか、外部オーケストレータ (Ansible 等) で管理します。

## Stats 値

- `stats_map` / `slot_stats_*` は PERCPU_ARRAY で in-memory
- daemon 再起動でリセット。`vinbero stats reset` / `stats slot reset` 相当
- 長期集計は外部 metrics 基盤 (Prometheus 等) にエクスポートして保持する設計を想定

## 一括削除 (`vinbero ... flush`)

pin 有効で運用すると「全部一旦クリアしたい」場面が出ます。各 service に `flush` サブコマンドがあり、**`--yes` フラグ必須**で全エントリ一掃できます:

```bash
vinbero sid flush --yes              # SID function + aux
vinbero hv4 / hv6 flush --yes --all-vrfs  # L3 Headend (省略すると global VRF だけ)
vinbero hl2 flush --yes              # L2 Headend
vinbero peer flush --yes --bd-id 100 # 部分フラッシュ (BD 単位)
vinbero fdb flush --yes --keep-static # 動的学習だけ消す
vinbero vt flush --yes --table-id 5  # 部分フラッシュ (table 単位)
```

Flush はサーバ側で `sid_function_map` を iterate → 1 件ずつ `Delete` + aux 解放という流れ。`pin_maps: true` の場合、削除結果は kernel map に即反映されるので **次回起動時にも空のまま** です。rm -rf で pin dir を吹き飛ばすより、schema を保ったまま state だけクリアしたいときに使えます。

## 再起動のチェックリスト

本番で安全に再起動するときの手順:

1. **上流ルーティングで draining** (可能なら)。SID を減らす / BGP で切り離すなど
2. `vinberod` 停止
3. (必要なら) `ip link set dev <iface> xdp off` を実行
4. `vinberod -c vinbero.yml` 再起動 → Ethernet Segment と L2 headend の回線の復元、Bridge/VRF reconcile、vrf_id と実行時 AC と ingress policy の復元、XDP attach、API で作った binding と locator の復元 が自動で走る
5. SID / Headend を再投入:
   - `pin_maps: false`: **外部コントローラから全部再投入**
   - `pin_maps: true`: RPC で入れたエントリは bpffs から復元されるので再投入不要。BGP を有効にした起動では、BGP の applier が書いたエントリは起動時に消え、経路を受信し直すと戻ります
   - L2 headend の回線、locator、Ethernet Segment はどちらの場合も `state.json` から戻るので、再投入は不要です
6. **Plugin は常に再登録**が必要 (`vinbero plugin register ...`)
7. トラフィック監視 (`vinbero stats show`, `stats slot show`) で正常性確認

schema を変更したときは手順 3 の後に `rm -rf /sys/fs/bpf/vinbero/` を挟んでから再起動。

## 将来拡張候補

- daemon hand-off による **hitless restart** (XDP link の継承 + pin 済み map 引き継ぎで無停止更新)
- Plugin の auto re-register (`plugins:` セクションを vinbero.yml に追加し、起動時に自動ロード)
- schema migration ツール (`vinbero admin pin-migrate` 等で capacity 変更を無停止適用)

これらは未実装です。現状は `pin_maps: true` でデータは残せますが、再登録が必要なのは XDP attach と plugin、capacity/schema 変更時のリロードです。
