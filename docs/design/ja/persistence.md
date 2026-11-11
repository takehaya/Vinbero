# Persistence (永続化) と再起動時の挙動

「daemon (`vinberod`) を落とした / 再起動した後、何が残り、何が消え、何が自動で戻るか」をまとめたドキュメントです。運用スクリプトや構成管理 (Ansible / etc.) で **どのリソースを何度も投入し直す必要があるか** を判断する基準になります。

## TL;DR

| リソース | `pin_maps: false` (default) | `pin_maps: true` | 復旧手段 |
|---|---|---|---|
| `vinbero.yml` (設定ファイル) | 残る (disk) | 残る | そのまま再ロード |
| XDP プログラムの attach | **消える** | **消える** | daemon 起動時に `internal.devices` と、`state.json` に記録された実行時 attach の device に attach し直す |
| SID function / aux | **消える** | **残る** (bpffs pin)。SID owner も保存 | RPC / CLI で再投入。cplane plugin の SID は保存済み割り当てと再宣言で復旧 |
| cplane plugin の SID 名と割り当て | cplane store 有効なら残る | 同左 | locator 登録より前に予約を復元。dispatch と grant は再宣言で作り直す |
| Headend v4 / v6 / L2 | **消える** | **残る** (bpffs pin)。ただし BGP を有効にした起動では、BGP の applier が書いた L3 の entry を全 VRF から消す | default: RPC / CLI で再投入。BGP の entry は経路の受信で書き直す ([vrf.md](vrf.md#起動時の-bgp-の-entry-の削除)) |
| BD peer / VLAN table / FDB | **消える** | **残る** (bpffs pin) | default: RPC / CLI (FDB は学習でも埋まる) |
| Bridge / VRF デバイス | カーネル netlink に残る / netns 単位 | 同左 | `state.json` から **自動 reconcile** |
| VRF の vrf_id と実行時 AC (`vrf ac-add`) | `state.json` に残る | 同左 | 起動時に XDP attach より前に復元 |
| 実行時の vrf-bgp binding (`vrf-bgp bind` など) | `state.json` に残る | 同左 | 起動時に BGP より前に復元。同じ VRF を config が bind していれば config が優先 |
| 登録済み plugin (`PROG_ARRAY`) | **消える** | **消える** (pin しない) | register RPC を再実行 |
| Global stats / per-slot stats | **消える** | **消える** (pin しない) | 自然増加で埋まる |

デフォルトは **外部コントローラが source of truth** として振る舞う設計 (`pin_maps: false`)。SRv6 制御状態は API クライアント側で保持します。`pin_maps: true` に切り替えれば kernel 側に BPF マップを残せるので、daemon 単体でステートフル運用できます。

## 永続化層: `state.json`

`state.json` に永続化するのは **Network Resource (Bridge / VRF)、実行時に attach した device、VRF オブジェクトの vrf_id と実行時に足した AC、API で作った VRF の BGP binding** です。保存先は `settings.state_path` (デフォルト `/var/lib/vinbero/state.json`)。

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
- 保存の失敗は RPC エラーとして返ります。device、bridge、VRF の RPC は kernel device とメモリ上の記録を巻き戻さず、次に成功した保存が全量を書き直して収束します。VRF の BGP binding の RPC は何も変えずに失敗します (後述)。
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
- 保存した binding の auto-advertise を有効にできない場合 (API で登録した locator は再起動で消えるので、その locator を使う binding がこれにあたります) は、warning を出して起動を続けます。binding は残り、auto-advertise だけが止まります。locator を登録し直してから、同じ内容で `vbctl vrf-bgp bind` を実行すると広告を始めます。config の binding では、これまでどおり起動を止めます

binding の RPC は、state.json への書き込みが成功したときだけ成功を返します。書き込みに失敗した RPC は binding を変えません。メモリ、data plane、state.json は直前の状態のままで、エラーには state file を書けなかったことが出ます (`vrf-bgp bind` / `unbind` は VRF ごとの `errors`、それ以外は `internal`)。同じ RPC を繰り返せばやり直せます。bind では、state.json に書いてから経路の import と広告に使い始めます。unbind では、state.json から消してから外します。どちらも、成功を返していない変更が再起動で現れることはありません。bind が新しく作った VRF は、書き込みに失敗しても VRF として残ります。

- `runtime_vrf_bindings` が無い state.json は、保存した binding が無いものとして読みます
- この版が知らない field を binding の record に持つ state.json は、起動を拒否します。新しい版が書いた import の制限を黙って捨てると、別の tenant の経路を取り込むおそれがあるためです。field を消すか、書いた版で起動してください
- `runtime_vrf_bindings` を知らない版の vinberod は、この field を読まずに起動し、次に state.json を書くときに消します。その版に戻す前に state.json を控えておき、binding は config で宣言するか、起動後に bind し直してください

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
4. `vinberod -c vinbero.yml` 再起動 → Bridge/VRF reconcile、vrf_id と実行時 AC の復元、XDP attach、API で作った binding の復元 が自動で走る
5. SID / Headend を再投入:
   - `pin_maps: false`: **外部コントローラから全部再投入**
   - `pin_maps: true`: RPC で入れたエントリは bpffs から復元されるので再投入不要。BGP を有効にした起動では、BGP の applier が書いたエントリは起動時に消え、経路を受信し直すと戻ります
6. **Plugin は常に再登録**が必要 (`vinbero plugin register ...`)
7. トラフィック監視 (`vinbero stats show`, `stats slot show`) で正常性確認

schema を変更したときは手順 3 の後に `rm -rf /sys/fs/bpf/vinbero/` を挟んでから再起動。

## 将来拡張候補

- daemon hand-off による **hitless restart** (XDP link の継承 + pin 済み map 引き継ぎで無停止更新)
- Plugin の auto re-register (`plugins:` セクションを vinbero.yml に追加し、起動時に自動ロード)
- schema migration ツール (`vinbero admin pin-migrate` 等で capacity 変更を無停止適用)

これらは未実装です。現状は `pin_maps: true` でデータは残せますが、再登録が必要なのは XDP attach と plugin、capacity/schema 変更時のリロードです。
