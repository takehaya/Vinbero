# Persistence (永続化) と再起動時の挙動

「daemon (`vinberod`) を落とした / 再起動した後、何が残り、何が消え、何が自動で戻るか」をまとめたドキュメントです。運用スクリプトや構成管理 (Ansible / etc.) で **どのリソースを何度も投入し直す必要があるか** を判断する基準になります。

## TL;DR

| リソース | `pin_maps: false` (default) | `pin_maps: true` | 復旧手段 |
|---|---|---|---|
| `vinbero.yml` (設定ファイル) | 残る (disk) | 残る | そのまま再ロード |
| XDP プログラムの attach | **消える** | **消える** | daemon 起動時に `internal.devices` に attach し直す |
| SID function / aux | **消える** | **残る** (bpffs pin) | default: RPC / CLI で再投入 |
| Headend v4 / v6 / L2 | **消える** | **残る** (bpffs pin) | default: RPC / CLI で再投入 |
| BD peer / VLAN table / FDB | **消える** | **残る** (bpffs pin) | default: RPC / CLI (FDB は学習でも埋まる) |
| Bridge / VRF デバイス | カーネル netlink に残る / netns 単位 | 同左 | `state.json` から **自動 reconcile** |
| 登録済み plugin (`PROG_ARRAY`) | **消える** | **消える** (pin しない) | register RPC を再実行 |
| Global stats / per-slot stats | **消える** | **消える** (pin しない) | 自然増加で埋まる |

デフォルトは **外部コントローラが source of truth** として振る舞う設計 (`pin_maps: false`)。SRv6 制御状態は API クライアント側で保持します。`pin_maps: true` に切り替えれば kernel 側に BPF マップを残せるので、daemon 単体でステートフル運用できます。

## 永続化層: `state.json`

Vinbero が daemon 内部で持つ状態のうち **永続化されるのは Network Resource (Bridge / VRF) のみ** です。保存先は `settings.state_path` (デフォルト `/var/lib/vinbero/state.json`)。

これは `state.json` の対象範囲です。control-plane plugin の module と登録内容は
別の [cplane store](cplane-plugin.md) に保存されますが、local SID の名前と address の
対応は現状 daemon の memory にのみあります。再起動後の SID と残存 entry の照合は
[cplane 移行計画 B](cplane-evolution.md) の対象で、登録の保存だけでは保証されません。

`pkg/netresource/manager.go` の ResourceManager が:
1. 起動時に `state.json` を読み込み、記録されていた Bridge / VRF デバイスを netlink で確認
2. 欠けていれば再作成 (`ip link add` 相当)
3. 存在するものは Create と同じ検証と収束で adopt する (link 種別の確認、up、不足 member の enslave、ifindex の更新)
4. 稼働中に `vinbero vrf create` や `vinbero vrf bridge-attach` で変更があれば都度 disk に flush (VRF device も bridge も VrfService 経由で、vrf_id を持つ一級 VRF object の facet として管理される。bridge の state record は owning VRF 名も持つ)

これにより、`sudo reboot` した後でも `vinbero vrf show` の BRIDGE / BD_ID 列に以前と同じ Bridge が見えます (daemon が自動で restore する)。

堅牢性は次の 3 点で担保します。

- 書き込みは atomic です。同一ディレクトリの temp file に書いて fsync してから rename するので、書き込み途中の crash や ENOSPC でも直前の state.json が無傷で残ります。
- 保存の失敗は RPC エラーとして返ります (旧実装は warn に落として成功を返していた)。kernel device とメモリ上の記録は巻き戻さず、次に成功した保存が全量を書き直して収束します。
- boot の reconcile は fail-closed です。state の entry が実体化できない場合 (member NIC の消失、名前を別種の link に取られた等) は、entry 名と修復手順 (デバイスの復旧か entry の削除) を示すエラーで起動を拒否します。stale な ifindex のまま続行すると FDB watcher / EVPN / SID 参照ガードが誤った index で動くためです。parse できない state.json も同様に起動を拒否します (空 state で始めると管理下のデバイスを黙って放棄することになるため)。

state.json フォーマットは内部実装扱いで、手編集は非推奨です。`vinbero` CLI 経由で操作してください (例外は上記の修復手順と、bridge record の owning VRF 付け替え)。

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
- **daemon 起動時**: pin dir に map が無ければ新規作成して pin、既にあれば既存 map を reuse
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

### 破壊的変更時の注意

**schema / capacity を変えたときは pin dir を削除**してください。BPF map の `max_entries` や value サイズは作成後に変更不可なので、cilium/ebpf は pin された既存 map と spec の不一致を見ると load エラーを返します。

```bash
sudo systemctl stop vinberod
sudo rm -rf /sys/fs/bpf/vinbero
sudo systemctl start vinberod
```

典型的にハマる場面:
- `settings.entries.*.capacity` を変更した
- Vinbero をアップグレードして BPF struct layout が変わった (例: plugin SDK v2 で `sid_function_entry` が 12B → 4B、SDK v4 で `headend_entry` が 204B → 208B)
- マップ名が変わった

ECMP path group の導入 (plugin SDK v4) で `headend_entry` のサイズが変わったため、pin_maps を有効にしたまま v4 より前の Vinbero から in-place upgrade すると headend 系と `bd_peer_map` の pin が不一致で load に失敗します。上の手順で pin dir を削除してから起動してください。

### Aux index の allocator recovery

pin 有効時は特に重要なメカニズム (`pkg/bpf/maps.go::RecoverAuxIndices`):

Phase 2 で `aux_owner_map` (BPF ARRAY map) を `sid_aux_map` と同じ keyspace で導入しました。各 index に対し owner タグ (`builtin:v1` か `plugin:v1:<mapType>:<slot>`) を持ち、`pinnedControlMaps` の一員として pin されます。

起動時のフロー:

1. `aux_owner_map` が空でなければそれを iterate して owner を再構築 (Phase 2 path)。**独立 PluginAux も復元される**ため、SID に bind されていない索引も daemon 再起動を跨いで生存します。
2. 空のときは fallback として `sid_function_map` を iterate して owner を再構築 (Phase 1d 互換)。再構築後 `aux_owner_map` に書き戻し、次回起動以降は Phase 2 path を取ります (legacy → v1 forward migration)。

pin 無効時は `aux_owner_map` も in-memory なので、allocator は fresh start します (= 従来挙動)。

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
vinbero hv4 / hv6 / hl2 flush --yes  # Headend 各種
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
4. `vinberod -c vinbero.yml` 再起動 → XDP attach + Bridge/VRF reconcile が自動で走る
5. SID / Headend を再投入:
   - `pin_maps: false`: **外部コントローラから全部再投入**
   - `pin_maps: true`: 前回のエントリが bpffs から復元されるので再投入不要
6. **Plugin は常に再登録**が必要 (`vinbero plugin register ...`)
7. トラフィック監視 (`vinbero stats show`, `stats slot show`) で正常性確認

schema を変更したときは手順 3 の後に `rm -rf /sys/fs/bpf/vinbero/` を挟んでから再起動。

## 将来拡張候補

- daemon hand-off による **hitless restart** (XDP link の継承 + pin 済み map 引き継ぎで無停止更新)
- Plugin の auto re-register (`plugins:` セクションを vinbero.yml に追加し、起動時に自動ロード)
- schema migration ツール (`vinbero admin pin-migrate` 等で capacity 変更を無停止適用)

これらは未実装です。現状は `pin_maps: true` でデータは残せますが、再登録が必要なのは XDP attach と plugin、capacity/schema 変更時のリロードです。
