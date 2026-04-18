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

`pkg/netresource/manager.go` の ResourceManager が:
1. 起動時に `state.json` を読み込み、記録されていた Bridge / VRF デバイスを netlink で確認
2. 欠けていれば再作成 (`ip link add` 相当)
3. 存在するものは ifindex を state に書き直して更新
4. 稼働中に `vinbero bridge create` / `vrf create` 等で変更があれば都度 disk に flush

これにより、`sudo reboot` した後でも `vinbero bridge list` で以前と同じ Bridge が見えます (daemon が自動で restore する)。

state.json フォーマットは内部実装扱いで、手編集は非推奨です。`vinbero` CLI 経由で操作してください。

## BPF マップ: in-memory vs pinned

SRv6 制御状態 (`sid_function_map`, `sid_aux_map`, `headend_*_map`, `fdb_map`, `bd_peer_map`, `bd_peer_reverse_map`, `dx2v_map`) は daemon が所有する eBPF マップです。`settings.pin_maps.enabled` で挙動が切り替わります。

### `pin_maps.enabled: false` (default)

- **daemon 終了 = map 消滅 = データ消滅**
- 次回起動時は空の map でスタート
- 既存エントリの引き継ぎは一切なし
- クライアント側 (API caller) が残りの状態を保持している前提

大量の SID を扱う運用では外部 DB / etcd / Kubernetes CRD 等に正本を置き、daemon 起動時に一括再投入する "external SoT" モデルが向きます。

### `pin_maps.enabled: true`

cilium/ebpf の `PinByName` で、対象 9 マップを `/sys/fs/bpf/<path>/<map_name>` に pin します (`path` はデフォルト `/sys/fs/bpf/vinbero`)。

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

### 破壊的変更時の注意

**schema / capacity を変えたときは pin dir を削除**してください。BPF map の `max_entries` や value サイズは作成後に変更不可なので、cilium/ebpf は pin された既存 map と spec の不一致を見ると load エラーを返します。

```bash
sudo systemctl stop vinberod
sudo rm -rf /sys/fs/bpf/vinbero
sudo systemctl start vinberod
```

典型的にハマる場面:
- `settings.entries.*.capacity` を変更した
- Vinbero をアップグレードして BPF struct layout が変わった (例: plugin SDK v2 で `sid_function_entry` が 12B → 4B)
- マップ名が変わった

### Aux index の allocator recovery

pin 有効時は特に重要なメカニズム (`pkg/bpf/maps.go::RecoverAuxIndices`):

起動直後に `sid_function_map` を iterate して、`aux_index != 0` のエントリが参照している index を allocator が使用中としてマーク。gap 部分を free list に戻します。pin された map を reuse したとき、allocator がすでに使われている index を二重に払い出さないためのガード。

pin 無効時は map が空なので recovery しても何も起きず、結果的に allocator は fresh start します (= 従来挙動)。

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
