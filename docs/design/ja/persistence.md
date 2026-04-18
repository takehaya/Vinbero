# Persistence (永続化) と再起動時の挙動

「daemon (`vinberod`) を落とした / 再起動した後、何が残り、何が消え、何が自動で戻るか」をまとめたドキュメントです。運用スクリプトや構成管理 (Ansible / etc.) で **どのリソースを何度も投入し直す必要があるか** を判断する基準になります。

## TL;DR

| リソース | 再起動で | 復旧手段 |
|---|---|---|
| `vinbero.yml` (設定ファイル) | 残る (disk) | そのまま再ロード |
| XDP プログラムの attach | **消える** | daemon 起動時に `internal.devices` に attach し直す |
| SID function / aux | **消える** (daemon 内 in-memory map) | RPC / CLI で再投入 |
| Headend v4 / v6 / L2 | **消える** | RPC / CLI で再投入 |
| BD peer / VLAN table / FDB (dynamic) | **消える** | RPC / CLI で再投入 (FDB は学習でも埋まる) |
| Bridge / VRF デバイス | カーネル netlink に残る / netns 単位 | `state.json` から **自動 reconcile** |
| 登録済み plugin (`PROG_ARRAY`) | **消える** | register RPC を再実行 |
| Global stats / per-slot stats | **消える** (PERCPU_ARRAY) | 自然増加で埋まる |

基本原則: **ネットワークリソース (Bridge / VRF) のみ disk 永続化、それ以外は in-memory**。SRv6 制御状態は外部コントローラ (API クライアント) が source of truth として保持する想定です。

## 永続化層: `state.json`

Vinbero が daemon 内部で持つ状態のうち **永続化されるのは Network Resource (Bridge / VRF) のみ** です。保存先は `settings.state_path` (デフォルト `/var/lib/vinbero/state.json`)。

`pkg/netresource/manager.go` の ResourceManager が:
1. 起動時に `state.json` を読み込み、記録されていた Bridge / VRF デバイスを netlink で確認
2. 欠けていれば再作成 (`ip link add` 相当)
3. 存在するものは ifindex を state に書き直して更新
4. 稼働中に `vinbero bridge create` / `vrf create` 等で変更があれば都度 disk に flush

これにより、`sudo reboot` した後でも `vinbero bridge list` で以前と同じ Bridge が見えます (daemon が自動で restore する)。

state.json フォーマットは内部実装扱いで、手編集は非推奨です。`vinbero` CLI 経由で操作してください。

## In-memory: BPF マップ群

SRv6 制御状態 (`sid_function_map`, `sid_aux_map`, `headend_*_map`, `fdb_map`, `bd_peer_map`, `dx2v_map` 等) はすべて **daemon が所有する eBPF マップ**で、`/sys/fs/bpf/` への pin は行なっていません。このため:

- **daemon 終了 = map 消滅 = データ消滅**
- 次回起動時は空の map でスタート
- 既存エントリの引き継ぎは一切なし

クライアント側 (API caller) が残りの状態を保持している前提の設計です。大量の SID を扱う運用では、外部 DB / etcd / Kubernetes CRD 等に正本を置き、daemon 起動時に一括再投入するのが正攻法になります。

### Aux index の allocator recovery

唯一の例外として、**map 内の既存エントリを読んで allocator 状態を復元する仕組み**が 1 箇所あります (`pkg/bpf/maps.go::RecoverAuxIndices`):

起動直後に `sid_function_map` を iterate して、`aux_index != 0` のエントリが参照している index を allocator が使用中としてマーク。gap 部分を free list に戻します。これは daemon を **map の pin 化 (将来機能)** なしで再起動する場面、または手動で kernel map に直接書き込まれた場合の整合性確保のための防御策です。

現状は `/sys/fs/bpf` pin が無いため実質「再起動 = map 空 = allocator も初期状態」ですが、将来 pin 永続化を入れたときにこのパスが生きます。

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
3. (必要なら) `ip link set dev <iface> xdp off` を実行、`make remove-ebpfmap` で残骸掃除
4. `vinberod -c vinbero.yml` 再起動 → XDP attach + Bridge/VRF reconcile が自動で走る
5. **外部コントローラから SID / Headend / plugin を再投入**
6. トラフィック監視 (`vinbero stats show`, `stats slot show`) で正常性確認

## 将来拡張候補

- BPF マップの `/sys/fs/bpf` pin + daemon hand-off による hitless restart
- SRv6 制御状態の state.json 永続化拡張 (Bridge/VRF と同様に SID も disk に書く)
- Plugin の auto re-register (`plugins:` セクションを vinbero.yml に追加)

これらは未実装です。現時点では上記「外部が source of truth」の前提で運用してください。
