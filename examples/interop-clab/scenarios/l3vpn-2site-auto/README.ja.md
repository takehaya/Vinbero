# l3vpn-2site-auto — auto-advertise SRv6 L3VPN interop (Vinbero ⇄ FRR)

*(English: [README.md](./README.md))*

[l3vpn-2site](../l3vpn-2site/) の auto-advertise 版。トポロジ・アドレッシング・FRR PE は同一で、違いは Vinbero PE が顧客経路をどう originate するかだけ。

`l3vpn-2site` では Vinbero は `vbctl sid create` + `vbctl bgp advertise-vpn` の明示呼び出しで `10.1.0.0/24` を広告する。ここでは **config から自動的に** 広告する — `bgp.global.auto_advertise: true` と、`redistribute: [static]` を持つ `vrf_bindings` エントリを置く。exporter (`pkg/bgp/export`) が `LOC1` から End.DT4/DT6 service SID を採番し、VRF-local prefix を自前で広告する。`vbctl` 呼び出しは不要で、受信方向の `pkg/bgp/apply` と対になる送信方向の実装。

## l3vpn-2site との差分

- **vinbero/vinbero.yml**: `bgp.locators` が `LOC1` を静的に宣言する (exporter は起動時、RPC より前に binding の `default_locator` を解決する)。`bgp.global.auto_advertise: true`。`bgp.global.next_hop` は PE の loopback (BGP next hop は通常のノードアドレスである必要がある。locator base は subnet-router anycast アドレスで、受信側 PE が local 扱いして転送が壊れる)。`vrf_bindings` が `rd` / `import_rts` / `export_rts` / `default_locator` / `redistribute` を持つ。
- **vinbero/start.sh**: `vbctl sid create` / `bgp advertise-vpn` がない。顧客経路は `proto static` で追加し、`redistribute: [static]` allowlist が転送するようにする (素の `ip route` は `RTPROT_BOOT` で、casual な経路が VPN に漏れるのを避けるため除外される)。
- **frr/start.sh**: /128 glue 経路の向き先が、手動の `fd00:100:0:1::` でなく auto 採番された SID `fd00:100:0:10::` (function `0x10`、最初に auto 割り当てされる End.DT4) になる。

広告される SID は動的なので、`test.sh` は SID をハードコードせず Vinbero の End.DT4 SID を discover する。

## 実行

Docker・`containerlab`・`sudo` が必要。`examples/interop-clab/` から:

```bash
make all SCENARIO=l3vpn-2site-auto
```

## test.sh が検証する内容

`l3vpn-2site` と同じ 4 点 — iBGP Established、FRR → Vinbero の SRv6 Service TLV decode (RFC 9252 §4 transposition 込み)、Vinbero → FRR encode、`ce-tokyo` ⇄ `ce-osaka` 間の双方向 `ping` が SRv6 L3VPN を通ること。違いは Vinbero → FRR の経路が operator の RPC なしに auto-advertise exporter で originate される点。
