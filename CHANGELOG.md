# Changelog

## [0.1.0](https://github.com/takehaya/Vinbero/compare/v0.0.10...v0.1.0) (2026-07-12)


### ⚠ BREAKING CHANGES

* **vrfbgp:** derive the EVPN bridge domain from the VRF bridge facet ([#98](https://github.com/takehaya/Vinbero/issues/98))

### 🎉 Features

* **bgp/evpn:** rescue early EVPN routes with an attach/bind-time loc-rib replay ([#99](https://github.com/takehaya/Vinbero/issues/99)) ([4dd96b3](https://github.com/takehaya/Vinbero/commit/4dd96b3c8807c5fe445d37e3bbd13cb9a2244a9c))
* **bpf/ecmp:** weighted ECMP path groups in the headend data plane ([#101](https://github.com/takehaya/Vinbero/issues/101)) ([54fab68](https://github.com/takehaya/Vinbero/commit/54fab689c7d198773eb090ae52876c9e58bc355b))
* **examples:** headend ECMP path-group netns example with fast-reroute demo ([#103](https://github.com/takehaya/Vinbero/issues/103)) ([84992ea](https://github.com/takehaya/Vinbero/commit/84992ea83bc7cf8f7a1a569a3f41eff16225a248))
* **vrf:** absorb the EVPN bridge-domain lifecycle into the VRF object ([#97](https://github.com/takehaya/Vinbero/issues/97)) ([7bbb672](https://github.com/takehaya/Vinbero/commit/7bbb6728850efa9808ed7b88e2b69855d7e464c3))
* **vrf:** absorb the kernel-VRF device lifecycle into the VRF object ([#95](https://github.com/takehaya/Vinbero/issues/95)) ([53f9cb2](https://github.com/takehaya/Vinbero/commit/53f9cb262a8e3b7fbce5edb3139f57575caa948d))
* **vrfbgp:** derive the EVPN bridge domain from the VRF bridge facet ([#98](https://github.com/takehaya/Vinbero/issues/98)) ([fdc0274](https://github.com/takehaya/Vinbero/commit/fdc0274ab08e5d9b9fe1aae8e1f6d81e55180726))


### 🐛 Bug Fixes

* **bpf/endpoint:** keep the End.B6 noinline boundary at five register args ([#102](https://github.com/takehaya/Vinbero/issues/102)) ([42b549b](https://github.com/takehaya/Vinbero/commit/42b549b9fdec68c88969137ea6b246d0c3915ecc))
* **netresource:** atomic state writes, error propagation, fail-closed reconcile ([#100](https://github.com/takehaya/Vinbero/issues/100)) ([21a02db](https://github.com/takehaya/Vinbero/commit/21a02db931d0cab778bcdeb249f11ecd93350006))

## [0.0.10](https://github.com/takehaya/Vinbero/compare/v0.0.9...v0.0.10) (2026-06-21)


### 🎉 Features

* **bgp/mup:** land v4src position extraction + uplink service instances into main ([#88](https://github.com/takehaya/Vinbero/issues/88) + [#89](https://github.com/takehaya/Vinbero/issues/89)) ([#90](https://github.com/takehaya/Vinbero/issues/90)) ([911ecad](https://github.com/takehaya/Vinbero/commit/911ecad4fe485fec2c1e830dc99f9afb86179391))
* **bgp/mup:** per-VRF GTP4 source-embed prefix, locator-derived SID Structure, ipv4_unicast family ([#86](https://github.com/takehaya/Vinbero/issues/86)) ([0e66a0a](https://github.com/takehaya/Vinbero/commit/0e66a0ac30caa03de06bf86aaf71b20e19454c18))
* **endpoint:** no-SRH dual-path End.M.GTP4.E / End.M.GTP6.E + macro ([#83](https://github.com/takehaya/Vinbero/issues/83)) ([b21b607](https://github.com/takehaya/Vinbero/commit/b21b607d95cc8e6c368607c3da5174608f2453c7))
* **vrf-bgp:** unified family-scoped binding with per-family RT/RD policy ([#85](https://github.com/takehaya/Vinbero/issues/85)) ([b5975ac](https://github.com/takehaya/Vinbero/commit/b5975ac3888c59066b20e7c7503a34cbc9d4ca82))
* **vrf:** promote VRF to a first-class object; fold ingress front door + MUP uplink in ([#94](https://github.com/takehaya/Vinbero/issues/94)) ([4b24119](https://github.com/takehaya/Vinbero/commit/4b2411979ce2fe156b3e541fd212c4d080569588))


### 🐛 Bug Fixes

* **bgp/mup:** pin gobgp fork tag carrying draft-01 T1ST framing + Prefix-SID behavior ([#82](https://github.com/takehaya/Vinbero/issues/82)) ([0d9407b](https://github.com/takehaya/Vinbero/commit/0d9407b664fe0b9b5062e1bb6ca7fcc66691d3ce))
* **interop-clab/mup-2site:** per-advertiser RDs, import-RT filter, RFC 9433 §6.6 source embed ([#87](https://github.com/takehaya/Vinbero/issues/87)) ([426300e](https://github.com/takehaya/Vinbero/commit/426300ee2986119b9c3d693bb346c671a51ebdd7))


### 🔧 Miscellaneous Chores

* **interop-clab:** move the license-restricted interop assets to a private overlay repo ([#92](https://github.com/takehaya/Vinbero/issues/92)) ([9e07595](https://github.com/takehaya/Vinbero/commit/9e07595216cbcb7e302174973cb8f7dcd26595d6))
* **interop-clab:** neutral overlay paths in .gitignore ([#93](https://github.com/takehaya/Vinbero/issues/93)) ([1ff91de](https://github.com/takehaya/Vinbero/commit/1ff91de02c5ff05eb81c5947f65e99c48fec29e4))

## [0.0.9](https://github.com/takehaya/Vinbero/compare/v0.0.8...v0.0.9) (2026-06-03)


### 🐛 Bug Fixes

* **release:** unify SDK staging and fix include/core packaging ([#80](https://github.com/takehaya/Vinbero/issues/80)) ([97670cb](https://github.com/takehaya/Vinbero/commit/97670cb9f4038ad32212a538f61c141f3082c370))


### 📝 Documentation

* **readme:** bump pinned install example to v0.0.8 ([#79](https://github.com/takehaya/Vinbero/issues/79)) ([2ba8a23](https://github.com/takehaya/Vinbero/commit/2ba8a237d41c945c80ae9af339eb8bb23c9e91d6))

## [0.0.8](https://github.com/takehaya/Vinbero/compare/v0.0.7...v0.0.8) (2026-06-03)


### 🐛 Bug Fixes

* **cli:** stamp vinbero CLI version from build ldflags ([#77](https://github.com/takehaya/Vinbero/issues/77)) ([2008036](https://github.com/takehaya/Vinbero/commit/200803693c02d4597acad1ce8e6d0eede106f3f2))

## [0.0.7](https://github.com/takehaya/Vinbero/compare/v0.0.6...v0.0.7) (2026-06-03)


### 🐛 Bug Fixes

* **release:** ship SDK tarball without binaries and verify goreleaser install ([#75](https://github.com/takehaya/Vinbero/issues/75)) ([278c9be](https://github.com/takehaya/Vinbero/commit/278c9be2843b7997f435a897ff69a262db2891c3))

## [0.0.6](https://github.com/takehaya/Vinbero/compare/v0.0.5...v0.0.6) (2026-06-03)


### 🐛 Bug Fixes

* **build:** pin goreleaser to v2.13.0 for Go 1.25 compatibility ([#73](https://github.com/takehaya/Vinbero/issues/73)) ([85a5c25](https://github.com/takehaya/Vinbero/commit/85a5c259ccc62a5d3dca7aa3d9b76713c6d4644f))

## [0.0.5](https://github.com/takehaya/Vinbero/compare/v0.0.4...v0.0.5) (2026-06-03)


### 🎉 Features

* **scripts:** add one-liner installer for prebuilt binaries ([#70](https://github.com/takehaya/Vinbero/issues/70)) ([bb5c1f5](https://github.com/takehaya/Vinbero/commit/bb5c1f54685b8d4757bd65d026a1d5d00912911c))


### 📝 Documentation

* **srv6-bgp:** quote Mermaid edge labels containing parens and slashes ([#71](https://github.com/takehaya/Vinbero/issues/71)) ([6499e00](https://github.com/takehaya/Vinbero/commit/6499e00506290c9aee4c47e6f9022ec00c82aa36))

## [0.0.4](https://github.com/takehaya/Vinbero/compare/v0.0.3...v0.0.4) (2026-06-03)


### 🎉 Features

* BGP SR Policy (SAFI 73) reception + color-based steering (Phase 1e-c) ([#41](https://github.com/takehaya/Vinbero/issues/41)) ([d274093](https://github.com/takehaya/Vinbero/commit/d2740930409eacff41a1663924443498116f6a99))
* **bgp:** advertise a local SR Policy into BGP via a per-policy flag ([#58](https://github.com/takehaya/Vinbero/issues/58)) ([5172274](https://github.com/takehaya/Vinbero/commit/51722749fad75ac227f0d0764a7737d46b9d0bbb))
* **bgp:** EVPN auto-advertise binding-axis + exporter hardening ([#55](https://github.com/takehaya/Vinbero/issues/55)) ([9ecd5b0](https://github.com/takehaya/Vinbero/commit/9ecd5b06cbe870c99feaab1e838efa1826eea1f2))
* **bgp:** EVPN RT2 auto-advertise (local MAC → RT2) ([#50](https://github.com/takehaya/Vinbero/issues/50)) ([8f79090](https://github.com/takehaya/Vinbero/commit/8f790900e99fa506d3dbbbe7b0b3606bacc2457c))
* **bgp:** EVPN RT3 (Inclusive Multicast / BUM) auto-advertise ([#54](https://github.com/takehaya/Vinbero/issues/54)) ([ccc2ee5](https://github.com/takehaya/Vinbero/commit/ccc2ee5030ee30212566b9d256d959adaf71d23a))
* **bgp:** EVPN RT4 (Ethernet Segment) auto-advertise ([#52](https://github.com/takehaya/Vinbero/issues/52)) ([a3a0163](https://github.com/takehaya/Vinbero/commit/a3a0163404a01eeb75020047a154036f4777223e))
* **bgp:** MupService CRUD to originate local BGP MUP routes (SAFI 85) ([#59](https://github.com/takehaya/Vinbero/issues/59)) ([7e51b90](https://github.com/takehaya/Vinbero/commit/7e51b90a156ce7c1595cb3b9f2b7148edb247eff))
* **bgp:** replay a bridge's existing FDB on enable for EVPN RT2 ([#53](https://github.com/takehaya/Vinbero/issues/53)) ([740725c](https://github.com/takehaya/Vinbero/commit/740725c80feae212686f968be6e79b1462f60811))
* **bgp:** RPC-driven VRF auto-advertise ([#49](https://github.com/takehaya/Vinbero/issues/49)) ([6c8bd1d](https://github.com/takehaya/Vinbero/commit/6c8bd1df009c9eaac0727712bb57315b94f3d156))
* **bgp:** unify advertise next-hop validation + per-service origination caps ([#60](https://github.com/takehaya/Vinbero/issues/60)) ([d8025ea](https://github.com/takehaya/Vinbero/commit/d8025ea496670e83abb0551af6278f07e7e48129))
* **bgp:** VRF-export driven automatic advertise (Phase 2a/2b) ([#48](https://github.com/takehaya/Vinbero/issues/48)) ([b21c1bf](https://github.com/takehaya/Vinbero/commit/b21c1bf2051f4e534e9e57e0aa91dcdd23b56c4f))
* EVPN over SRv6 (RFC 9252) — RT2/RT3/RT4 + multi-homing DF/split-horizon (Phase E1-E3) ([#44](https://github.com/takehaya/Vinbero/issues/44)) ([9d7bbed](https://github.com/takehaya/Vinbero/commit/9d7bbed457bb5733c8c430278991859655a08016))
* **headend:** plumb args_offset through Headendv6 so H.M.GTP6.D is usable; fix gtp6-encap ([#67](https://github.com/takehaya/Vinbero/issues/67)) ([fe270d0](https://github.com/takehaya/Vinbero/commit/fe270d0c2c8dcc297544ba53989a67f401c074e9))
* SRv6 MUP (RFC 9433 + draft-mpmz-bess-mup-safi) — BGP MUP SAFI 85 + GTP4/6 data plane + segment-discovery SID resolution ([#45](https://github.com/takehaya/Vinbero/issues/45)) ([9e0528f](https://github.com/takehaya/Vinbero/commit/9e0528fd610d3dd1d70b15979692b2a8ea79db48))


### 🐛 Bug Fixes

* **examples:** correct false-green FDB test, daemon leaks, and doc drift ([#69](https://github.com/takehaya/Vinbero/issues/69)) ([22a1112](https://github.com/takehaya/Vinbero/commit/22a1112505cb598463255b7f2eaabe93eac52691))
* **examples:** make gtp4-encap actually transform GTP-U-&gt;SRv6, add it to CI ([#65](https://github.com/takehaya/Vinbero/issues/65)) ([ae2ca8f](https://github.com/takehaya/Vinbero/commit/ae2ca8f9b0b908fa3e95286e1c57f3c230f2d0aa))
* **gobgp:** bound Session.Stop() so a wedged gobgp teardown can't hang ([#47](https://github.com/takehaya/Vinbero/issues/47)) ([682b264](https://github.com/takehaya/Vinbero/commit/682b26479b7ddb7ac8eb464ce8352ea6e525e14f))


### 📝 Documentation

* **examples:** refresh stale READMEs (netns + interop-clab) ([#62](https://github.com/takehaya/Vinbero/issues/62)) ([fb88467](https://github.com/takehaya/Vinbero/commit/fb884678d9c370f27ce9276272f56ec7f3ec6f53))
* **loadmap:** mark EVPN (RT2/3/4) as Supported ([#46](https://github.com/takehaya/Vinbero/issues/46)) ([4dfedef](https://github.com/takehaya/Vinbero/commit/4dfedef21a1b33cef8ac9cc4bb234befed31bcbf))
* **loadmap:** mark SR Policy (SAFI 73) as Supported ([#43](https://github.com/takehaya/Vinbero/issues/43)) ([1784e65](https://github.com/takehaya/Vinbero/commit/1784e65d76314b9d075bec5283455443c7b90188))


### ♻️ Code Refactoring

* **bgp:** idempotent EVPN EnableBD + shared next-hop validation ([#56](https://github.com/takehaya/Vinbero/issues/56)) ([e82d5fd](https://github.com/takehaya/Vinbero/commit/e82d5fd02a1ac1aaf58c1a3e829a14275bdc67c9))
* **bgp:** make L3VPN AddVRF idempotent on an unchanged re-bind ([#57](https://github.com/takehaya/Vinbero/issues/57)) ([30b2509](https://github.com/takehaya/Vinbero/commit/30b250908d83e31b1937118dfcc8baad6f03227d))
* **examples:** hoist test_ping_with_counter into common/test_utils.sh ([#64](https://github.com/takehaya/Vinbero/issues/64)) ([d94d6b2](https://github.com/takehaya/Vinbero/commit/d94d6b221e38ae12670dce76cd085c225a615015))

## [0.0.3](https://github.com/takehaya/Vinbero/compare/v0.0.2...v0.0.3) (2026-05-20)


### 🎉 Features

* **bgp:** integrate GoBGP for SRv6 service route exchange (Phase 1) ([#39](https://github.com/takehaya/Vinbero/issues/39)) ([00b521b](https://github.com/takehaya/Vinbero/commit/00b521b1b35d7fdc510d67f57f84312942d19860))
* **bpf:** scaffold L2 headend tail-call infrastructure (Phase 1) ([#29](https://github.com/takehaya/Vinbero/issues/29)) ([0ee3e5f](https://github.com/takehaya/Vinbero/commit/0ee3e5f573ae3c9150dc7fee8066cf65e61c9649))
* End.DT2M + EVPN multi-homing (RFC 7432/9252 Split-Horizon + DF) ([#22](https://github.com/takehaya/Vinbero/issues/22)) ([c00bcea](https://github.com/takehaya/Vinbero/commit/c00bcea7e4f9c83976473231d5b509c83ad15cb9))
* plugin SDK Phase 1c/1d — map classification + typed aux lifecycle ([#23](https://github.com/takehaya/Vinbero/issues/23)) ([8dc0f39](https://github.com/takehaya/Vinbero/commit/8dc0f392c7e019788ef7b0b69dab8f51c8c87b83))
* plugin SDK v2 + BTF-driven aux JSON + per-slot stats ([#21](https://github.com/takehaya/Vinbero/issues/21)) ([fa69f06](https://github.com/takehaya/Vinbero/commit/fa69f0606a033b49c6aba7b616cefed2391873a3))
* plugin SDK with static validator, VINBERO_PLUGIN macro, samples ([#19](https://github.com/takehaya/Vinbero/issues/19)) ([a372b7d](https://github.com/takehaya/Vinbero/commit/a372b7de900cbdbdcbdb09e403d01d544a8d2835))
* **sdk:** publish a goreleaser tarball alongside the binaries ([#24](https://github.com/takehaya/Vinbero/issues/24)) ([05decd7](https://github.com/takehaya/Vinbero/commit/05decd7c4ff2df732acd7e9a49b6595a89c09dd4))
* SRv6 L3VPN interop lab (containerlab) + RFC 9252 SID transposition fix ([#40](https://github.com/takehaya/Vinbero/issues/40)) ([bb7853e](https://github.com/takehaya/Vinbero/commit/bb7853e72d15eea85bdc5925faf6cecabd41736b))


### 🐛 Bug Fixes

* **bpf:** make src/core/srv6.h self-sufficient by including linux/in6.h ([#27](https://github.com/takehaya/Vinbero/issues/27)) ([a90767a](https://github.com/takehaya/Vinbero/commit/a90767ac6bf022247299e84d46deb48419f79c98))


### 🔧 Miscellaneous Chores

* land squashed [#25](https://github.com/takehaya/Vinbero/issues/25) and [#26](https://github.com/takehaya/Vinbero/issues/26) onto main ([#28](https://github.com/takehaya/Vinbero/issues/28)) ([70fcf1e](https://github.com/takehaya/Vinbero/commit/70fcf1e0917334e5eca2228b57c294c618d4dced))

## [0.0.2](https://github.com/takehaya/Vinbero/compare/v0.0.1...v0.0.2) (2026-04-16)


### 🎉 Features

* add config load ([019a566](https://github.com/takehaya/Vinbero/commit/019a56647e588c58bb7285bc768b9c10d2dc7104))
* add connectrpc and protobuf and mapping define ([21e2066](https://github.com/takehaya/Vinbero/commit/21e2066b8c66850436b8025d0742b88f03ba0246))
* add end behavior ([92e329d](https://github.com/takehaya/Vinbero/commit/92e329d6778e8d199fc6c29947e6de88d8d3c021))
* add end behavior ([a034107](https://github.com/takehaya/Vinbero/commit/a034107ef80caf481f81d9986a27ac5fc2490a9e))
* add NetworkResourceService and vinbero CLI ([5bc81b4](https://github.com/takehaya/Vinbero/commit/5bc81b41e231b1663a3112691282115518a0355b))
* add NetworkResourceService for VRF/Bridge management via API ([0c526e6](https://github.com/takehaya/Vinbero/commit/0c526e684f338074cb83fe72ca328b97a4d0a2c5))
* add vinbero CLI and rename daemon to vinberod ([a092ebb](https://github.com/takehaya/Vinbero/commit/a092ebb7ce86685003b20804152bd58069beefe6))
* base code ([8ed0582](https://github.com/takehaya/Vinbero/commit/8ed0582ecbfcd245a8dc1325b235743d35ed6fb3))
* implement End.B6.Insert/Encaps with Reduced SRH variants ([#13](https://github.com/takehaya/Vinbero/issues/13)) ([4d2fb36](https://github.com/takehaya/Vinbero/commit/4d2fb369232a780c77ebd01ed254a4ab6ddd0f43))
* implement End.DX2V VLAN cross-connect (RFC 8986 Sec.4.10) ([#18](https://github.com/takehaya/Vinbero/issues/18)) ([e524075](https://github.com/takehaya/Vinbero/commit/e5240750f2cd8d3c0e92eb3a59140a0515aa1310))
* implement End.X, End.T and SRv6 flavors (PSP/USP/USD) ([63fd6ee](https://github.com/takehaya/Vinbero/commit/63fd6eead2891b21c3b013036ceb81788ef15961))
* implement End.X, End.T and SRv6 flavors (PSP/USP/USD) ([493e1b2](https://github.com/takehaya/Vinbero/commit/493e1b29fbaebda89a2c0f9d87bf77e1c14a9d7e))
* implement GTP-U/SRv6 interworking functions (RFC 9433) ([#14](https://github.com/takehaya/Vinbero/issues/14)) ([3f8f310](https://github.com/takehaya/Vinbero/commit/3f8f3106a66c3f6077c31d755b69ed520e3202d6))
* pluggable XDP data plane with BPF tail call dispatch ([#16](https://github.com/takehaya/Vinbero/issues/16)) ([3ff411f](https://github.com/takehaya/Vinbero/commit/3ff411f44d5d0419657c5bf1a260ab62b8747827))
* support BUM traffic flooding via TC clone-to-self ([43e2cdf](https://github.com/takehaya/Vinbero/commit/43e2cdf594a924fd2d1562760d306d679580ffdc))
* support BUM traffic flooding via TC clone-to-self with VLAN materialization ([7caffba](https://github.com/takehaya/Vinbero/commit/7caffbab702cc3f3ba0a56cb21e172853fa58bec))
* support End.DT4/DT6/DT46, End.DT2 with Bridge Domain, FDB sync, and port VLAN ([5ac0478](https://github.com/takehaya/Vinbero/commit/5ac047830d010dd11e04e7ec9573e5c322d4897f))
* support end.dx4,dx6 ([1415d96](https://github.com/takehaya/Vinbero/commit/1415d96f930378478ea6a1bfca568cf5d3f48378))
* support H.Encaps.L2 and End.DX2 for L2VPN ([7e42331](https://github.com/takehaya/Vinbero/commit/7e42331c1025225885ac3fe66376d3655e5a52ef))
* support H.Encaps.L2 and End.DX2 for L2VPN ([44ca880](https://github.com/takehaya/Vinbero/commit/44ca880f8d277841fab575dcdad58df688a00879))
* support headend and closs connect L3 Behavior ([94292af](https://github.com/takehaya/Vinbero/commit/94292af6ce5766a5cd8e58397ba1dea590c60e6a))
* support headend prog ([609884f](https://github.com/takehaya/Vinbero/commit/609884fd25903c73c3639480c56bd895f7a36a50))


### 🐛 Bug Fixes

* add --version flag to vinbero CLI for test-runnable compatibility ([4cd7f84](https://github.com/takehaya/Vinbero/commit/4cd7f849704cddc60e44653bd2dca2cfde6c54bc))
* add onlink flag for VRF route install in end-t example ([4e6b7f6](https://github.com/takehaya/Vinbero/commit/4e6b7f625e6efc13bc1178f6ad0d10336a3ab324))
* address Copilot review feedback ([b30be21](https://github.com/takehaya/Vinbero/commit/b30be21cb3f9d844f9dd5ba43577e7d506ec784d))
* fix End.DT4/DT6 CI failures with VRF routing and rp_filter ([d79d729](https://github.com/takehaya/Vinbero/commit/d79d729d276cb7e08359d8af46a088fde142b8c5))
* match JSON indent format in headend-l2 test grep patterns ([030ee79](https://github.com/takehaya/Vinbero/commit/030ee79745dd6401a83e88cdbc243668b2afaac0))
* move --json flag before subcommand in end-dt2 test ([576592e](https://github.com/takehaya/Vinbero/commit/576592e083b7b71975ff1e59a0dac520803913cd))
* re-add IPv6 addresses after VRF enslave in end-t example ([18eda82](https://github.com/takehaya/Vinbero/commit/18eda82ce565e499e434a09a3b4906d3b51db765))
* restore direct H.Encaps.L2 for bd_id=0 (no Bridge Domain) ([1b9472e](https://github.com/takehaya/Vinbero/commit/1b9472e0ffdbedda058e940088e66ada6cc0ad95))
* update goreleaser to build both vinberod and vinbero CLI ([93423c1](https://github.com/takehaya/Vinbero/commit/93423c1bab8dcbc7ffe676ee06c1c221a8a3f838))
* upload both vinberod and vinbero binaries in CI ([983d5ab](https://github.com/takehaya/Vinbero/commit/983d5ab538e27c40ee6a69a617fde3ec4ffb359e))
* use route replace instead of add for VRF table routes in end-t example ([7c0dbf6](https://github.com/takehaya/Vinbero/commit/7c0dbf6e49dea82a6e0c33a7360e3535623a3151))


### 📝 Documentation

* add CLI section to top-level README ([5e8e62d](https://github.com/takehaya/Vinbero/commit/5e8e62d6007e61c3c9d38e28bf9d149f6e01b9d0))
* add l2l3vpn design ([0201f08](https://github.com/takehaya/Vinbero/commit/0201f0820b8aaffd86bbae864b85e2316636bf55))
* add missing READMEs and update all examples to use vinbero CLI ([70055bc](https://github.com/takehaya/Vinbero/commit/70055bc263f294f12a0fc1f1498c96d02a702c5f))
* remove tc_bum_forwarding.md from tracking ([6c949a4](https://github.com/takehaya/Vinbero/commit/6c949a4449784eca8bdf12beaa91d2cabe93db26))
* replace ASCII topology diagrams with mermaid in all READMEs ([02cbaec](https://github.com/takehaya/Vinbero/commit/02cbaec7921ca819b902601f019b417dda8f1ea3))
* rewrite BUM forwarding design doc to match final implementation ([a3830b6](https://github.com/takehaya/Vinbero/commit/a3830b6ccccadd9c42c62980416a7828011611db))
* update loadmap ([471ce43](https://github.com/takehaya/Vinbero/commit/471ce4377274fe2dba09a2a79fc9e0fe3ce8f0bc))
* update readme ([cab2214](https://github.com/takehaya/Vinbero/commit/cab221446ae3cae997c86261450da44c20776174))


### 🔧 Miscellaneous Chores

* add base bpf code ([1842641](https://github.com/takehaya/Vinbero/commit/1842641b92a02c6545f57036fe81b660af1dca94))
* add bpfload and close code ([83cfb1b](https://github.com/takehaya/Vinbero/commit/83cfb1bed6325ab8ebd210fe5c66d880218617ce))
* add headendv46 ([506f788](https://github.com/takehaya/Vinbero/commit/506f78831b76619b329c9032b25f338abc4d99e7))
* add load map ([f259dfc](https://github.com/takehaya/Vinbero/commit/f259dfca5dcb3d2b851186bfed33e90c413cc170))
* add logger pkg ([f10b392](https://github.com/takehaya/Vinbero/commit/f10b3926c1f9dd4fcfae8751ac73f894cba825c9))
* add update protobuf support ([36f7b8f](https://github.com/takehaya/Vinbero/commit/36f7b8f18931d84f4cd66cc9e9dc7b4d2feb4154))
* logo modify ([c4d39ca](https://github.com/takehaya/Vinbero/commit/c4d39ca94554097ccd215a554aaca8ab809a8db1))
* migrate logo and readme ([7606419](https://github.com/takehaya/Vinbero/commit/76064194fd45688a12b763d0c87e95bd66806010))
* modify load map ([#17](https://github.com/takehaya/Vinbero/issues/17)) ([8ac7474](https://github.com/takehaya/Vinbero/commit/8ac74742929e1630cdf8237b5905e5387ad039f2))
* replace curl with vinbero CLI in examples ([e76aa38](https://github.com/takehaya/Vinbero/commit/e76aa38441c15aec43289d35afe5cd6881805429))
* update go version ([eda87d5](https://github.com/takehaya/Vinbero/commit/eda87d530591fec46d0660918c8d3d7169d4042f))


### ♻️ Code Refactoring

* add cache and shurink v6 addr ([abe4728](https://github.com/takehaya/Vinbero/commit/abe4728af5bb9d2da3f391471c1044da0b7d7b73))
* apply make lint ([2f667cf](https://github.com/takehaya/Vinbero/commit/2f667cf27d4d82525c133884e4b876fbb43a7821))
* apply make lint ([1fde06b](https://github.com/takehaya/Vinbero/commit/1fde06b0c37451fe6eb6048c08801fbb53a34d17))
* data plane code restructuring, map optimization, and observability ([#15](https://github.com/takehaya/Vinbero/issues/15)) ([292aee1](https://github.com/takehaya/Vinbero/commit/292aee13d264ce7beb7aa42f3c6dd2b88496fb6d))
* modify loop type ([30f717d](https://github.com/takehaya/Vinbero/commit/30f717d5b349ac27a2121d67a511642e3ba6b31c))
* rename dmac CLI command to fdb ([5e0eab8](https://github.com/takehaya/Vinbero/commit/5e0eab8a105d268e8b511247d1c492aac4082976))
* rename headend ([c2b3772](https://github.com/takehaya/Vinbero/commit/c2b377229159a2efbacb4b3441d0ec23b12bc3d4))
* replace curl with vinbero CLI in all example test scripts ([12ca099](https://github.com/takehaya/Vinbero/commit/12ca09980fba253cfcb9e21276b69ff4aebc9252))
* unify test ci ([7a3d7c2](https://github.com/takehaya/Vinbero/commit/7a3d7c2352df98758ca9800f2737f4fa027ba0a6))
