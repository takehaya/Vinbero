# Changelog

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
