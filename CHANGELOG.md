# Changelog

## [0.1.2](https://github.com/takehaya/Vinbero/compare/v0.1.1...v0.1.2) (2026-11-11)


### 🎉 Features

* **api:** name the VRF of a headend entry over RPC and vbctl ([9c990cc](https://github.com/takehaya/Vinbero/commit/9c990cc5f3413fd82ee8596e12d294927e65be0d))
* attach devices to the data plane at runtime ([54613c9](https://github.com/takehaya/Vinbero/commit/54613c9382c6ebb35f3cae701e138203f2c45133))
* **bench:** add balanced cplane convergence measurement suites ([d82aa53](https://github.com/takehaya/Vinbero/commit/d82aa53cb0449a8bdb0f8f115bd4177e0ecad3fe))
* **benchmark:** TRex-driven SRv6 dataplane load-test harness ([#140](https://github.com/takehaya/Vinbero/issues/140)) ([848597e](https://github.com/takehaya/Vinbero/commit/848597eebf11eafc6abd813ed307fe408b8dd32f))
* **bench:** measure BGP convergence through cplane plugins ([#179](https://github.com/takehaya/Vinbero/issues/179)) ([00f6fd3](https://github.com/takehaya/Vinbero/commit/00f6fd3e63c4d1d64bd334746ee6dab2ecd6113d))
* **bgp:** signal and honour the SRv6 SID Structure on L3VPN routes ([#167](https://github.com/takehaya/Vinbero/issues/167)) ([96a0016](https://github.com/takehaya/Vinbero/commit/96a00165f48b4711459e0618e872a67ef9708429))
* **bpf:** build the xdp BUM copies from a per-CPU replication plan ([883cccf](https://github.com/takehaya/Vinbero/commit/883cccf2541db487ee9e426bd92003bbc15dd930))
* **bpf:** End.T with REPLACE-CSID (RFC 9800 Sec.4.2, VRF-bound FIB) ([#180](https://github.com/takehaya/Vinbero/issues/180)) ([dfa92dc](https://github.com/takehaya/Vinbero/commit/dfa92dcbe23425278250469707f363bcd319b472))
* **bpf:** forward End.X-family USD over the adjacency ([#160](https://github.com/takehaya/Vinbero/issues/160)) ([6e6372f](https://github.com/takehaya/Vinbero/commit/6e6372f66a8515dbed21796eda0aa767491c8ab1))
* **bpf:** keep the xdp BUM devmaps in step with the L2 maps ([6ad7b86](https://github.com/takehaya/Vinbero/commit/6ad7b86812a7bd70e8a85959fb650802bffe07fc))
* **bpf:** key the L3 headend maps by {vrf_id, prefix} ([022989a](https://github.com/takehaya/Vinbero/commit/022989a084378056062d9f7047517bb49e6527c1))
* **bpf:** key the L3 headend maps by {vrf_id, prefix} ([607b883](https://github.com/takehaya/Vinbero/commit/607b8837edd43581ba5e19ba49b26373cc942727))
* **bpf:** read and write headend entries of any VRF ([a690525](https://github.com/takehaya/Vinbero/commit/a690525c449c93bf4d6dd9a9652e9cc2e4e46211))
* **bpf:** replicate BUM in XDP through per-BD devmaps ([fece27c](https://github.com/takehaya/Vinbero/commit/fece27c0b312b0bbd8964ea80ffad3ef9fe43bc1))
* **bpf:** replicate xdp-mode BUM in native XDP ([8b330fa](https://github.com/takehaya/Vinbero/commit/8b330fa599fa727200cdaaea8db5d9ac706add21))
* **bpf:** resolve xdp BUM uplinks through a test_run probe ([c096a8a](https://github.com/takehaya/Vinbero/commit/c096a8a3234893f4722ad3d3d3742ef4d26e763d))
* **bpf:** run a BD with disagreeing ACs in tc, and retry left-out slots ([aef5456](https://github.com/takehaya/Vinbero/commit/aef54562fc9eff07e9c68e2ecf366dc89c9e8991))
* **cni:** accept the same pod subnet in two VRFs and update the VRF docs ([56e6ba4](https://github.com/takehaya/Vinbero/commit/56e6ba433974addbca795059d150955062e89509))
* **cni:** accept the same pod subnet in two VRFs on one node ([5a95459](https://github.com/takehaya/Vinbero/commit/5a95459be792bad85dc5e9ba69cc1fd3582ba780))
* **cni:** add a CNI plugin for pods in an L3VPN VRF ([86ef136](https://github.com/takehaya/Vinbero/commit/86ef136bd7573ad2a032e938cc415bed53560847))
* **cni:** add the vinbero CNI plugin in L3 mode ([4ab3342](https://github.com/takehaya/Vinbero/commit/4ab3342a67bba83cc8e49d78d2c5e896b4a7259c))
* **config:** add settings.l2.bum_mode ([63bea75](https://github.com/takehaya/Vinbero/commit/63bea755beb7e1d7f0ccca780d6daf16f43f4bc0))
* **config:** allow xdp BUM mode with native XDP ([b30578e](https://github.com/takehaya/Vinbero/commit/b30578e815b16c33e92b4de4751b40ab573591f3))
* **cplane:** add extensible control-plane plugins ([8f021e1](https://github.com/takehaya/Vinbero/commit/8f021e1709f1c5bead5d5b0d50402b15ef2c1a41))
* **cplane:** add Go guest SDK and replay-aware route view ([#174](https://github.com/takehaya/Vinbero/issues/174)) ([7697258](https://github.com/takehaya/Vinbero/commit/76972586502c03c4537dc72db5a5701ae3bee070))
* **cplane:** add opt-in live batch input policy ([b219e5b](https://github.com/takehaya/Vinbero/commit/b219e5b2fded4cb09788fc11e25e87114025957f))
* **cplane:** add shared IMET-gated EVPN static MAC policy ([7de73e4](https://github.com/takehaya/Vinbero/commit/7de73e4b231e70d222c0d9b76b45a219cb906b6f))
* **cplane:** add shared IMET-gated EVPN static MAC policy ([26900d6](https://github.com/takehaya/Vinbero/commit/26900d66212dec33246c852a8d4fe83d6bf34535))
* **cplane:** coalesce opted-in queued live routes ([5d12dd8](https://github.com/takehaya/Vinbero/commit/5d12dd81609c03f91fa948d8d7400bce96757a90))
* **cplane:** compose authorized routes and reconcile owned outputs ([b330130](https://github.com/takehaya/Vinbero/commit/b330130aed0c23059e8c3db2fe27f2f55f8b0a45))
* **cplane:** configure shared native and WASM behavior with JSON ([1adbc2d](https://github.com/takehaya/Vinbero/commit/1adbc2d479c6ca548fa2eaf25ee5070cc6b7ecc0))
* **cplane:** configure shared native and WASM behavior with JSON ([4a8a285](https://github.com/takehaya/Vinbero/commit/4a8a2858839778f88cac00e482fbf0b9231099a0))
* **cplane:** default new plugin registrations to native ([9531e4b](https://github.com/takehaya/Vinbero/commit/9531e4b7be248d768d6d65fea2243aa041089563))
* **cplane:** expose received GoBGP packet model to WASM plugins ([88824f0](https://github.com/takehaya/Vinbero/commit/88824f041b8fc594cd9d972677262504a42e0126))
* **cplane:** let a plugin name a granted VRF for a headend entry ([631ec1b](https://github.com/takehaya/Vinbero/commit/631ec1b16a4fe61d35fe39ce26a53172231b66fa))
* **cplane:** let plugins read their registration grants ([91f2bde](https://github.com/takehaya/Vinbero/commit/91f2bdee0f596660a8c656647e08c467213a22b9))
* **cplane:** persist local SID identities across restarts ([#178](https://github.com/takehaya/Vinbero/issues/178)) ([3d34ad2](https://github.com/takehaya/Vinbero/commit/3d34ad23439b73621c1d46c3c828b7a9add2ae38))
* **cplane:** plugin dispatch の End.DT4/6/46 を VRF scoped に decap する ([#139](https://github.com/takehaya/Vinbero/issues/139)) ([30c7932](https://github.com/takehaya/Vinbero/commit/30c793279aac1ce43709678b1736e391eeb9d90e))
* **cplane:** plugin の scope と producer 分離と eBPF half 込みの interop ([#138](https://github.com/takehaya/Vinbero/issues/138)) ([88ab6f6](https://github.com/takehaya/Vinbero/commit/88ab6f6ccacb9759aa3cc0f1f6003d5da74822b6))
* **cplane:** read registration grants and configure custom-behavior with JSON ([4512fad](https://github.com/takehaya/Vinbero/commit/4512fad1e2b479639ef0119f21055ccda2a8e022))
* **cplane:** register and restore trusted native controllers ([9ddc632](https://github.com/takehaya/Vinbero/commit/9ddc632aecbfcbfc9136971e336fcddc43620309))
* **cplane:** share MUP controller across native and WASM runtimes ([2a88c78](https://github.com/takehaya/Vinbero/commit/2a88c7871653c724c00e396ba66e0e1aaa7b940c))
* End.LBS and End.XLBS (RFC 9800 Sec.7, Locator-Block Swap) ([#166](https://github.com/takehaya/Vinbero/issues/166)) ([7a57ff8](https://github.com/takehaya/Vinbero/commit/7a57ff8fde4a3bccbbc8a5454271d0e2a6a2267d))
* **examples:** demonstrate Cplane and Dplane plugins together ([30adbd0](https://github.com/takehaya/Vinbero/commit/30adbd0f5d0bcdee2f2637f766e41a513dcb5a60))
* **examples:** demonstrate custom Cplane and Dplane behavior ([356b765](https://github.com/takehaya/Vinbero/commit/356b7651487c3b213bd152c94b7556505fdd857b))
* **headend:** key desired sets and leases by {vrf, prefix} ([f052bf7](https://github.com/takehaya/Vinbero/commit/f052bf76e16efb1a6746ed180861397a6ea1f044))
* keep the locators, Ethernet Segments and VRF policy made over the API across a restart ([1f42527](https://github.com/takehaya/Vinbero/commit/1f425273a32a34719a98be957c69a8be0a1d7745))
* keep the locators, Ethernet Segments and VRF policy made over the API across a restart ([0a74d11](https://github.com/takehaya/Vinbero/commit/0a74d11ac7c8adc82af9b72c270ee176396440c0))
* **l2:** give RT2 peers their own bd_peer index range ([5f82ee7](https://github.com/takehaya/Vinbero/commit/5f82ee737931200a90fe018376c0aefaae0c2ac3))
* **l2:** give RT2 peers their own bd_peer index range (9 nodes per bridge domain) ([aa36630](https://github.com/takehaya/Vinbero/commit/aa36630a8f33846ebe20bb3f6248cbbf6205b25a))
* **l2:** raise the flood slots of a bridge domain from 8 to 32 ([1702dcb](https://github.com/takehaya/Vinbero/commit/1702dcb20c40cc75d2c7151bffd549c44957c0f4))
* **l2:** raise the flood slots of a bridge domain from 8 to 32 ([45c58cb](https://github.com/takehaya/Vinbero/commit/45c58cb643ee877582dc6514d0c6fed2fb59f5b6))
* **l2:** save L2 headend circuits and restore them before the reconcile ([7826c6c](https://github.com/takehaya/Vinbero/commit/7826c6c010f2cc0392b0d8295407517f617e8ef5))
* **l2:** save L2 headend circuits and restore them in boot order ([2687b4f](https://github.com/takehaya/Vinbero/commit/2687b4fc101ad593dc690d4a725f36bd8c65d93f))
* REPLACE-CSID flavor for End and End.X (RFC 9800 Sec.4.2) ([#159](https://github.com/takehaya/Vinbero/issues/159)) ([24d3e2f](https://github.com/takehaya/Vinbero/commit/24d3e2f0ca699a5c71abbe76f6cf978d2adee2d4))
* replicate BUM in native XDP (bum_mode: xdp with device_mode: driver) ([65e9f1f](https://github.com/takehaya/Vinbero/commit/65e9f1facd0238f6acae817e7a24383e58a56189))
* replicate BUM in XDP (bum_mode: xdp) with a shared devmap egress program and a per-CPU plan ([1b137af](https://github.com/takehaya/Vinbero/commit/1b137af50fdc9fa1e55922218a0abf8ac3c4c347))
* run the global VRF's FIB lookups as direct lookups while that gives the same answer ([16ff6f5](https://github.com/takehaya/Vinbero/commit/16ff6f579dbe2817aa71e809277df958b0b2e12c))
* run the global VRF's FIB lookups as direct lookups while that gives the same answer (opt-in) ([322f2fc](https://github.com/takehaya/Vinbero/commit/322f2fc76f297d4b33e4f84866a753af85bbdf94))
* **sdk:** add strict JSON configuration decoder ([1ac6b19](https://github.com/takehaya/Vinbero/commit/1ac6b19874eaf3ce82bcff689f922fcd8ab343f5))
* **sdk:** configure custom-behavior from JSON and its grants ([0395545](https://github.com/takehaya/Vinbero/commit/0395545ec2c914eb67622e8e2dda0b43c1f6fe98))
* **server:** add DeviceService and vbctl device ([afa30f0](https://github.com/takehaya/Vinbero/commit/afa30f0b8a0e04b1155b800b38df36177b3da4f8))
* **server:** mint uSID SID functions from a locator_ref ([#181](https://github.com/takehaya/Vinbero/issues/181)) ([5346abf](https://github.com/takehaya/Vinbero/commit/5346abf2b2e7a84f960bbabcbe217750cd781d8d))
* uSID (RFC 9800 NEXT-C-SID) uN and uA support ([#150](https://github.com/takehaya/Vinbero/issues/150)) ([ed6e8bb](https://github.com/takehaya/Vinbero/commit/ed6e8bb828b36dd5c1e176f4493832b468b3bb14))
* uSID uT / terminal uDT-uDX / USD flavor (NEXT-C-SID completion) ([#155](https://github.com/takehaya/Vinbero/issues/155)) ([aac4e13](https://github.com/takehaya/Vinbero/commit/aac4e130996ac83a78aab22bfc7c532cd76014f8))
* **vinbero:** attach devices at runtime and attach them again on start ([9c49f64](https://github.com/takehaya/Vinbero/commit/9c49f64119b92dba8f4303d69e9a3964dc5dda17))
* **vinberod:** keep the VRF bindings made over the API across a restart ([741bf90](https://github.com/takehaya/Vinbero/commit/741bf909b3edb848e879345171e56008745562f3))
* **vinberod:** keep the VRF bindings made over the API across a restart ([d87966d](https://github.com/takehaya/Vinbero/commit/d87966d9efd9abbf2d4dfa146b0b221fdd7e44c1))
* **vinbero:** fall back to tc BUM replication where generic XDP copies share a buffer ([4a77f93](https://github.com/takehaya/Vinbero/commit/4a77f93256c3f41896a90fca6e129f1999374588))
* **vinbero:** forget a device when its interface is deleted ([830b52e](https://github.com/takehaya/Vinbero/commit/830b52e3a15394b44b80c3eba3154500270422cc))
* **vinbero:** refuse xdp BUM mode on PREEMPT_RT kernels ([e14cb36](https://github.com/takehaya/Vinbero/commit/e14cb36a10efeddb713751a5bf510f1e02d9eadb))
* **vinbero:** run xdp-mode bridge domains end to end ([375aae9](https://github.com/takehaya/Vinbero/commit/375aae95b49983bc46b0f11a021e1d4e7d781752))
* **vrf:** add and remove bridge members at runtime ([2ebf963](https://github.com/takehaya/Vinbero/commit/2ebf9636285bc1c01139beeefea1d5db6c5e89b0))
* **vrf:** end the tables of managed VRFs in an unreachable default ([e563662](https://github.com/takehaya/Vinbero/commit/e5636628f5f98d8325a6d44628bdbb5993c871ab))
* **vrf:** keep vrf_ids and runtime ACs across a restart ([a0b3122](https://github.com/takehaya/Vinbero/commit/a0b312283829fbcf5e80803b0c7296d9158d2dfa))
* **vrf:** keep vrf_ids and runtime ACs across a restart ([770ff90](https://github.com/takehaya/Vinbero/commit/770ff90dafb03d98d1918f890e6f4f5d3ceb1922))
* **vrf:** look headend entries up in the ingress VRF and import VPN routes per VRF ([95ab7ba](https://github.com/takehaya/Vinbero/commit/95ab7baf3261656564b29b586fcc8db7a1b64be2))
* **vrf:** look headend entries up in the ingress VRF and import VPN routes per VRF ([2027bd5](https://github.com/takehaya/Vinbero/commit/2027bd57bce697a64441dd454e6a5cba62c1d67d))
* **vrf:** name the VRF of a headend entry over RPC, vbctl and the plugin API ([3a2fb70](https://github.com/takehaya/Vinbero/commit/3a2fb705b700adf0118d2067937be8e458361b0e))
* **vrf:** stop VRF table misses at an unreachable default ([d24ad7d](https://github.com/takehaya/Vinbero/commit/d24ad7db908307a243820d2524c4dedce219be60))
* xdp BUM over an ECMP underlay ([92b252c](https://github.com/takehaya/Vinbero/commit/92b252c8cb44e632335b4f410061b5cadde9b23b))


### 🐛 Bug Fixes

* **bench:** make MUP TEID replacements observable over a real BGP peer ([d373ab0](https://github.com/takehaya/Vinbero/commit/d373ab056ce483320d85098d0162708b71c9732a))
* **bench:** preserve cleanup grace on cancellation ([a58142a](https://github.com/takehaya/Vinbero/commit/a58142adcc7295830deba0d2112fbc08c2ba9d8f))
* **bench:** reject incomplete pacing and track pending replays ([51f058c](https://github.com/takehaya/Vinbero/commit/51f058c057581eac5a5204f2f85069001d233a71))
* **bench:** stop orphaned workers after driver failure ([c3152fd](https://github.com/takehaya/Vinbero/commit/c3152fdb3fe3e7c1901942611784161cd0da6981))
* **bench:** verify archived trial executable bytes ([d3b4fe8](https://github.com/takehaya/Vinbero/commit/d3b4fe85a96e91c0256298fdf157ce10f06c0b51))
* **bgp:** detect import filter changes in the binding manager and write tracked routes on locator registration ([64bf19d](https://github.com/takehaya/Vinbero/commit/64bf19d28108f4f1e73dfc4ea2885dcdb4969ecd))
* **bgp:** do not read a MUP community with sub-type 2 as a route target ([bc60940](https://github.com/takehaya/Vinbero/commit/bc60940470221cc05256a53ca52740546694f7dc))
* **bgp:** drain subscription callbacks before demux shutdown ([e42664e](https://github.com/takehaya/Vinbero/commit/e42664e0275c4aef09dbc600dc8f6e4d3254486a))
* **bgp:** drop retry records with the destination they wait for ([3b8d134](https://github.com/takehaya/Vinbero/commit/3b8d134f5d8b2e25b20cd69ebf5cdefa8d3043be))
* **bgp:** keep failure-caused retries in their series and record the source a VPN group carries ([4864f9f](https://github.com/takehaya/Vinbero/commit/4864f9f821212bc1f4bd064c5f538881153d3eb9))
* **bgp:** re-evaluate VPN routes when imports shrink or the source locator appears ([a26537f](https://github.com/takehaya/Vinbero/commit/a26537faf0bd7da32599069d78bcae91bc99aace))
* **bgp:** re-evaluate VPN routes when imports shrink or the source locator appears ([a14684f](https://github.com/takehaya/Vinbero/commit/a14684f63bd4f89fa61dfe9d154afe830e498b71))
* **bgp:** remove an earlier run's MUP uplinks at boot and finish failed MUP moves ([702631e](https://github.com/takehaya/Vinbero/commit/702631e5265571252e19d87b3b00faec3ef1f4a4))
* **bgp:** remove an unresolvable MUP session before retrying its move ([5b3887d](https://github.com/takehaya/Vinbero/commit/5b3887d4d42c37ce9e0d86ac8037470483e321e5))
* **bgp:** replay the VPN loc-rib when a binding adds import RTs ([66235c3](https://github.com/takehaya/Vinbero/commit/66235c3d4cebef760135cb92705f80369e6a0081))
* **bgp:** replay the VPN loc-rib when a binding adds import RTs ([e68fb8f](https://github.com/takehaya/Vinbero/commit/e68fb8f50c536e384fcb4a1217c85f1f56242fb2))
* **bgp:** report failed EVPN replay writes and MUP T2ST removals ([4c23f1d](https://github.com/takehaya/Vinbero/commit/4c23f1d102a8435e882ff7204bbe65f9dfd83b91))
* **bgp:** reserve RFC-assigned endpoint behavior claims ([4ec4b38](https://github.com/takehaya/Vinbero/commit/4ec4b382bb66bfb0426ee0eb218ace0b9901e7fe))
* **bgp:** retain VPN groups until trigger cleanup succeeds ([#176](https://github.com/takehaya/Vinbero/issues/176)) ([5836b60](https://github.com/takehaya/Vinbero/commit/5836b6099d8e907a6819e665d77898a4ca72375d))
* **bgp:** retry failed writes by what they need, a bounded number of times ([36f3080](https://github.com/takehaya/Vinbero/commit/36f30807a3db2dd9e9d073200c5291b46e7dd875))
* **bgp:** retry tracked writes after the source locator registration ([9d6c2a0](https://github.com/takehaya/Vinbero/commit/9d6c2a0e7abdb2db4ef90e7d8fed8fdfe0a60158))
* **bgp:** rewrite EVPN and MUP T2ST entries when the source locator moves ([8b41fd6](https://github.com/takehaya/Vinbero/commit/8b41fd6549e3ca6cff594bae3ab61dc8280f3555))
* **bgp:** rewrite EVPN and MUP T2ST entries when the source locator moves ([b93a5bf](https://github.com/takehaya/Vinbero/commit/b93a5bf117590c9273ee508bacf75d28ac64b960))
* **bgp:** serialize route ownership with GoBGP updates ([87fd6f2](https://github.com/takehaya/Vinbero/commit/87fd6f2ce4b99bb7b41b47f0497853134da358f3))
* **bgp:** stop the VPN replay worker in the same step that gives up ([2a54cff](https://github.com/takehaya/Vinbero/commit/2a54cff69f8b61d21774c016f3dc65c06e4da4ea))
* **bgp:** stop the VPN replay worker in the same step that gives up ([374d7b1](https://github.com/takehaya/Vinbero/commit/374d7b168933edbbc4a126fcfab3994b51aa5752))
* **bgp:** tear down MUP and EVPN state on unusable replacement UPDATEs ([#170](https://github.com/takehaya/Vinbero/issues/170)) ([288259f](https://github.com/takehaya/Vinbero/commit/288259f4d700d348a27b9ca8b8e14f8db2edad43))
* **bgp:** wait for server shutdown before final stop ([ca38264](https://github.com/takehaya/Vinbero/commit/ca382646f82d7e025a2f9851c9787e109cef66ac))
* **bgp:** withhold a plugin-claimed VPN prefix only in the VRFs that import the claimed path ([d881072](https://github.com/takehaya/Vinbero/commit/d881072c7113031a11099f2ffcfee3d5288aecc7))
* **bgp:** withhold a plugin-claimed VPN prefix only in the VRFs that import the claimed path ([9a563a3](https://github.com/takehaya/Vinbero/commit/9a563a3407c290652ec3323daa115d908ad3da08))
* **bpf:** atomically update FDB forwarding identities ([20e066a](https://github.com/takehaya/Vinbero/commit/20e066a5c100466c1289d046889dbfbd0db842d8))
* **bpf:** batch the bum_tx_map grace and fall back when the map is full ([3d39e9f](https://github.com/takehaya/Vinbero/commit/3d39e9f73c935c0b1e8a5ad907aae33bb5f92a23))
* **bpf:** check the tc encapsulation's SRH length where it is added to the packet pointer ([21a67f1](https://github.com/takehaya/Vinbero/commit/21a67f1be1afa521f6361dba34eef0dfefabd152))
* **bpf:** close the VLAN and plugin paths around the SID gate ([eccb8b9](https://github.com/takehaya/Vinbero/commit/eccb8b9b13a7b14a5fdf5a30d54bc597e39dbbd0))
* **bpf:** count a BUM frame once in BUM_XDP_FALLBACK ([29965e8](https://github.com/takehaya/Vinbero/commit/29965e87ac78a13682555c081cadb7329ee59176))
* **bpf:** count a failed BUM metadata strip as an egress drop ([8e930f7](https://github.com/takehaya/Vinbero/commit/8e930f7e228432f6d6b009744dfa16558bf1cba4))
* **bpf:** count a frame that cannot carry the marker, on every tc path ([0fb3765](https://github.com/takehaya/Vinbero/commit/0fb3765e3bcb6820807c5df7bf020069940f26d9))
* **bpf:** enable IPv6 forwarding in the adjacency test fixture ([#164](https://github.com/takehaya/Vinbero/issues/164)) ([d3f178e](https://github.com/takehaya/Vinbero/commit/d3f178e9c5e70aa58d33227ecc9066a42042eb32))
* **bpf:** enforce plugin aux and decap grants on builtin handoffs ([9fa9034](https://github.com/takehaya/Vinbero/commit/9fa9034005932ea0659e4e2489d3c2e079953fc3))
* **bpf:** filter DT2M by independent ES peer membership ([6c5fbab](https://github.com/takehaya/Vinbero/commit/6c5fbabf1967a1a40040b186e7335c3ae40ed675))
* **bpf:** finish the verifier log change and reset the plugin slots ([#169](https://github.com/takehaya/Vinbero/issues/169)) ([5fc6651](https://github.com/takehaya/Vinbero/commit/5fc665100652a6487d3974fe40ed53c276af70ab))
* **bpf:** flush and prune headend entries of every VRF ([44e9b4e](https://github.com/takehaya/Vinbero/commit/44e9b4e583ddd9cc8b7e7daf348d47ae7a8e6963))
* **bpf:** ignore a write notification on a nil map handle ([cdfba62](https://github.com/takehaya/Vinbero/commit/cdfba62516c462eafe87fdbedcbf486ee221a6aa))
* **bpf:** keep a split BD's next hops resolved and heal removed entries ([a8ea462](https://github.com/takehaya/Vinbero/commit/a8ea4627a92e0e40bcc0f228df38ac134ac8e524))
* **bpf:** keep encap next hops resolved across a link flap ([41cacce](https://github.com/takehaya/Vinbero/commit/41cacce1b75dde81f33e3a90ae2dc0a9ff10ed28))
* **bpf:** keep encap next hops resolved across a link flap ([191b57c](https://github.com/takehaya/Vinbero/commit/191b57c577a5411a7eacb8808e67b90548a74d2d))
* **bpf:** keep the builtin aux lifecycle tied to the exact SID entry ([#148](https://github.com/takehaya/Vinbero/issues/148)) ([3a0533a](https://github.com/takehaya/Vinbero/commit/3a0533a483304082fe7bcd85352b1e73a359a78b))
* **bpf:** keep the uplink next hops of xdp BUM flood slots resolved ([39ace75](https://github.com/takehaya/Vinbero/commit/39ace75fa6c7a55da41b7aaca037053639dc23ba))
* **bpf:** keep the xdp BUM devmaps going through partial failures ([ac2850e](https://github.com/takehaya/Vinbero/commit/ac2850e796cb0a84ced000e0fed4162e7bede119))
* **bpf:** leave xdp-mode BDs xdp mode cannot serve on the tc path ([77f1a4c](https://github.com/takehaya/Vinbero/commit/77f1a4c1f72633608246b69b7046d7df62ddbb21))
* **bpf:** let configured circuits take an unknown tag on a tenant port ([bdf6942](https://github.com/takehaya/Vinbero/commit/bdf694281af149da383c9d016d9c3c19a63dff9e))
* **bpf:** look up a tenant packet's outer header in the main table ([ea45592](https://github.com/takehaya/Vinbero/commit/ea455927f9310d2e9dc820f140852b7a86fc2ae8))
* **bpf:** look up local SIDs only for packets from the global VRF ([62275d2](https://github.com/takehaya/Vinbero/commit/62275d2a486ddeb2724069fe3a70e80474206af0))
* **bpf:** look up local SIDs only for packets from the global VRF ([f3ad65e](https://github.com/takehaya/Vinbero/commit/f3ad65e9a943cece0346feca1df8d779bfff1015))
* **bpf:** make bd_peer lifecycle transactional across its writers ([#172](https://github.com/takehaya/Vinbero/issues/172)) ([82b9254](https://github.com/takehaya/Vinbero/commit/82b9254da4a9cf72737d4036ffdcde41d9db16dd))
* **bpf:** make subprogram provenance path-safe ([794a1a7](https://github.com/takehaya/Vinbero/commit/794a1a7ccc6f42d3895d3e7e31e657734139df71))
* **bpf:** mark again on the first failure after a carrier came back ([8cc1f5f](https://github.com/takehaya/Vinbero/commit/8cc1f5f2170e6873cf05d1f1fd725a760aa7f581))
* **bpf:** pass the ingress VRF to the outer lookup and drop the retry ([706c08e](https://github.com/takehaya/Vinbero/commit/706c08e7473c751fb8476d3d74e317052c75fa12))
* **bpf:** plan and broadcast BUM through one devmap lookup ([935e6d6](https://github.com/takehaya/Vinbero/commit/935e6d6203f75acd2969598826fee9b281eaf9cb))
* **bpf:** probe a next hop that fails after its carrier came back ([f303675](https://github.com/takehaya/Vinbero/commit/f303675b2c8b380a911827a98d5dd6e10f3e66e9))
* **bpf:** prune encapsulation destinations conservatively ([ac3272b](https://github.com/takehaya/Vinbero/commit/ac3272b4c0e043a61c3e846c2635f906db560659))
* **bpf:** refuse a trigger prefix of the other family in headend keys ([bf24c04](https://github.com/takehaya/Vinbero/commit/bf24c0492a0be11d1f9b0a7825b1b71ec3baa827))
* **bpf:** run the BUM egress program on every native XDP devmap queue ([ee204d2](https://github.com/takehaya/Vinbero/commit/ee204d27231d3fada2af875c7712019bae1f3113))
* **bpf:** send native xdp BUM the tc way when the metadata write fails ([9691709](https://github.com/takehaya/Vinbero/commit/9691709c3782272bc91482c5a1250861bd5c4f61))
* **bpf:** serve an xdp BUM AC that shares its port with an uplink ([4d61cf4](https://github.com/takehaya/Vinbero/commit/4d61cf40b5bf90ad6cb09e44ff99bf3ced955696))
* **bpf:** skip the xdp flood lookup for BD-less End.DT2 ([3419797](https://github.com/takehaya/Vinbero/commit/341979784e6c86b1fd785e98c09539e1accee069))
* **bpf:** spend a hop limit when an endpoint advances the segment list ([#149](https://github.com/takehaya/Vinbero/issues/149)) ([cab1aa0](https://github.com/takehaya/Vinbero/commit/cab1aa07b6f29bef4c91633d79cf742c60e7edf1))
* **bpf:** track map arguments across subprogram calls ([6db8291](https://github.com/takehaya/Vinbero/commit/6db82912e6c31e6864421191f06fedca7e41eb18))
* **bpf:** track map arguments across subprogram calls ([c082161](https://github.com/takehaya/Vinbero/commit/c082161268447d58937a78f53dfa30e537e02f9a))
* **ci:** install extra kernel modules only when missing ([5871412](https://github.com/takehaya/Vinbero/commit/58714121664ebec54348d7f33880bf880f0a8bfb))
* **ci:** resolve Ubuntu bpftool for combined plugin example ([5c5f67b](https://github.com/takehaya/Vinbero/commit/5c5f67b27ee778dcc44b32e3a91a541f14f105b0))
* **ci:** watch the C SDK header directory used by plugin builds ([ca39e91](https://github.com/takehaya/Vinbero/commit/ca39e91d498159fed96e67be90f4fd463ca3c850))
* **cli:** report per-target errors of headend-l2 delete ([785dd33](https://github.com/takehaya/Vinbero/commit/785dd33e63a5ce62daf90649751e3592335bc29d))
* **cli:** show BGP-installed FDB entries as remote ([7139b25](https://github.com/takehaya/Vinbero/commit/7139b25957427d1369599a23c3d2350a751cbd48))
* **cni:** call VrfCreate only for a VRF vinberod does not have ([b9b8495](https://github.com/takehaya/Vinbero/commit/b9b849501e0368f87eeb3d7a64f2cd4cc08d0507))
* **cni:** compare route targets and maxPrefixes with an existing binding ([2691b12](https://github.com/takehaya/Vinbero/commit/2691b1268d9a4273712ab33fd0d1c2032ae97046))
* **cni:** delete a veth only through its own host end ([94e66ac](https://github.com/takehaya/Vinbero/commit/94e66ac2bfeb316bb5306cab7bb945c6ba7ff740))
* **cni:** give each RPC to vinberod its own timeout ([b643f25](https://github.com/takehaya/Vinbero/commit/b643f254e36bf2df4e21009d73cb42bb69bc73d1))
* **cni:** ignore attachment records without a veth in the overlap check ([81edfb9](https://github.com/takehaya/Vinbero/commit/81edfb9542c7fbeabc6b97abae09e5a60658b2bb))
* **cni:** keep the veth and lease while the AC cannot be removed ([ea8a3bb](https://github.com/takehaya/Vinbero/commit/ea8a3bb6ba660c7860b70f69bf90d1f5feb31625))
* **cni:** refuse IPAM routes that would override the primary network ([b7399d0](https://github.com/takehaya/Vinbero/commit/b7399d03575f8df7bf78c6466ff6ed2f78a3fc49))
* **cni:** reject every interface name the kernel rejects ([915f85c](https://github.com/takehaya/Vinbero/commit/915f85cfd49564a50a22f28b026add5c3cd2816f))
* **cni:** return the DNS settings IPAM provides ([3979a2f](https://github.com/takehaya/Vinbero/commit/3979a2fab9c5eff3da8038fb53708990297b2dde))
* **cni:** tolerate IPAM plugins that do not implement CHECK ([805699e](https://github.com/takehaya/Vinbero/commit/805699ee24206236dd336f3275ba6ae5173c561c))
* **config:** count a VRF policy key given through a YAML merge or alias ([6494192](https://github.com/takehaya/Vinbero/commit/64941922dbc6d53314d3ffff8c26e8a1295c998c))
* **config:** count a VRF policy key with an empty value ([a1135c2](https://github.com/takehaya/Vinbero/commit/a1135c2a18962dbc552402135fcd449eb2f5fdb3))
* count a BUM frame once in BUM_XDP_FALLBACK ([d548bed](https://github.com/takehaya/Vinbero/commit/d548bedec816afad8ca6260a2e9316edaa2fc2df))
* **cplane:** bound guest grant buffers by memory alone ([4badfe1](https://github.com/takehaya/Vinbero/commit/4badfe1d44fb69a730f90b3cd0e450b291bb2f2c))
* **cplane:** clear inherited input state when config changes ([6ec1b21](https://github.com/takehaya/Vinbero/commit/6ec1b21d359f86840bd1f63cf4d7466e465eac25))
* **cplane:** count repeated families and behaviors once in grants ([6b39cc0](https://github.com/takehaya/Vinbero/commit/6b39cc0e91ebc50fc4b2bb8c14919a58300241ec))
* **cplane:** decap-grant の VRF 削除 TOCTOU を共有 leaf lease で閉じる ([#142](https://github.com/takehaya/Vinbero/issues/142)) ([de25eb3](https://github.com/takehaya/Vinbero/commit/de25eb3989767490551984c6c7d5fbcda70a06d9))
* **cplane:** exclude conflicting EVPN reverse peers ([2653755](https://github.com/takehaya/Vinbero/commit/26537552eacf91c975c3956c53c55c56bc2051cf))
* **cplane:** fence retired owners and reconcile complete outputs ([6890e21](https://github.com/takehaya/Vinbero/commit/6890e210e008ca4a614c0c53239f91409d8f1c2c))
* **cplane:** gate a plugin's headend VRF on a host feature, not the ABI ([44e5e21](https://github.com/takehaya/Vinbero/commit/44e5e21b2215c2f6d86956713e405261e13bf4cb))
* **cplane:** judge handoff health after the in-flight apply finishes ([1c1656f](https://github.com/takehaya/Vinbero/commit/1c1656f3ae5417525666a3d11d10d36171f4bb50))
* **cplane:** preflight both families and retain ordinary reservations ([caa730f](https://github.com/takehaya/Vinbero/commit/caa730ff9a36274cecc6a09b3952a2bb0d1bb621))
* **cplane:** preserve unchanged routes on binding notifications ([523dfc7](https://github.com/takehaya/Vinbero/commit/523dfc7b4c49241f03ce2dda5d4213e0dca89a4f))
* **cplane:** prune MAC-free segment replacements ([7f74b53](https://github.com/takehaya/Vinbero/commit/7f74b53d459d0c528dcb38e23105159f1a4fe96c))
* **cplane:** reconcile partial withdrawals and shared forwarding keys ([9c09180](https://github.com/takehaya/Vinbero/commit/9c09180c0e03865afbf76a216eaff7c01abbfdbe))
* **cplane:** refresh CI artifact and endpoint grant documentation ([bddbef4](https://github.com/takehaya/Vinbero/commit/bddbef405dd8f1627c35a7346247d52b9e30b7a2))
* **cplane:** report restart work before rebuilding ([70d71bf](https://github.com/takehaya/Vinbero/commit/70d71bfe6b6ca3a547e90a0f5eda9f57bade5e59))
* **cplane:** retain bounded WASM execution diagnostics ([f8f66f6](https://github.com/takehaya/Vinbero/commit/f8f66f66697b87404adbc8a6f073e84dcf3b3250))
* **cplane:** retain EVPN peer slots during segment updates ([1617e81](https://github.com/takehaya/Vinbero/commit/1617e81776ce1124c252069be51a0990a0e17333))
* **cplane:** retain EVPN peer slots during segment updates ([6fb9da5](https://github.com/takehaya/Vinbero/commit/6fb9da59796a51e7ef366cff5f27ecf7b4fa732f))
* **cplane:** retain failed durable unregisters for retry ([1b06721](https://github.com/takehaya/Vinbero/commit/1b067216d6567fe7f1ac4ba9196f692d843ede54))
* **cplane:** retain forwarding ownership and release claims safely ([b69377c](https://github.com/takehaya/Vinbero/commit/b69377c4af669c9f9888177c18afbdc6f782b262))
* **cplane:** retain healthy forwarding across equivalent input registrations ([22ed61d](https://github.com/takehaya/Vinbero/commit/22ed61d8ea7a290d68090bd3c06285433f1eb843))
* **cplane:** version persisted input authorization explicitly ([af40951](https://github.com/takehaya/Vinbero/commit/af40951e1735777cbc257aa5d272967e2571c59f))
* **cplane:** 経路の担当変更と replay 後の状態適用を修正する ([#171](https://github.com/takehaya/Vinbero/issues/171)) ([a53bd7b](https://github.com/takehaya/Vinbero/commit/a53bd7b2570ba2d8195f2c0049c8cf90b14e9ba6))
* **evpn:** refuse an ESI that BGP peers would reject ([77903ca](https://github.com/takehaya/Vinbero/commit/77903ca0d4f5758f02c569fb264040e1681de7ac))
* **evpn:** refuse an ESI that BGP peers would reject ([8dd854a](https://github.com/takehaya/Vinbero/commit/8dd854a7714e2b33126534b79a511b1ba86b39ed))
* **evpn:** retain RX membership by RT4 path reference ([a0b6c48](https://github.com/takehaya/Vinbero/commit/a0b6c48665f65abad0145ee98613906725785b8a))
* **examples:** let only one end dial the vinberod-to-vinberod sessions ([15ce5a1](https://github.com/takehaya/Vinbero/commit/15ce5a1e647e99cf9f803eeb837e76b02b5d83cb))
* **examples:** let only one end dial the vinberod-to-vinberod sessions ([05ae115](https://github.com/takehaya/Vinbero/commit/05ae11519b57ac4a841a7994903afd3c80de1dfd))
* **examples:** list cni-l3's listening BGP sockets too ([760d4c0](https://github.com/takehaya/Vinbero/commit/760d4c0fe7a1a18477a19ed587baf30e40de22da))
* **examples:** take cni-l3's BGP socket dump at the first timeout ([ac995b9](https://github.com/takehaya/Vinbero/commit/ac995b9aeb7b4d6f646ac30d9ea42e3c211c51bb))
* **examples:** take cni-l3's BGP socket dump before stopping the daemons, print it after ([d13da8f](https://github.com/takehaya/Vinbero/commit/d13da8f6ca887505ce31c560aafbc8e4f08888e1))
* **fdb:** leave kernel-learned MAC entries unowned ([4c96989](https://github.com/takehaya/Vinbero/commit/4c969897bce05ccf6b08254380cdb9139b9ea712))
* **fdb:** let the bridge own the local MACs it holds and advertise only workloads ([95db7de](https://github.com/takehaya/Vinbero/commit/95db7dee0e3418ce6bf2a6fc3c4c0e2cf2c33749))
* **fdb:** let the bridge own the local MACs it holds and advertise only workloads ([e416a82](https://github.com/takehaya/Vinbero/commit/e416a8223ea2d274556394c36ce319ff88dd82af))
* **fibmode:** close three gaps where the direct lookup could run on a stale view ([94f9972](https://github.com/takehaya/Vinbero/commit/94f9972c6239f4ca35928e044233dcc426729a6b))
* **headend-l2:** remove the entries of a deleted interface ([1113583](https://github.com/takehaya/Vinbero/commit/11135833fb6042d87f114966528e2e79f64e402c))
* **headend-l2:** remove the entries of a deleted interface ([784a135](https://github.com/takehaya/Vinbero/commit/784a1355f38476d371d259c35f27304c11d4085c))
* **interop:** apply frr.conf once in the SRv6 FRR scenarios ([f4c49e2](https://github.com/takehaya/Vinbero/commit/f4c49e26b60ec0c8f213404cbc855b9ffc363557))
* **interop:** apply frr.conf once; pin attribute-only VPN UPDATEs ([445feb4](https://github.com/takehaya/Vinbero/commit/445feb411dcfd5f86d540380e98675f38cd3ee25))
* **interop:** describe how watchfrr applies frr.conf at start ([f9fb46e](https://github.com/takehaya/Vinbero/commit/f9fb46ea743b3d6bbe2557f3ff3f708c0180479c))
* **interop:** watchfrr applies frr.conf once all daemons are up ([77cf5d5](https://github.com/takehaya/Vinbero/commit/77cf5d52b0a145d3c388d70dae05cfc043149e15))
* **l2:** drop a BUM copy whose uplink the plan does not cover ([af8a91c](https://github.com/takehaya/Vinbero/commit/af8a91c1033e43064a4ca36115557d89ed85ffb2))
* **l2:** refuse a create whose ifindex another interface took during it ([2a065da](https://github.com/takehaya/Vinbero/commit/2a065daa345a63deb53859cb97bf8f933f64a67d))
* **l2:** rewrite a state file a failed write left behind, and record a rename made during a create ([b41b49e](https://github.com/takehaya/Vinbero/commit/b41b49e573eb7bae251ef8d4af0674f106afb2ec))
* **lint:** validate JSON without requiring output ([78aeb35](https://github.com/takehaya/Vinbero/commit/78aeb35d402ba6504970009a508f81d383a1f546))
* **netlink:** retry a failed listing, remove before adding in the route resync, rearm the carrier window ([920c4cc](https://github.com/takehaya/Vinbero/commit/920c4cc0b6de67aec0564d7459155fd5a30ed17d))
* **netlink:** stop multicasting dump requests, resubscribe every watch, open route sockets only ([51a4a38](https://github.com/takehaya/Vinbero/commit/51a4a3825f3e16126e19c0b974aa4a3833d4dc5d))
* **netlink:** stop multicasting dump requests, resubscribe every watch, open route sockets only ([11e0dd0](https://github.com/takehaya/Vinbero/commit/11e0dd0606ecf0f32d52e6402d626407c68b7ee7))
* **netlinkwatch:** age xdp-mode local MACs without fdb_aging_seconds ([ffb9f77](https://github.com/takehaya/Vinbero/commit/ffb9f772a6c8b3c1b00af34e3e9e1bde1d074c71))
* **netresource:** keep runtime bridge members on a transient failure ([025e680](https://github.com/takehaya/Vinbero/commit/025e680cb266cf7288cbe984f3c93920453852c8))
* **sdk:** preserve fenced examples when staging README links ([a5c25f5](https://github.com/takehaya/Vinbero/commit/a5c25f56ea45980f978fe2eb47aa628fa308c8f1))
* **sdk:** rebuild plugins when an SDK or core header changes ([e5ab283](https://github.com/takehaya/Vinbero/commit/e5ab283fd853a3a9cfad2cbd9851c4be97879b8d))
* **sdk:** reject repeated and case-mismatched JSON keys ([7dde3f4](https://github.com/takehaya/Vinbero/commit/7dde3f47097635394c47114471a99038bb480e12))
* **sdk:** validate present custom-behavior keys as written ([94273f3](https://github.com/takehaya/Vinbero/commit/94273f33588a827507348ea90baae56e049e1bb3))
* **sdk:** verify archives when git is unavailable ([18d60a0](https://github.com/takehaya/Vinbero/commit/18d60a02a914e3cfe906987e061734c7ce81c8ff))
* **server:** reject every interface name the kernel rejects ([8a62f28](https://github.com/takehaya/Vinbero/commit/8a62f2835465d4e67c120073615dbf3df2bfed68))
* **vinberod:** refuse an unnamed binding before it creates a VRF, and keep a failed boot drop pending ([d2ecec6](https://github.com/takehaya/Vinbero/commit/d2ecec6ae438b0b0a8113135aa6c23436fee8fbc))
* **vinbero:** keep a device that fails to attach on start for another reason ([5ec85e7](https://github.com/takehaya/Vinbero/commit/5ec85e73aeefeff12c693d6574fabe7891a532eb))
* **vinbero:** let a detach whose state write failed be retried ([06fcf96](https://github.com/takehaya/Vinbero/commit/06fcf96a67d3a70449e3d6413657a3a9896dee55))
* **vinbero:** refuse a runtime attach in another XDP mode under xdp BUM ([b37f298](https://github.com/takehaya/Vinbero/commit/b37f298a8a9398f48acb7f0f0ceb27026cf8f9f1))
* **vinbero:** refuse an invalid internal.bpf.device_mode at boot ([d69217f](https://github.com/takehaya/Vinbero/commit/d69217f13a16d769effacff700b55497f601dbc3))
* **vrf,bpf:** check every VRF device on a table it closes and keep a destination written before its release ([0d8df5f](https://github.com/takehaya/Vinbero/commit/0d8df5fddac26d2d7af26b76e603a01f7ba8aa9b))
* **vrf,bpf:** check L2 circuits wherever a table is closed and release under the notify lock ([0fdab3c](https://github.com/takehaya/Vinbero/commit/0fdab3c4a94d9689301a3c9838f1618d9c3a37d8))
* **vrf:** check a table over every port it will have and hold it open only once its defaults are gone ([aed7aff](https://github.com/takehaya/Vinbero/commit/aed7aff07f098df25c82939f8953e0e9ac731b2f))
* **vrf:** decide closedness by table and check an adopt's existing ports ([bf447cb](https://github.com/takehaya/Vinbero/commit/bf447cb701abb7502a5cb502e086ae113db4ff56))
* **vrf:** keep encapsulation next hops resolved and own the defaults ([6a876d7](https://github.com/takehaya/Vinbero/commit/6a876d75c0bc65b80c74fa8f1f65ad781e7810f5))
* **vrf:** keep headend VRF state removable and the no-name requests global ([46f9623](https://github.com/takehaya/Vinbero/commit/46f9623411ec3e4add818fc13c116dc98083ea3c))
* **vrf:** leave malformed headend keys out of the delete refusal ([7209641](https://github.com/takehaya/Vinbero/commit/72096416cfe6f095b856e994f41602db5fffc692))
* **vrf:** refuse removing a bridge member the config declares ([5fd8f12](https://github.com/takehaya/Vinbero/commit/5fd8f12cf9aa0d31eae1301dee86341e5c023127))
* **vrf:** refuse to allocate past the last vrf_id ([29c24ff](https://github.com/takehaya/Vinbero/commit/29c24ff2cf7760ae62b3713cde698c955a8bf24d))
* **vrf:** rework the next-hop keeper and close tables only with TBID ([d239dcf](https://github.com/takehaya/Vinbero/commit/d239dcf1e1d0584c7c0d299c11a8dad092209783))
* **vrf:** save boot ids first and keep state and answers in step ([0d1f611](https://github.com/takehaya/Vinbero/commit/0d1f61103fc39b062b1659a08447caf053c53426))
* **vrf:** serialize L2 circuit creates with VRF creates, keep an unsaved device's facet, retry interrupted dumps ([341e352](https://github.com/takehaya/Vinbero/commit/341e352b9f29993926d9774c14e0516ce2bf8102))
* **vrf:** skip runtime ACs whose interface is gone in Reconcile ([6dfda52](https://github.com/takehaya/Vinbero/commit/6dfda523bc76af711dde4c477a5262abab0b8667))
* **vrf:** tie the config bridge member refusal to the config's bridge ([1147099](https://github.com/takehaya/Vinbero/commit/1147099aab203e810316601c83fdbc44285e1822))


### ⚡ Performance Improvements

* **bpf:** make the BPF test suite finish in seconds instead of minutes ([#151](https://github.com/takehaya/Vinbero/issues/151)) ([b81e8b4](https://github.com/takehaya/Vinbero/commit/b81e8b49d062836da10d68134082abb35b90426d))
* **bpf:** rebuild the xdp BUM devmaps once per bd_peer call ([698a22f](https://github.com/takehaya/Vinbero/commit/698a22f6901d47d0134951ce12196e664f0d5528))
* **config:** look the BUM mode of a BD up without building a map ([90fd89c](https://github.com/takehaya/Vinbero/commit/90fd89c70508a1c88cce1bc2dea7773411f6c267))
* **cplane:** encode composition headend bodies directly ([e3a0897](https://github.com/takehaya/Vinbero/commit/e3a089786794be99d87470727e256126fb225c05))
* **cplane:** reuse compiled code for compatible registrations ([99c7e05](https://github.com/takehaya/Vinbero/commit/99c7e050707fd979003eee253f73a5c32c086d36))
* **cplane:** reuse compiled code for compatible registrations ([687e07f](https://github.com/takehaya/Vinbero/commit/687e07ffaf8b87a0a8d4462ead4dcaf25f732426))
* **cplane:** reuse route key ordering between view mutations ([3dae639](https://github.com/takehaya/Vinbero/commit/3dae639f2e42361912b5de3b7fd9760acf0abfc0))
* **cplane:** traverse ordered route slots without key lookups ([06ebec8](https://github.com/takehaya/Vinbero/commit/06ebec8906d70e9f3526bfc502ac297522e12c2c))
* **cplane:** visit resolved pairs without a snapshot slice ([f412052](https://github.com/takehaya/Vinbero/commit/f412052fadb17558fd36f05d9a8656cfeb259deb))


### 📝 Documentation

* **bpf:** document provenance tracking limits ([af9cdb1](https://github.com/takehaya/Vinbero/commit/af9cdb1d9797b6b6164ff3ce4fd99c90c6ed13a8))
* **bum:** describe BUM over an ECMP underlay ([f00661e](https://github.com/takehaya/Vinbero/commit/f00661ef34bc85b9067187ab56999afc353e6f07))
* **cni:** cover what running under Kubernetes actually needs ([19c8206](https://github.com/takehaya/Vinbero/commit/19c8206ae551bb43ed74fb66bff059086789e408))
* **cni:** describe the CNI plugin and how to deploy it ([e7ba5f5](https://github.com/takehaya/Vinbero/commit/e7ba5f5ec40b0fcebff5f77568654d3a3185842b))
* **cni:** note the attach mode constraint under xdp BUM ([ff9bf06](https://github.com/takehaya/Vinbero/commit/ff9bf067b2b5a3134f0f33c16e24727794ae1a88))
* **cplane:** add an opt-in batched MUP policy ([6b88b0e](https://github.com/takehaya/Vinbero/commit/6b88b0eadb99244a0f8ab9278b560fa2ee913c3f))
* **cplane:** add an opt-in batched MUP policy ([cd7f07e](https://github.com/takehaya/Vinbero/commit/cd7f07ee15b793700961d39a7503ad4d5234f0ce))
* **cplane:** clarify behavior claim release semantics ([94ac586](https://github.com/takehaya/Vinbero/commit/94ac586c397d643b30628106f5a7d4f7402c5af0))
* **cplane:** describe present keys and strict JSON key matching ([7cc6031](https://github.com/takehaya/Vinbero/commit/7cc60319061f46d0eccd3a8a2da592e37a8a6550))
* **cplane:** describe registration grants and JSON configuration ([ff1e7e0](https://github.com/takehaya/Vinbero/commit/ff1e7e00c63ff9bf249982d64723aad2474faf1d))
* **cplane:** distinguish preparation errors from overflow recovery ([14900fc](https://github.com/takehaya/Vinbero/commit/14900fcc711b4906defad738c8b89ae9b944c61a))
* **cplane:** guide dynamic WASM loading and fix SDK links ([db5d206](https://github.com/takehaya/Vinbero/commit/db5d2066229f8fee82c97f01e81367b76c5594e6))
* **cplane:** guide dynamic WASM loading and fix SDK links ([6f0360f](https://github.com/takehaya/Vinbero/commit/6f0360f92bd902f3cdf193770275cb06cd2dfee5))
* **cplane:** require shared implementations across native and WASM ([02c4a2d](https://github.com/takehaya/Vinbero/commit/02c4a2d48a622ae309dfd65625d7aa5dc8d2bbb0))
* **cplane:** 設計 doc に安全性の不変条件と lifecycle の境界を明文化する ([#143](https://github.com/takehaya/Vinbero/issues/143)) ([ee8c896](https://github.com/takehaya/Vinbero/commit/ee8c896352dce2bd4feaeca688f0ee4b8c994f85))
* describe how VRF bindings made over the API survive a restart ([c8a9654](https://github.com/takehaya/Vinbero/commit/c8a96540ff3d3404022d3d5308ee8ae8dda0bba7))
* describe naming the VRF of a headend entry ([ce4fa2d](https://github.com/takehaya/Vinbero/commit/ce4fa2db514cd65601d1a2e249e6788adfe27295))
* describe tenant separation, overlapping pod subnets and the per-VRF lookup ([f1d1dfa](https://github.com/takehaya/Vinbero/commit/f1d1dfa3b3ae6b8aceb89405a6868923158ea8d3))
* describe the {vrf_id, prefix} headend key and pin compatibility ([ca28940](https://github.com/takehaya/Vinbero/commit/ca28940bfa0a8053045d3c8555b90e843c483dfd))
* describe the BUM replication modes ([6b9d507](https://github.com/takehaya/Vinbero/commit/6b9d50778530a1a5316c4be80f0417c144eafc16))
* describe the global default, the delete refusal and the boot cleanup ([9b92ccf](https://github.com/takehaya/Vinbero/commit/9b92ccffe5c566a9c606019dd77e2308731fa08f))
* describe the per-VRF reach of a behavior claim ([dd69a43](https://github.com/takehaya/Vinbero/commit/dd69a435b164c27aa22aed40b0fe7e9ec065d615))
* describe the xdp BUM replication plan and its limits ([fc5dec2](https://github.com/takehaya/Vinbero/commit/fc5dec2e99005ba36703ba97f785077b337f3c19))
* describe xdp BUM mode in native XDP ([c8a1e13](https://github.com/takehaya/Vinbero/commit/c8a1e13c8683196261d74ccd846786087696e8ad))
* design runtime device attach ([0493150](https://github.com/takehaya/Vinbero/commit/049315045f96857f57e1b764e14643be68861b7f))
* **evpn:** state that a stored segment with a rejected ESI skips only the start-up election ([3647efd](https://github.com/takehaya/Vinbero/commit/3647efdd036d25df8c4a30bb8696cce59c38762e))
* **examples:** align bilingual index with configured plugin example ([7ca2c0f](https://github.com/takehaya/Vinbero/commit/7ca2c0f006ab568c9a0fa8fe204b19cecae29f47))
* **examples:** make the netns example READMEs English-first ([#147](https://github.com/takehaya/Vinbero/issues/147)) ([3a33b5b](https://github.com/takehaya/Vinbero/commit/3a33b5b51089b092d3c83d9fe00573eb1aedd899))
* **examples:** name the custom Cplane and Dplane behavior demo ([76a3406](https://github.com/takehaya/Vinbero/commit/76a3406591a25f8a8676623b51fcc7324242813c))
* **examples:** provide English and Japanese example indexes ([7c27ce4](https://github.com/takehaya/Vinbero/commit/7c27ce4eb6afb903f20b70f5ed8938d0a40143aa))
* **examples:** provide English and Japanese example indexes ([5adca16](https://github.com/takehaya/Vinbero/commit/5adca16dc9f6077783deefcb573af6e8caf25d6c))
* **l2:** describe the 33-PE run of the BUM scale example ([1e7cfd7](https://github.com/takehaya/Vinbero/commit/1e7cfd7070acc5360e63a71efd5b5e003ae48b02))
* note that plugins cannot bypass uplink_tx_map ([6fde889](https://github.com/takehaya/Vinbero/commit/6fde889fb7cb759dfd685f51313c03c9f1c935e7))
* qualify the tenant separation, and fix cplane and SDK statements on VRFs and restarts ([b9981b5](https://github.com/takehaya/Vinbero/commit/b9981b5b5db6a588c2f053899c6b96716ed865cf))
* **readme:** state which interop scenarios run against FRR ([a5b5bc9](https://github.com/takehaya/Vinbero/commit/a5b5bc90b0248c66b7fae91e3fbf26cb69418631))
* **readme:** state which interop scenarios run against FRR ([1cc4d24](https://github.com/takehaya/Vinbero/commit/1cc4d24209d8da235c58e904d20464acc9c4617c))
* **vrf:** describe the boot order, the config origin and save failures ([b4a5a23](https://github.com/takehaya/Vinbero/commit/b4a5a23d358e1cd711d973b242d8742333c35847))
* **vrf:** describe the next-hop keeper, the opt-out and route ownership ([63fc6c5](https://github.com/takehaya/Vinbero/commit/63fc6c560d2c3634fd3fc44e74c4dcc82e0a0372))
* **vrf:** describe the two lookup modes and the reworked keeper ([1e6f54d](https://github.com/takehaya/Vinbero/commit/1e6f54d50af9fbe7e37913d20bbc869596978f94))
* **vrf:** drop the helper name from the adjacency row ([5c1db34](https://github.com/takehaya/Vinbero/commit/5c1db3424e6f5196a7b42972cafde73aead71741))
* **vrf:** explain how ip rule history affects FIB lookup cost ([d92ac4b](https://github.com/takehaya/Vinbero/commit/d92ac4b0e6bc651ee0fb8fc6143adf148f539d15))
* **vrf:** include global service proxy returns and qualify the End.DT4 VRF requirement ([6fbe5e7](https://github.com/takehaya/Vinbero/commit/6fbe5e78997ee94c460cea8696934a8ffb5fae4e))
* **vrf:** ip rule history and FIB lookup cost ([7bff3f0](https://github.com/takehaya/Vinbero/commit/7bff3f037e1829da5141007237e441870a392ab3))
* **vrf:** say what happens to ids when the boot save fails ([e9d3096](https://github.com/takehaya/Vinbero/commit/e9d3096448e32c9d456bdc3bf6d98dde44df68c2))
* **vrf:** state the per-family scope and complete the FIB lookup table ([daa4a19](https://github.com/takehaya/Vinbero/commit/daa4a198f065bc2c69f55b4f3e612d2753b6504a))
* **vrf:** with auto the forwarding cost no longer follows the rule history, and IPv6 skips the local table ([154c908](https://github.com/takehaya/Vinbero/commit/154c9082335dbe7a450360adfb9cb6397a4a5089))


### 🔧 Miscellaneous Chores

* **cplane:** merge main into the control plane plugin branch ([ebdc546](https://github.com/takehaya/Vinbero/commit/ebdc54657fe22ff883c74239a20217dabf695427))
* **deps:** move GoBGP to the fork on top of v4.11.0 ([1c436e7](https://github.com/takehaya/Vinbero/commit/1c436e7cd232339ebffa161110aba4b381bb434f))
* **deps:** move GoBGP to the fork on top of v4.11.0 ([12c8f70](https://github.com/takehaya/Vinbero/commit/12c8f70faf6fb44a45d4ce7bf14e22713ff72803))
* **deps:** pin the GoBGP fork by its release tag ([982ead2](https://github.com/takehaya/Vinbero/commit/982ead2984ecc8af1c3ee9c9b25344dd768529dc))
* **deps:** take the OpenConfirm hold timer fix into the GoBGP fork ([6770a42](https://github.com/takehaya/Vinbero/commit/6770a426fca25e9206562cc3428829d314759a5c))
* **deps:** take two upstream FSM fixes into the GoBGP fork ([c48fcde](https://github.com/takehaya/Vinbero/commit/c48fcde566e44cd3c7d33ecbf02595c480ff9f2f))
* merge origin/main into feat/global-direct-fib-lookup ([a8b5a19](https://github.com/takehaya/Vinbero/commit/a8b5a19eec1729a84957bcb96376bc1197446e37))
* merge origin/main into fix/esi-validation ([b747089](https://github.com/takehaya/Vinbero/commit/b747089a366ef2269ffa12217f53c5c69e6cdd8a))
* update mise compilers and stabilize privileged tests ([022f710](https://github.com/takehaya/Vinbero/commit/022f71048f870740c159e567741d497d2d32dd5f))


### ♻️ Code Refactoring

* **bgp:** drop the migration off the per-RD VPN trigger owner ([99759c4](https://github.com/takehaya/Vinbero/commit/99759c43412769f0f4f7f6f02dce6926bf249a85))
* **bgp:** separate built-in delivery transitions from callbacks ([#177](https://github.com/takehaya/Vinbero/issues/177)) ([3251005](https://github.com/takehaya/Vinbero/commit/325100528d00247f832477b1b57b770d02485cb4))
* **bgp:** separate VPN selection from application ([#175](https://github.com/takehaya/Vinbero/issues/175)) ([0c8d987](https://github.com/takehaya/Vinbero/commit/0c8d9875acd5a7a4d6c0e7d2051f8a08a3b26c3d))
* **bgp:** track received VPN paths and MUP gates per VRF ([d28d221](https://github.com/takehaya/Vinbero/commit/d28d22163369333be62d8ece8842ffbc2bca4692))
* **bgp:** track received VPN paths and MUP gates per VRF ([df686ad](https://github.com/takehaya/Vinbero/commit/df686adec310048ff034e88afcf399181254aca5))
* **bpf:** drop the reserved auto-mode and unused plan fields ([8447a3b](https://github.com/takehaya/Vinbero/commit/8447a3b5079778a59383f83854c792e64f8290c5))
* **bpf:** share the headend lookup VRF with the ECMP demo tool ([d98ce7a](https://github.com/takehaya/Vinbero/commit/d98ce7ab9f66e8c006a5b71d3b0a95c54321e74a))
* **cplane:** decode native grants once per instance ([dad7080](https://github.com/takehaya/Vinbero/commit/dad708039b2b484324f41fe48625016cdd2d063f))
* **cplane:** share headend reconciliation with built-in appliers ([#173](https://github.com/takehaya/Vinbero/issues/173)) ([7b67ab4](https://github.com/takehaya/Vinbero/commit/7b67ab4b5d6c03b57cddcd8fbef8985b976aab29))
* **netresource:** enslave bridge and VRF members through one helper ([15ea535](https://github.com/takehaya/Vinbero/commit/15ea535dac8473f917a38220d78cbdd15e938dcb))
* **sdk:** extract documentation link verifier ([75415df](https://github.com/takehaya/Vinbero/commit/75415dfdf3fed22702feafa9a28be73b9a8cf7b0))
* **sdk:** share varint decoding with the wire package ([1fd60d1](https://github.com/takehaya/Vinbero/commit/1fd60d15e811934d124983ff85dcc7679af5541b))
* **vinbero:** close device links through one helper ([d99a4fa](https://github.com/takehaya/Vinbero/commit/d99a4fad5b848ee2ab21a444fc58863e4cf8356b))

## [0.1.1](https://github.com/takehaya/Vinbero/compare/v0.1.0...v0.1.1) (2026-08-17)


### 🎉 Features

* **api:** expose the ECMP path groups over RPC and vbctl ([#123](https://github.com/takehaya/Vinbero/issues/123)) ([bf01efa](https://github.com/takehaya/Vinbero/commit/bf01efa257e8dc258e49c879bda2ab323458aa1b))
* **bgp:** aggregate a VPN prefix's paths into one ECMP group ([#121](https://github.com/takehaya/Vinbero/issues/121)) ([135e362](https://github.com/takehaya/Vinbero/commit/135e362e297eb56fe761df8a7fa8b1b62df558e7))
* **bgp:** carry per-path identity on received routes ([#119](https://github.com/takehaya/Vinbero/issues/119)) ([ec61332](https://github.com/takehaya/Vinbero/commit/ec613324c27cf26db77e22be0327dc618089965d))
* **bpf:** End.AD dynamic proxy (service programming) ([#109](https://github.com/takehaya/Vinbero/issues/109)) ([f333baa](https://github.com/takehaya/Vinbero/commit/f333baabf1c381a2d989ca065199bb1e7b04ac72))
* **bpf:** End.AM masquerading proxy (service programming) ([#110](https://github.com/takehaya/Vinbero/issues/110)) ([30f1fed](https://github.com/takehaya/Vinbero/commit/30f1fed9c9547c4ef1a9a4663419c192f313cba6))
* **bpf:** End.AN for SR-aware services (service programming) ([#111](https://github.com/takehaya/Vinbero/issues/111)) ([e28e5db](https://github.com/takehaya/Vinbero/commit/e28e5dbcfb11fb0fab9fe8ed9a79f62f797a7e33))
* **bpf:** End.AS static proxy (service programming) ([#108](https://github.com/takehaya/Vinbero/issues/108)) ([91b5565](https://github.com/takehaya/Vinbero/commit/91b55652401e50bdbdf50f2cc0c2b26b038ae330))
* **bpf:** service programming return-path base (End.AS/AD/AM/AN groundwork) ([#107](https://github.com/takehaya/Vinbero/issues/107)) ([b851fa1](https://github.com/takehaya/Vinbero/commit/b851fa17d42fc2e6f71259dcd86299f71f1df053))
* **evpn:** decode RT1 Ethernet A-D routes ([#125](https://github.com/takehaya/Vinbero/issues/125)) ([8526d74](https://github.com/takehaya/Vinbero/commit/8526d745afd00d9797c61886a94704035022e913))
* **evpn:** RT1 aliasing で multi-homed segment を ECMP group に集約する ([#127](https://github.com/takehaya/Vinbero/issues/127)) ([005e1a5](https://github.com/takehaya/Vinbero/commit/005e1a56da7bc36aa6e089de10ae9324dc4d4093))
* **evpn:** RT1 Ethernet A-D を advertise し aliasing を interop 検証する ([#130](https://github.com/takehaya/Vinbero/issues/130)) ([12f11bb](https://github.com/takehaya/Vinbero/commit/12f11bbd0d95435b2647ba86a2d3a973ee412574))
* **fib:** install multipath kernel routes ([#122](https://github.com/takehaya/Vinbero/issues/122)) ([4077c9d](https://github.com/takehaya/Vinbero/commit/4077c9dbc952ad128e99a3fd01fb560bdc84cb66))
* **interop:** ecmp-2site シナリオで path group と prober を E2E 検証する ([#129](https://github.com/takehaya/Vinbero/issues/129)) ([fbb9a8a](https://github.com/takehaya/Vinbero/commit/fbb9a8a9f622d02efa8189417413422c25807a7f))
* **prober:** SR Policy transport を probe の journey に反映する ([#131](https://github.com/takehaya/Vinbero/issues/131)) ([1312f3f](https://github.com/takehaya/Vinbero/commit/1312f3fbd15abe314d2df4a91105684ffdecfdf4))
* **prober:** SRv6 self-probe で ECMP path の生死を検知し fast reroute する ([#128](https://github.com/takehaya/Vinbero/issues/128)) ([11f87a4](https://github.com/takehaya/Vinbero/commit/11f87a441c4a37bbfe35b7b6c37fb1f1783d6b76))
* **service-programming:** re-derive return-path outer flow label from inner flow ([#117](https://github.com/takehaya/Vinbero/issues/117)) ([55d1d7c](https://github.com/takehaya/Vinbero/commit/55d1d7cd251f164db0b57eaa12872e1a88c0259d))
* **srpolicy:** decode every weighted Segment List ([#124](https://github.com/takehaya/Vinbero/issues/124)) ([9a0be0c](https://github.com/takehaya/Vinbero/commit/9a0be0cc558d3b793ff66e629e81af1a8f784eab))
* **stats:** per-slot invocation counters for service-return behaviors ([#116](https://github.com/takehaya/Vinbero/issues/116)) ([b00a1b6](https://github.com/takehaya/Vinbero/commit/b00a1b6baf54935e0144595acb85a487e617ffc8))


### 🐛 Bug Fixes

* **bpf:** harden service programming (OCR review follow-up) ([#112](https://github.com/takehaya/Vinbero/issues/112)) ([f8f050f](https://github.com/takehaya/Vinbero/commit/f8f050f7a0ea76ad26b2e92b29ed5323a2a28c80))
* **bpf:** service programming return-path dataplane correctness (review follow-up 3) ([#114](https://github.com/takehaya/Vinbero/issues/114)) ([5337b5d](https://github.com/takehaya/Vinbero/commit/5337b5d2812ec7e82d84872d3b734026b032d32f))
* **interop:** l3vpn-2site の connected locator hack による RA 毒経路を除去する ([#132](https://github.com/takehaya/Vinbero/issues/132)) ([6b349ee](https://github.com/takehaya/Vinbero/commit/6b349ee07cfc4a3a3b29a9629badb7e83c5b4804))
* **sdk:** Go SDK の aux helper が使えない drift を直す ([#136](https://github.com/takehaya/Vinbero/issues/136)) ([e0b9f15](https://github.com/takehaya/Vinbero/commit/e0b9f15eac2188f66084035ac74b65234d6a5cf2))
* **server:** close proxy circuit lifecycle gaps from the review ([#113](https://github.com/takehaya/Vinbero/issues/113)) ([a888631](https://github.com/takehaya/Vinbero/commit/a88863109f23d7ed59129c5e8fddc39c23f47531))
* **srpolicy:** do not reuse policy ids a restart left referenced ([#120](https://github.com/takehaya/Vinbero/issues/120)) ([e63aa03](https://github.com/takehaya/Vinbero/commit/e63aa0311e1f20a68af351a2f9f27daf716aa11c))


### 📝 Documentation

* **readme:** scope the interop bullet to the CI scenarios ([#105](https://github.com/takehaya/Vinbero/issues/105)) ([748d637](https://github.com/takehaya/Vinbero/commit/748d63783e00a3c2e33030a891d67a72ab49dd22))


### 🔧 Miscellaneous Chores

* gitignore docs/plan so working notes cannot be committed ([#118](https://github.com/takehaya/Vinbero/issues/118)) ([b5fb952](https://github.com/takehaya/Vinbero/commit/b5fb952bb23172345a1870faf6c0206225b36012))

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
