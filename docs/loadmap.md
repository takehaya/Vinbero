
## List of SRv6 functions of interest and status (Road Map)

### Reference list

- [RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming](https://datatracker.ietf.org/doc/rfc8986/)
  - [draft-filsfils-spring-srv6-net-pgm-insertion-09](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-net-pgm-insertion/09/)
- [RFC 9433: Segment Routing over IPv6 for the Mobile User Plane](https://datatracker.ietf.org/doc/rfc9433/)
  - [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding/)
- [RFC 9800: Compressed SRv6 Segment List Encoding](https://datatracker.ietf.org/doc/rfc9800/)
- [RFC 9524: Segment Routing Replication for Multicast](https://datatracker.ietf.org/doc/rfc9524/)
- [RFC 9491: Integration of the NSH and SRv6](https://datatracker.ietf.org/doc/rfc9491/)
- [draft-ietf-spring-srv6-service-programming](https://datatracker.ietf.org/doc/draft-ietf-spring-srv6-service-programming/)

### Headend behaviors

| Function         | Status      | Description                                      | Reference |
|------------------|-------------|--------------------------------------------------|-----------|
| H.Insert         | Supported   | Headend with SRH insertion (existing IPv6)       | draft-filsfils-spring-srv6-net-pgm-insertion |
| H.Insert.Red     | Supported   | H.Insert with reduced SRH                        | draft-filsfils-spring-srv6-net-pgm-insertion |
| H.Encaps         | Supported   | Headend with encapsulation in outer IPv6 header  | RFC 8986 Sec.5.1 |
| H.Encaps.Red     | Supported   | H.Encaps with reduced SRH                        | RFC 8986 Sec.5.2 |
| H.Encaps.L2      | Supported   | H.Encaps with L2 payload                         | RFC 8986 Sec.5.3 |
| H.Encaps.L2.Red  | Supported   | H.Encaps.L2 with reduced SRH                     | RFC 8986 Sec.5.4 |
| H.M.GTP4.D       | Supported   | GTP-U/IPv4 => SRv6                               | RFC 9433 Sec.6.7 |
| H.M.GTP6.D       | Supported   | GTP-U/IPv6 => SRv6                               | RFC 9433 |

### Functions associated with a SID

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| End                  | Supported   | Endpoint function                                           | RFC 8986 Sec.4.1 |
| End.X                | Supported   | Endpoint with Layer-3 cross-connect                         | RFC 8986 Sec.4.2 |
| End.T                | Supported   | Endpoint with specific IPv6 table lookup                    | RFC 8986 Sec.4.3 |
| End.DX2              | Supported   | Endpoint with decap and L2 cross-connect                    | RFC 8986 Sec.4.9 |
| End.DX2V             | Supported   | Endpoint with decap and VLAN L2 table lookup                | RFC 8986 Sec.4.10 |
| End.DT2U             | Supported   | Endpoint with decap and unicast MAC L2 table lookup         | RFC 8986 Sec.4.11 |
| End.DT2M             | Supported   | Endpoint with decap and L2 table flooding                   | RFC 8986 Sec.4.12 |
| End.DX6              | Supported   | Endpoint with decap and IPv6 cross-connect                  | RFC 8986 Sec.4.4 |
| End.DX4              | Supported   | Endpoint with decap and IPv4 cross-connect                  | RFC 8986 Sec.4.5 |
| End.DT6              | Supported   | Endpoint with decap and IPv6 table lookup                   | RFC 8986 Sec.4.6 |
| End.DT4              | Supported   | Endpoint with decap and IPv4 table lookup                   | RFC 8986 Sec.4.7 |
| End.DT46             | Supported   | Endpoint with decap and IP (v4/v6) table lookup             | RFC 8986 Sec.4.8 |
| End.B6.Insert        | Supported   | Endpoint bound to SRv6 policy with insertion                | draft-filsfils-spring-srv6-net-pgm-insertion |
| End.B6.Insert.Red    | Supported   | End.B6.Insert with reduced SRH                              | draft-filsfils-spring-srv6-net-pgm-insertion |
| End.B6.Encaps        | Supported   | Endpoint bound to SRv6 policy with encapsulation            | RFC 8986 Sec.4.13 |
| End.B6.Encaps.Red    | Supported   | End.B6.Encaps with reduced SRH                              | RFC 8986 Sec.4.14 |
| End.BM               |             | Endpoint bound to SR-MPLS policy                            | RFC 8986 Sec.4.15 |
| End.Replicate        |             | Replication segment for multicast                           | RFC 9524 |
| End.NSH              |             | NSH segment for SFC                                         | RFC 9491 |

### Mobile user plane (RFC 9433)

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| Args.Mob.Session     | Supported   | GTP-U mobile session args in SID                            | RFC 9433 Sec.6.1 |
| End.MAP              |             | Endpoint function with SID argument mapping                 | RFC 9433 Sec.6.2 |
| End.M.GTP6.D         | Supported   | GTP-U/IPv6 => SRv6                                          | RFC 9433 Sec.6.3 |
| End.M.GTP6.D.Di      | Supported   | GTP-U/IPv6 => SRv6 with DI (Drop-In)                        | RFC 9433 Sec.6.4 |
| End.M.GTP6.E         | Supported   | SRv6 => GTP-U/IPv6                                          | RFC 9433 Sec.6.5 |
| End.M.GTP4.E         | Supported   | SRv6 => GTP-U/IPv4                                          | RFC 9433 Sec.6.6 |
| End.Limit            |             | Rate limiting function                                      | RFC 9433 Sec.6.8 |

### Compressed SID (RFC 9800)

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| NEXT-CSID            | Partial     | uN (End) / uA (End.X), F3216 only, single flavor            | RFC 9800 |
| REPLACE-CSID         |             | Compressed SID with replace-based encoding                  | RFC 9800 |
| End.LBS              |             | Locator-Block Swap                                          | RFC 9800 |
| End.XLBS             |             | L3 cross-connect and Locator-Block Swap                     | RFC 9800 |

### Service programming (draft)

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| End.AN               | Supported   | SR-aware function (native SRv6 service)                     | draft-ietf-spring-srv6-service-programming |
| End.AS               | Supported   | Static proxy (SR-unaware service, static config)            | draft-ietf-spring-srv6-service-programming |
| End.AD               | Supported   | Dynamic proxy (SR-unaware service, dynamic detection)       | draft-ietf-spring-srv6-service-programming |
| End.AM               | Supported   | Masquerading proxy (SR-unaware service, masquerade SRH)     | draft-ietf-spring-srv6-service-programming |

### Flavours

| Function | Status      | Description                    | Reference |
|----------|-------------|--------------------------------|-----------|
| PSP      | Supported   | Penultimate Segment Pop        | RFC 8986 Sec.4.16.1 |
| USP      | Supported   | Ultimate Segment Pop           | RFC 8986 Sec.4.16.2 |
| USD      | Supported   | Ultimate Segment Decapsulation | RFC 8986 Sec.4.16.3 |

### BGP control plane (SRv6 services)

In-process GoBGP speaker for exchanging SRv6 service routes (RFC 9252).
VPNv4/VPNv6 (L3) installs SRv6 H.Encaps headend entries, and EVPN (L2VPN)
bridges L2 over SRv6 with multi-homing; see the table below for the full
status.

| Function                   | Status    | Description                                              | Reference |
|----------------------------|-----------|----------------------------------------------------------|-----------|
| VPNv4/VPNv6 receive        | Supported | Decode SRv6 service SID/RD/RT, install H.Encaps headends | RFC 9252 |
| VPNv4/VPNv6 advertise      | Supported | Operator-explicit advertise/withdraw via BgpRouteService | RFC 9252 |
| IPv6 unicast receive       | Supported | Inject BGP-learned routes into the kernel FIB            | RFC 4760 |
| SRv6 locator manager       | Supported | RPC-driven locator pool / SID allocation                 | RFC 8986 |
| VRF <-> route-target binding | Supported | Import-RT filter for received VPN routes               | RFC 9252 |
| SR Policy (SAFI 73)        | Supported | Color-based steering (control + data plane)              | RFC 9256 |
| BGP MUP (SAFI 85)          | Supported | MUP route exchange (ISD/DSD/T1ST/T2ST, IPv4/IPv6) + apply: GTP4/GTP6 downlink H.Encaps + uplink F-TEID (H.M.GTP4.D_TEID / H.M.GTP6.D_TEID) | draft-mpmz-bess-mup-safi |
| Automatic advertise        | Partial   | VRF-export driven (config-time bindings and runtime VrfBgpBind RPC): connected/static prefixes auto-advertised as VPNv4/v6, and EVPN RT2/RT3 (local bridge MAC/BUM) and RT4 (local Ethernet Segment) driven by the bridge-device and binding lifecycles. A local SR Policy with `advertise=true` is originated into SAFI 73, and local MUP routes (ISD/DSD/T1ST/T2ST) are originated into SAFI 85 via MupService CRUD | RFC 9252 / 7432 / 9256 / draft-mpmz-bess-mup-safi |
| EVPN (RT2/3/4)             | Supported | L2VPN over BGP EVPN: RT2 MAC/IP, RT3 Inclusive Multicast, RT4 Ethernet Segment + RFC 8584 DF election / Local-Bias split-horizon (multi-homing). IRB (RT2 L3) and RT5 not yet supported | RFC 9252 / 7432 / 8584 |
