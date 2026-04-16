
## List of SRv6 functions of interest and status (Road Map)

### Reference list

- [RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming](https://datatracker.ietf.org/doc/rfc8986/)
  - [draft-filsfils-spring-srv6-net-pgm-insertion-09](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-net-pgm-insertion/09/)
- [RFC 9433: Segment Routing over IPv6 for the Mobile User Plane](https://datatracker.ietf.org/doc/rfc9433/)
  - [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding/)
- [RFC 9800: Compressed SRv6 Segment List Encoding](https://datatracker.ietf.org/doc/rfc9800/)
- [RFC 9524: Segment Routing Replication for Multicast](https://datatracker.ietf.org/doc/rfc9524/)
- [RFC 9491: Integration of the NSH and SRv6](https://datatracker.ietf.org/doc/rfc9491/)
- [draft-ietf-spring-sr-service-programming](https://datatracker.ietf.org/doc/draft-ietf-spring-sr-service-programming/)

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

### Functions associated with a SID

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| End                  | Supported   | Endpoint function                                           | RFC 8986 Sec.4.1 |
| End.X                | Supported   | Endpoint with Layer-3 cross-connect                         | RFC 8986 Sec.4.2 |
| End.T                | Supported   | Endpoint with specific IPv6 table lookup                    | RFC 8986 Sec.4.3 |
| End.DX2              | Supported   | Endpoint with decap and L2 cross-connect                    | RFC 8986 Sec.4.9 |
| End.DX2V             | Supported   | Endpoint with decap and VLAN L2 table lookup                | RFC 8986 Sec.4.10 |
| End.DT2U             | Supported   | Endpoint with decap and unicast MAC L2 table lookup         | RFC 8986 Sec.4.11 |
| End.DT2M             |             | Endpoint with decap and L2 table flooding                   | RFC 8986 Sec.4.12 |
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
| NEXT-CSID            |             | Compressed SID with next-based encoding                     | RFC 9800 |
| REPLACE-CSID         |             | Compressed SID with replace-based encoding                  | RFC 9800 |
| End.LBS              |             | Locator-Block Swap                                          | RFC 9800 |
| End.XLBS             |             | L3 cross-connect and Locator-Block Swap                     | RFC 9800 |

### Service programming (draft)

| Function             | Status      | Description                                                 | Reference |
|----------------------|-------------|-------------------------------------------------------------|-----------|
| End.AN               |             | SR-aware function (native SRv6 service)                     | draft-ietf-spring-sr-service-programming |
| End.AS               |             | Static proxy (SR-unaware service, static config)            | draft-ietf-spring-sr-service-programming |
| End.AD               |             | Dynamic proxy (SR-unaware service, dynamic detection)       | draft-ietf-spring-sr-service-programming |
| End.AM               |             | Masquerading proxy (SR-unaware service, masquerade SRH)     | draft-ietf-spring-sr-service-programming |

### Flavours

| Function | Status      | Description                    | Reference |
|----------|-------------|--------------------------------|-----------|
| PSP      | Supported   | Penultimate Segment Pop        | RFC 8986 Sec.4.16.1 |
| USP      | Supported   | Ultimate Segment Pop           | RFC 8986 Sec.4.16.2 |
| USD      | Supported   | Ultimate Segment Decapsulation | RFC 8986 Sec.4.16.3 |
