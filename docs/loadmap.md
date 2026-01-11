
## List of SRv6 functions of interest and status (Road Map)

### Reference list

- [RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming](https://datatracker.ietf.org/doc/rfc8986/)
  - [draft-filsfils-spring-srv6-net-pgm-insertion-09](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-net-pgm-insertion/09/)
- [RFC 9433: Segment Routing over IPv6 for the Mobile User Plane](https://datatracker.ietf.org/doc/rfc9433/)
  - [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding/)

### Headend behaviors

| Function         | Phase | Status      | Description                                      |
|------------------|:-----:|-------------|--------------------------------------------------|
| H                | 1     |             | Headend with SRH insertion                       |
| H.Insert         | 2     |             | Headend with SRH insertion (existing IPv6)       |
| H.Insert.Red     | 2     |             | H.Insert with reduced SRH                        |
| H.Encaps         | 2     | Supported   | Headend with encapsulation in outer IPv6 header  |
| H.Encaps.Red     | 2     |             | H.Encaps with reduced SRH                        |
| H.Encaps.L2      | 3     |             | H.Encaps with L2 payload                         |
| H.Encaps.L2.Red  | 3     |             | H.Encaps.L2 with reduced SRH                     |

### Functions associated with a SID

| Function             | Phase | Status      | Description                                                                 |
|----------------------|:-----:|-------------|-----------------------------------------------------------------------------|
| End                  | 1     | Supported   | Endpoint function                                                           |
| End.X                | 1     |             | Endpoint with Layer-3 cross-connect                                         |
| End.T                | 1     |             | Endpoint with specific IPv6 table lookup                                    |
| End.DX2 (V)          | 1     |             | Endpoint with decap and L2 cross-connect (VLAN)                             |
| End.DT2 (U/M)        | 1     |             | Endpoint with decap and L2 table lookup (Unicast/Multicast)                 |
| End.DX6              | 1     | Supported   | Endpoint with decap and IPv6 cross-connect                                  |
| End.DX4              | 1     | Supported   | Endpoint with decap and IPv4 cross-connect                                  |
| End.DT6              | 1     |             | Endpoint with decap and IPv6 table lookup                                   |
| End.DT4              | 3     |             | Endpoint with decap and IPv4 table lookup                                   |
| End.DT46             | 3     |             | Endpoint with decap and IP (v4/v6) table lookup                             |
| End.B6.Insert        | 2     |             | Endpoint bound to SRv6 policy with insertion                                |
| End.B6.Insert.Red    | 2     |             | End.B6.Insert with reduced SRH                                              |
| End.B6.Encaps        | 2     |             | Endpoint bound to SRv6 policy with encapsulation                            |
| End.B6.Encaps.Red    | 2     |             | End.B6.Encaps with reduced SRH                                              |
| End.BM               | ?     |             | Endpoint bound to SR-MPLS policy                                            |
| End.S                | 2     |             | Endpoint in search of a target in table T                                   |
| Args.Mob.Session     | 4     |             | Consider with End.MAP, End.DT and End.DX                                    |
| End.MAP              | 4     |             | Endpoint function with SID argument mapping                                 |
| End.M.GTP6.D         | 4     |             | GTP-U/IPv6 => SRv6                                                          |
| End.M.GTP6.D.Di      | 4     |             | GTP-U/IPv6 => SRv6 with DI (Drop-In)                                        |
| End.M.GTP6.E         | 4     |             | SRv6 => GTP-U/IPv6                                                          |
| End.M.GTP4.E         | 4     |             | SRv6 => GTP-U/IPv4                                                          |
| H.M.GTP4.D           | 4     |             | GTP-U/IPv4 => SRv6                                                          |
| End.Limit            | 4     |             | Rate limiting function                                                      |

### Non-functional design items

| Item name                       | Phase |
|---------------------------------|:-----:|
| BSID-friendly table structure   | 1     |

### Flavours

| Function | Phase | Status      | Description                          |
|----------|:-----:|-------------|--------------------------------------|
| PSP      | 1     |             | Penultimate Segment Pop              |
| USP      | 1     |             | Ultimate Segment Pop                 |
| USD      | 3     |             | Ultimate Segment Decapsulation       |


