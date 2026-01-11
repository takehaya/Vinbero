
## List of SRv6 functions of interest and status (Road Map)

### Reference list

- [RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming](https://datatracker.ietf.org/doc/rfc8986/)
  - [draft-filsfils-spring-srv6-net-pgm-insertion-09](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-net-pgm-insertion/09/)
- [RFC 9433: Segment Routing over IPv6 for the Mobile User Plane](https://datatracker.ietf.org/doc/rfc9433/)
  - [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding/)

### Headend behaviors

| Function         | Status      | Description                                      |
|------------------|-------------|--------------------------------------------------|
| H                |             | Headend with SRH insertion                       |
| H.Insert         |             | Headend with SRH insertion (existing IPv6)       |
| H.Insert.Red     |             | H.Insert with reduced SRH                        |
| H.Encaps         | Supported   | Headend with encapsulation in outer IPv6 header  |
| H.Encaps.Red     |             | H.Encaps with reduced SRH                        |
| H.Encaps.L2      |             | H.Encaps with L2 payload                         |
| H.Encaps.L2.Red  |             | H.Encaps.L2 with reduced SRH                     |

### Functions associated with a SID

| Function             | Status      | Description                                                 |
|----------------------|-------------|-------------------------------------------------------------|
| End                  | Supported   | Endpoint function                                           |
| End.X                |             | Endpoint with Layer-3 cross-connect                         |
| End.T                |             | Endpoint with specific IPv6 table lookup                    |
| End.DX2 (V)          |             | Endpoint with decap and L2 cross-connect (VLAN)             |
| End.DT2 (U/M)        |             | Endpoint with decap and L2 table lookup (Unicast/Multicast) |
| End.DX6              | Supported   | Endpoint with decap and IPv6 cross-connect                  |
| End.DX4              | Supported   | Endpoint with decap and IPv4 cross-connect                  |
| End.DT6              |             | Endpoint with decap and IPv6 table lookup                   |
| End.DT4              |             | Endpoint with decap and IPv4 table lookup                   |
| End.DT46             |             | Endpoint with decap and IP (v4/v6) table lookup             |
| End.B6.Insert        |             | Endpoint bound to SRv6 policy with insertion                |
| End.B6.Insert.Red    |             | End.B6.Insert with reduced SRH                              |
| End.B6.Encaps        |             | Endpoint bound to SRv6 policy with encapsulation            |
| End.B6.Encaps.Red    |             | End.B6.Encaps with reduced SRH                              |
| End.BM               |             | Endpoint bound to SR-MPLS policy                            |
| End.S                |             | Endpoint in search of a target in table T                   |
| Args.Mob.Session     |             | Consider with End.MAP, End.DT and End.DX                    |
| End.MAP              |             | Endpoint function with SID argument mapping                 |
| End.M.GTP6.D         |             | GTP-U/IPv6 => SRv6                                          |
| End.M.GTP6.D.Di      |             | GTP-U/IPv6 => SRv6 with DI (Drop-In)                        |
| End.M.GTP6.E         |             | SRv6 => GTP-U/IPv6                                          |
| End.M.GTP4.E         |             | SRv6 => GTP-U/IPv4                                          |
| H.M.GTP4.D           |             | GTP-U/IPv4 => SRv6                                          |
| End.Limit            |             | Rate limiting function                                      |

### Flavours

| Function | Status      | Description                    |
|----------|-------------|--------------------------------|
| PSP      |             | Penultimate Segment Pop        |
| USP      |             | Ultimate Segment Pop           |
| USD      |             | Ultimate Segment Decapsulation |
