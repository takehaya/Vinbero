
## List of SRv6 functions of interest and status (Road Map)

### Reference list

- [RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming](https://datatracker.ietf.org/doc/rfc8986/)
  - [draft-filsfils-spring-srv6-net-pgm-insertion-09](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-net-pgm-insertion/09/)
- [RFC 9433: Segment Routing over IPv6 for the Mobile User Plane](https://datatracker.ietf.org/doc/rfc9433/)
  - [draft-murakami-dmm-user-plane-message-encoding](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding/)

### Headend behaviors

| Function         | Phase | Description       |
|------------------|:-----:|-------------------|
| H                | 1     | Headend behavior  |
| H.Insert         | 2     |                   |
| H.Insert.Red     | 2     |                   |
| H.Encaps         | 2     |                   |
| H.Encaps.Red     | 2     |                   |
| H.Encaps.L2      | 3     |                   |
| H.Encaps.L2.Red  | 3     |                   |

### Functions associated with a SID

| Function             | Phase | Description                                                                 |
|----------------------|:-----:|-----------------------------------------------------------------------------|
| End                  | 1     |                                                                             |
| End.X                | 1     |                                                                             |
| End.T                | 1     |                                                                             |
| End.DX2 (V)          | 1     |                                                                             |
| End.DT2 (U/M)        | 1     |                                                                             |
| End.DX6              | 1     |                                                                             |
| End.DX4              | 1     |                                                                             |
| End.DT6              | 1     |                                                                             |
| End.DT4              | 3     |                                                                             |
| End.DT46             | 3     |                                                                             |
| End.B6.Insert        | 2     |                                                                             |
| End.B6.Insert.Red    | 2     |                                                                             |
| End.B6.Encaps        | 2     |                                                                             |
| End.B6.Encaps.Red    | 2     |                                                                             |
| End.BM               | ?     |                                                                             |
| End.S                | 2     |                                                                             |
| Args.Mob.Session     | 4     | Consider with End.MAP, End.DT and End.DX                                    |
| End.MAP              | 4     |                                                                             |
| End.M.GTP6.D         | 4     | GTP-U/IPv6 => SRv6 (treated as headend for implementation)                 |
| End.M.GTP6.D.Di      | 4     | GTP-U/IPv6 => SRv6 (treated as headend for implementation)                 |
| End.M.GTP6.E         | 4     | SRv6 => GTP-U/IPv6                                                          |
| End.M.GTP4.E         | 4     | SRv6 => GTP-U/IPv4 (gtpv1ext header not supported)                          |
| H.M.GTP4.D           | 4     | GTP-U/IPv4 => SRv6 (gtpv1ext header not supported)                          |
| End.Limit            | 4     | Rate limiting function                                                      |

### Non-functional design items

| Item name                       | Phase |
|---------------------------------|:-----:|
| BSID-friendly table structure   | 1     |

### Flavours

| Function | Phase | Description                          |
|----------|:-----:|--------------------------------------|
| PSP      | 1     | Penultimate Segment Pop              |
| USP      | 1     | Ultimate Segment Pop                 |
| USD      | 3     | Ultimate Segment Decapsulation       |


