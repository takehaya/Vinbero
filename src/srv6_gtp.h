#ifndef SRV6_GTP_H
#define SRV6_GTP_H

#include <linux/types.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"

// ========== GTP-U Protocol Constants (3GPP TS 29.281) ==========

#define GTPU_PORT         2152
#define GTPU_TYPE_GPDU    0xFF

// GTP-U flags (byte 0)
#define GTPU_FLAG_VERSION 0xE0  // Version mask (bits 7-5)
#define GTPU_FLAG_PT      0x10  // Protocol Type (bit 4)
#define GTPU_FLAG_E       0x04  // Extension Header flag (bit 2)
#define GTPU_FLAG_S       0x02  // Sequence Number flag (bit 1)
#define GTPU_FLAG_PN      0x01  // N-PDU Number flag (bit 0)

// GTP-U v1 mandatory flags: Version=1, PT=1
#define GTPU_V1_FLAGS     0x30  // 0b00110000

// Extension header types
#define GTPU_EXT_PDU_SESSION  0x85  // PDU Session Container

// ========== GTP-U Header Structures ==========

// Mandatory GTP-U header (8 bytes)
struct gtpu_hdr {
    __u8  flags;       // [Version(3)|PT(1)|*(1)|E(1)|S(1)|PN(1)]
    __u8  type;        // Message Type (0xFF = G-PDU)
    __be16 length;     // Payload length (after mandatory header)
    __be32 teid;       // Tunnel Endpoint Identifier
} __attribute__((packed));

// Optional fields present when E/S/PN flags are set (4 bytes)
struct gtpu_opt_hdr {
    __be16 seq_num;    // Sequence Number
    __u8  npdu_num;    // N-PDU Number
    __u8  next_ext;    // Next Extension Header Type
} __attribute__((packed));

// PDU Session Container extension header (type 0x85)
// Minimal form: 4 bytes (length=1)
struct pdu_session_container {
    __u8 length;          // Length in 4-byte units (1 = 4 bytes, 2 = 8 bytes)
    __u8 pdu_type_flags;  // PDU Type(upper 4 bits) | flags(lower 4 bits)
    __u8 qfi_flags;       // PPP(1)|RQI(1)|QFI(6)
    __u8 next_ext_type;   // Next Extension Header Type
} __attribute__((packed));

// ========== GTP-U Parse Result ==========

struct gtpu_parsed {
    __u32 teid;           // Tunnel Endpoint Identifier
    __u8  qfi;            // QoS Flow Identifier (6 bits, 0-63)
    __u8  rqi;            // Reflective QoS Indication (1 bit)
    __u16 hdr_total_len;  // Total GTP-U header length (mandatory + optional + extensions)
};

// ========== GTP-U Parser ==========

// Parse GTP-U header including extension headers.
// Returns 0 on success, -1 on error.
// l4_ptr must point to the start of the UDP header.
static __always_inline int gtpu_parse(
    void *l4_ptr,
    void *data_end,
    struct gtpu_parsed *result)
{
    struct udphdr *udph = (struct udphdr *)l4_ptr;
    if ((void *)(udph + 1) > data_end)
        return -1;

    // Verify UDP destination port
    if (udph->dest != bpf_htons(GTPU_PORT))
        return -1;

    // Parse mandatory GTP-U header
    struct gtpu_hdr *gtph = (struct gtpu_hdr *)(udph + 1);
    if ((void *)(gtph + 1) > data_end)
        return -1;

    // Verify GTP-U v1 and G-PDU type
    if ((gtph->flags & (GTPU_FLAG_VERSION | GTPU_FLAG_PT)) != GTPU_V1_FLAGS)
        return -1;
    if (gtph->type != GTPU_TYPE_GPDU)
        return -1;

    result->teid = bpf_ntohl(gtph->teid);
    result->qfi = 0;
    result->rqi = 0;
    result->hdr_total_len = sizeof(struct gtpu_hdr);

    __u8 flags = gtph->flags;
    __u8 has_opt = flags & (GTPU_FLAG_E | GTPU_FLAG_S | GTPU_FLAG_PN);

    if (!has_opt)
        return 0;

    // Parse optional header (present when E/S/PN flags set)
    struct gtpu_opt_hdr *opt = (struct gtpu_opt_hdr *)(gtph + 1);
    if ((void *)(opt + 1) > data_end)
        return -1;

    result->hdr_total_len += sizeof(struct gtpu_opt_hdr);

    // If E flag is not set, no extension headers to parse
    if (!(flags & GTPU_FLAG_E))
        return 0;

    // Handle PDU Session Container (type 0x85) as the first extension header.
    // In 5G networks, this is the standard case (3GPP TS 29.281).
    // We support exactly one extension header (the PDU Session Container).
    // Other extension headers are skipped (QFI defaults to 0).
    __u8 next_ext = opt->next_ext;
    void *ext_ptr = (void *)(opt + 1);

    if (next_ext == GTPU_EXT_PDU_SESSION) {
        // PDU Session Container: 4 bytes minimum (length=1)
        // Layout: [length(1)] [pdu_type|flags(1)] [PPP|RQI|QFI(1)] [next_ext_type(1)]
        struct pdu_session_container *psc = (struct pdu_session_container *)ext_ptr;
        if ((void *)(psc + 1) > data_end)
            return -1;

        if (psc->length == 0)
            return -1;

        __u16 psc_bytes = (__u16)psc->length * 4;
        if (ext_ptr + psc_bytes > data_end)
            return -1;

        result->qfi = psc->qfi_flags & 0x3F;
        result->rqi = (psc->qfi_flags >> 6) & 0x01;
        result->hdr_total_len += psc_bytes;
    } else if (next_ext != 0x00) {
        if (ext_ptr + 1 > data_end)
            return -1;
        __u8 ext_len = *((__u8 *)ext_ptr);
        if (ext_len == 0)
            return -1;
        __u16 ext_bytes = (__u16)ext_len * 4;
        if (ext_ptr + ext_bytes > data_end)
            return -1;
        result->hdr_total_len += ext_bytes;
    }

    return 0;
}

// ========== Args.Mob.Session (RFC 9433 Section 6) ==========
//
// SID = LOC:FUNCT:Args.Mob.Session
//
// GTP4 Args layout (9 bytes):
//   [IPv4 DstAddr (4B)][TEID (4B)][QFI(6b)|R(1b)|U(1b)]
//
// GTP6 Args layout (5 bytes):
//   [TEID (4B)][QFI(6b)|R(1b)|U(1b)]

// Encode QFI(6bit) + RQI(1bit) + U(1bit) into a single byte
#define ENCODE_QFI_RQI(qfi, rqi) (((qfi) & 0x3F) | (((rqi) & 0x01) << 6))

// Detect inner protocol from first nibble of packet data.
// Returns 0 on success with inner_proto set, -1 on error.
static __always_inline int detect_inner_proto(
    void *inner_start,
    void *data_end,
    __u8 *inner_proto)
{
    if (inner_start + 1 > data_end)
        return -1;
    __u8 version = (*((__u8 *)inner_start)) >> 4;
    if (version == 4)
        *inner_proto = IPPROTO_IPIP;
    else if (version == 6)
        *inner_proto = IPPROTO_IPV6;
    else
        return -1;
    return 0;
}

// Encode Args.Mob.Session for GTP4 into a SID (16-byte array).
// offset: byte offset within the SID where Args.Mob.Session starts.
static __always_inline int args_mob_encode_gtp4(
    __u8 *sid,
    __u8 offset,
    __u8 *dst_v4,
    __u32 teid,
    __u8 qfi,
    __u8 rqi)
{
    if (offset + 9 > IPV6_ADDR_LEN)
        return -1;

    __builtin_memcpy(sid + offset, dst_v4, 4);

    __be32 teid_be = bpf_htonl(teid);
    __builtin_memcpy(sid + offset + 4, &teid_be, 4);

    sid[offset + 8] = ENCODE_QFI_RQI(qfi, rqi);

    return 0;
}

// Encode Args.Mob.Session for GTP6 into a SID (16-byte array).
static __always_inline int args_mob_encode_gtp6(
    __u8 *sid,
    __u8 offset,
    __u32 teid,
    __u8 qfi,
    __u8 rqi)
{
    if (offset + 5 > IPV6_ADDR_LEN)
        return -1;

    __be32 teid_be = bpf_htonl(teid);
    __builtin_memcpy(sid + offset, &teid_be, 4);

    sid[offset + 4] = ENCODE_QFI_RQI(qfi, rqi);

    return 0;
}

// Decode Args.Mob.Session for GTP4 from a SID.
static __always_inline int args_mob_decode_gtp4(
    const __u8 *sid,
    __u8 offset,
    __u8 *dst_v4,       // output: 4-byte IPv4 address
    __u32 *teid,        // output
    __u8 *qfi,          // output
    __u8 *rqi)          // output
{
    if (offset + 9 > IPV6_ADDR_LEN)
        return -1;

    __builtin_memcpy(dst_v4, sid + offset, 4);

    __be32 teid_be;
    __builtin_memcpy(&teid_be, sid + offset + 4, 4);
    *teid = bpf_ntohl(teid_be);

    __u8 flags = sid[offset + 8];
    *qfi = flags & 0x3F;
    *rqi = (flags >> 6) & 0x01;

    return 0;
}

// Decode Args.Mob.Session for GTP6 from a SID.
static __always_inline int args_mob_decode_gtp6(
    const __u8 *sid,
    __u8 offset,
    __u32 *teid,
    __u8 *qfi,
    __u8 *rqi)
{
    if (offset + 5 > IPV6_ADDR_LEN)
        return -1;

    __be32 teid_be;
    __builtin_memcpy(&teid_be, sid + offset, 4);
    *teid = bpf_ntohl(teid_be);

    __u8 flags = sid[offset + 4];
    *qfi = flags & 0x3F;
    *rqi = (flags >> 6) & 0x01;

    return 0;
}

// ========== GTP-U Header Builder (for encapsulation) ==========

// GTP-U encap header sizes:
//   With PSC: GTP-U(8) + optional(4) + PSC(4) = 16 bytes
//   Without PSC (QFI=0): GTP-U(8) = 8 bytes
#define GTPU_ENCAP_HDR_WITH_PSC  16
#define GTPU_ENCAP_HDR_NO_PSC     8

// Return GTP-U encap header length based on whether QFI is present
static __always_inline __u16 gtpu_encap_hdr_len(__u8 qfi, __u8 rqi)
{
    return (qfi > 0 || rqi > 0) ? GTPU_ENCAP_HDR_WITH_PSC : GTPU_ENCAP_HDR_NO_PSC;
}

// Build GTP-U headers at the given pointer.
// If qfi==0 && rqi==0: minimal header (8 bytes, no extension).
// Otherwise: with PDU Session Container (16 bytes).
// Caller must ensure ptr has at least gtpu_encap_hdr_len(qfi,rqi) bytes available.
// Returns 0 on success.
static __always_inline int gtpu_build_headers(
    void *ptr,
    void *data_end,
    __u32 teid,
    __u8 qfi,
    __u8 rqi,
    __u16 payload_len)
{
    int has_psc = (qfi > 0 || rqi > 0);
    __u16 hdr_len = has_psc ? GTPU_ENCAP_HDR_WITH_PSC : GTPU_ENCAP_HDR_NO_PSC;

    if (ptr + hdr_len > data_end)
        return -1;

    struct gtpu_hdr *gtph = (struct gtpu_hdr *)ptr;
    gtph->type = GTPU_TYPE_GPDU;
    gtph->teid = bpf_htonl(teid);

    if (has_psc) {
        gtph->flags = GTPU_V1_FLAGS | GTPU_FLAG_E;
        gtph->length = bpf_htons(4 + 4 + payload_len);

        struct gtpu_opt_hdr *opt = (struct gtpu_opt_hdr *)(gtph + 1);
        opt->seq_num = 0;
        opt->npdu_num = 0;
        opt->next_ext = GTPU_EXT_PDU_SESSION;

        struct pdu_session_container *psc = (struct pdu_session_container *)(opt + 1);
        psc->length = 1;
        psc->pdu_type_flags = 0x00;
        psc->qfi_flags = ENCODE_QFI_RQI(qfi, rqi);
        psc->next_ext_type = 0x00;
    } else {
        gtph->flags = GTPU_V1_FLAGS;  // No E flag
        gtph->length = bpf_htons(payload_len);
    }

    return 0;
}

#endif // SRV6_GTP_H
