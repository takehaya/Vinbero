#ifndef SRV6_GTP_H
#define SRV6_GTP_H

#include <linux/types.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"

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

        // 3GPP TS 38.415 PSC: QFI in the low 6 bits, RQI in bit 6 (inverse of
        // ENCODE_PSC_QFI_RQI). Inline because this site precedes that macro's
        // definition in this header.
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
// SID = LOC:FUNCT:[IPv4 DA]:Args.Mob.Session
//
// RFC 9433 Section 6.1 lays Args.Mob.Session out MSB-first as
//   [QFI(6b)|R(1b)|U(1b)][PDU Session ID / TEID ...]
// so the QFI byte is (QFI << 2) | (R << 1) | U and the TEID follows it. The
// gNB IPv4 DA (GTP4 only) precedes Args.Mob.Session. Concretely:
//
// GTP4 Args layout (9 bytes): [IPv4 DstAddr (4B)][QFI(1B)][TEID (4B)]
// GTP6 Args layout (5 bytes):                    [QFI(1B)][TEID (4B)]
//
// QFI-before-TEID (and QFI in the high 6 bits) is the RFC 9433 wire layout, so an
// End.M.GTP4.E SID composed by one implementation decodes correctly on another.
// (Vinbero historically used [TEID][QFI] with QFI in the low 6 bits, which only
// interoperated with itself.)

// SRv6 Args.Mob.Session QFI byte (RFC 9433 Section 6.1): QFI occupies the high 6
// bits (bits 7..2), R is bit 1, U (always 0) is bit 0. Used only for the SID's
// embedded Args.Mob.Session -- NOT for the GTP-U PDU Session Container, which is
// a different (3GPP) layout (see ENCODE_PSC_QFI_RQI below).
#define ENCODE_QFI_RQI(qfi, rqi) ((((qfi) & 0x3F) << 2) | (((rqi) & 0x01) << 1))
// Decode the QFI / RQI back out of that SRv6 Args.Mob.Session byte.
#define DECODE_QFI(flags) (((flags) >> 2) & 0x3F)
#define DECODE_RQI(flags) (((flags) >> 1) & 0x01)

// GTP-U PDU Session Container QFI byte (3GPP TS 38.415): QFI occupies the low 6
// bits (bits 5..0), RQI is bit 6, PPP is bit 7. This is the on-the-wire GTP-U
// extension-header layout the gNB/UPF reads, and is distinct from the SRv6
// Args.Mob.Session byte above -- the two MUST NOT share an encoding.
#define ENCODE_PSC_QFI_RQI(qfi, rqi) (((qfi) & 0x3F) | (((rqi) & 0x01) << 6))

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
        // 3GPP TS 38.415 PSC layout (QFI low 6 bits), NOT the SRv6 Args.Mob.Session
        // layout -- this octet goes on the wire to the gNB/UPF.
        psc->qfi_flags = ENCODE_PSC_QFI_RQI(qfi, rqi);
        psc->next_ext_type = 0x00;
    } else {
        gtph->flags = GTPU_V1_FLAGS;  // No E flag
        gtph->length = bpf_htons(payload_len);
    }

    return 0;
}

#endif // SRV6_GTP_H
