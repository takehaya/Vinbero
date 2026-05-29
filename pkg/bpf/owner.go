package bpf

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// OwnerTag identifies who wrote a given entry to a Vinbero main map
// (sid_function_map, headend_v4_map, headend_v6_map). The tag is persisted
// to the parallel *_owner_map so the daemon survives restart with owner
// identity intact.
//
// Wire format: <kind>:<version>[:<qualifier>...]
//
//   - "rpc:v1"                            -- RPC client (Connect handler)
//   - "builtin:v1"                        -- Vinbero internal automation
//   - "bgp:v1:asn=<asn>:rd=<rd>"          -- BGP VPN route
//   - "bgp:v1:asn=<asn>:unicast"          -- BGP IPv6 unicast route
//
// Entry-owner shares its byte representation (64-byte aux_owner) and
// version stamp with aux-owner (see AuxOwnerVersion / AuxOwnerBuiltin) so
// a future format bump migrates both namespaces in lockstep. The two
// namespaces remain distinct: aux-owner indexes uint32 aux slots, entry-
// owner indexes the main map's LPM key.
type OwnerTag string

// OwnerTagVersion piggybacks on AuxOwnerVersion so a single bump rolls
// the wire format for both owner namespaces together.
const OwnerTagVersion = AuxOwnerVersion

const (
	OwnerRPC OwnerTag = "rpc:" + OwnerTagVersion
	// OwnerBuiltin shares its literal value with AuxOwnerBuiltin so the
	// "vinbero-internal" identity reads the same in both namespaces. They
	// remain logically distinct constants because the maps they tag have
	// different key spaces.
	OwnerBuiltin = OwnerTag(AuxOwnerBuiltin)
)

// OwnerBGPVPN is the entry owner for a VPNv4 / VPNv6 prefix installed from
// a BGP UPDATE. The (asn, rd) pair is sufficient to attribute the entry
// back to the BGP session that learned it. Defined now; the receive path
// that calls it is wired up in Phase 1d.
func OwnerBGPVPN(asn uint32, rd string) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:rd=%s", OwnerTagVersion, asn, rd))
}

// OwnerBGPMUP is the entry owner for a downlink H.Encaps headend installed from
// a BGP MUP T1ST route (SAFI 85). Distinct from OwnerBGPVPN so MUP-owned entries
// are attributed to MUP and not to an L3VPN route that may share the same RD.
//
// NOTE (lifecycle): MUP entries are not yet owner-reconciled on boot/shutdown —
// there is no FlushByOwner caller for OwnerBGPMUP, and the mup_uplink_v{4,6}_map
// F-TEID entries carry no owner tag at all (they are keyed by the F-TEID, which
// is what the packet carries). With pinned maps, MUP data-plane state can outlive
// the process; today the in-memory reverse indexes in pkg/bgp/apply are the
// source of truth and a manual `make remove-ebpfmap` clears stale state between
// runs. Owner-scoped MUP reconcile is a forward-looking item.
func OwnerBGPMUP(asn uint32, rd string) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:mup:rd=%s", OwnerTagVersion, asn, rd))
}

// OwnerBGPMUPGate is the entry owner for the H.M.GTP{4,6}.D_TEID uplink gate
// (BGP MUP T2ST). The gate is shared by every session on one N3 endpoint
// regardless of RD — the uplink data plane keys on the F-TEID, not the RD — so
// the gate owner is deliberately RD-independent. This lets any session create or
// release the gate; an RD-scoped owner would make a second RD's withdraw fail the
// cross-owner check and leak the gate.
func OwnerBGPMUPGate(asn uint32) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:mup-gate", OwnerTagVersion, asn))
}

// OwnerBGPUnicast is the entry owner for an IPv6 unicast prefix derived
// from a BGP UPDATE. Reserved for any future path that caches unicast
// routes in BPF; today (Phase 1d plan) these go through netlink to the
// kernel FIB, so this is defined for completeness but not yet called.
func OwnerBGPUnicast(asn uint32) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:unicast", OwnerTagVersion, asn))
}

// Owner kind constants returned by ParseOwnerTag.
const (
	OwnerKindRPC     = "rpc"
	OwnerKindBuiltin = "builtin"
	OwnerKindBGP     = "bgp"
)

// ParseOwnerTag extracts the kind and version of a tag. Unknown kinds
// return an error so callers can refuse to operate on tags written by a
// format they do not recognize.
func ParseOwnerTag(tag OwnerTag) (kind, version string, err error) {
	s := string(tag)
	if s == "" {
		return "", "", errors.New("empty owner tag")
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("malformed owner tag %q (missing version)", s)
	}
	kind = parts[0]
	version = parts[1]
	switch kind {
	case OwnerKindRPC, OwnerKindBuiltin, OwnerKindBGP:
		return kind, version, nil
	default:
		return "", "", fmt.Errorf("unknown owner tag kind %q", kind)
	}
}

// ErrEntryOwnerMismatch is returned by Create / Delete / Flush on a main
// map when the caller's OwnerTag does not match the recorded entry owner
// and the operation was not invoked with force-override semantics.
var ErrEntryOwnerMismatch = errors.New("entry owner mismatch")

// ErrEmptyOwner is returned by Create when the supplied OwnerTag is the
// empty string. Empty would silently collide with "no recorded owner"
// during conflict checks; callers must pick a concrete tag.
var ErrEmptyOwner = errors.New("owner tag must be non-empty")

// encodeOwnerTag fills a fixed-width aux_owner.tag buffer with the given
// tag, reserving the last byte for the null terminator so the C side
// always reads a well-formed string.
func encodeOwnerTag(tag string) [auxOwnerTagBytes]byte {
	var v [auxOwnerTagBytes]byte
	copy(v[:auxOwnerTagBytes-1], tag)
	return v
}

// decodeOwnerTag reads a fixed-width aux_owner.tag buffer into a string.
// Returns ("", false) for an all-zero / never-written slot so callers do
// not treat it as a present-but-empty owner.
func decodeOwnerTag(v []byte) (string, bool) {
	n := 0
	for n < len(v) && v[n] != 0 {
		n++
	}
	if n == 0 {
		return "", false
	}
	return string(v[:n]), true
}

// entryOwnerMap persists the per-entry OwnerTag for one main map. It is
// the HASH-typed sibling of auxOwnerMap (which is ARRAY-backed for aux
// indices). A nil receiver means pinning is disabled: Put / Delete become
// no-ops, Lookup returns ("", false, nil), so the caller can ignore the
// owner space entirely when the BPF handle is unavailable.
//
// Key type matches the paired main map -- LpmKeyV6 for
// sid_function_owner_map and headend_v6_owner_map, LpmKeyV4 for
// headend_v4_owner_map. We accept it as any so one wrapper covers all
// three maps without generics.
//
// This type tracks write-permission ownership. It is deliberately not
// reused by the locator manager (pkg/locator): that subsystem's
// BindingTable records SID allocation provenance, a different concern,
// so the two stay separate.
type entryOwnerMap struct {
	m *ebpf.Map
}

func newEntryOwnerMap(m *ebpf.Map) *entryOwnerMap {
	if m == nil {
		return nil
	}
	return &entryOwnerMap{m: m}
}

func (o *entryOwnerMap) Put(key any, tag OwnerTag) error {
	if o == nil {
		return nil
	}
	v := encodeOwnerTag(string(tag))
	return o.m.Put(key, v)
}

// Delete tolerates ErrKeyNotExist so the caller can use Delete
// idempotently when rolling back a half-finished Create.
func (o *entryOwnerMap) Delete(key any) error {
	if o == nil {
		return nil
	}
	if err := o.m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// Lookup returns ("", false, nil) when no owner is recorded (the entry
// predates owner tracking or never existed), rather than surfacing it as
// an error.
func (o *entryOwnerMap) Lookup(key any) (OwnerTag, bool, error) {
	if o == nil {
		return "", false, nil
	}
	var v [auxOwnerTagBytes]byte
	if err := o.m.Lookup(key, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	s, ok := decodeOwnerTag(v[:])
	if !ok {
		return "", false, nil
	}
	return OwnerTag(s), true, nil
}
