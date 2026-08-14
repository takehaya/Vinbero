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
//   - "plugin:v1:bundle=<name>"           -- plugin (see plugin_owner.go)
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

// OwnerBGPVPNGroup owns the ECMP groups holding the paths learned for VPN
// prefixes.
//
// It is deliberately scoped by neither RD nor prefix. Not by RD, because a
// prefix reachable through several PEs arrives under a different RD per PE
// and an RD-scoped owner would make the second PE's path fail the
// cross-owner check -- the very defect this aggregation removes (same
// reasoning as OwnerBGPMUPGate). Not by prefix, because owner tags persist
// into a 64-byte buffer and "asn + vpngroup + family + an expanded IPv6
// prefix" runs to ~80 bytes, which would truncate silently and take both
// the ownership check and any tag-derived bookkeeping down with it.
//
// One consequence is that the tag cannot say WHICH prefix a surviving group
// belonged to. Group ids are therefore not resumed across a restart: the
// applier sweeps the groups under this owner at startup and rebuilds them
// as BGP re-advertises. Trigger entries carry fallback segments so a
// briefly unresolvable group degrades to single-path forwarding rather than
// dropping.
func OwnerBGPVPNGroup(asn uint32) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:vpngroup", OwnerTagVersion, asn))
}

// OwnerBGPEVPNGroup owns the ECMP groups an EVPN multi-homed Ethernet
// Segment aliases over: one group per {bridge domain, ESI}, holding one
// member per all-active PE that advertised a per-EVI Ethernet A-D route.
// Scoped like OwnerBGPVPNGroup and for the same reasons: the members arrive
// under per-PE RDs, and the segment identity would overflow the tag buffer.
// The applier sweeps this owner's groups at startup and rebuilds them from
// the replayed rib.
func OwnerBGPEVPNGroup(asn uint32) OwnerTag {
	return OwnerTag(fmt.Sprintf("bgp:%s:asn=%d:evpngroup", OwnerTagVersion, asn))
}

// IsLegacyBGPVPNOwner reports whether tag is a pre-aggregation VPN owner
// belonging to this node: the RD-scoped form OwnerBGPVPN produced when each
// prefix was written per RD.
//
// It exists for the upgrade. Those entries persist in the pinned headend
// maps, and the aggregating writer uses an RD-independent owner, so every
// previously installed prefix would fail the cross-owner check and never
// reinstall. Recognising the old shape lets the writer clear exactly its
// own leftovers, and nothing else -- an operator's RPC-installed entry for
// the same prefix must survive.
func IsLegacyBGPVPNOwner(asn uint32, tag OwnerTag) bool {
	prefix := fmt.Sprintf("bgp:%s:asn=%d:rd=", OwnerTagVersion, asn)
	rd, ok := strings.CutPrefix(string(tag), prefix)
	// An empty RD is the aggregating writer's own owner, not a legacy one.
	return ok && rd != ""
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
	// OwnerKindPlugin marks a main-map entry written on behalf of a plugin.
	// It shares its literal with AuxOwnerKindPlugin so a plugin identity
	// reads the same in the entry-owner and aux-owner namespaces; see
	// plugin_owner.go for the two tag forms and their canonicalization.
	OwnerKindPlugin = AuxOwnerKindPlugin
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
	case OwnerKindRPC, OwnerKindBuiltin, OwnerKindBGP, OwnerKindPlugin:
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

// IterateU32 returns every (key, tag) pair in an owner map keyed by
// uint32. Entries whose tag does not decode are skipped rather than
// reported: an undecodable tag means the entry predates owner tracking or
// was written by an incompatible build, and neither is worth failing a
// startup scan over.
func (o *entryOwnerMap) IterateU32() (map[uint32]OwnerTag, error) {
	out := make(map[uint32]OwnerTag)
	if o == nil {
		return out, nil
	}
	var key uint32
	var v [auxOwnerTagBytes]byte
	iter := o.m.Iterate()
	for iter.Next(&key, &v) {
		if s, ok := decodeOwnerTag(v[:]); ok {
			out[key] = OwnerTag(s)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate owner map: %w", err)
	}
	return out, nil
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
