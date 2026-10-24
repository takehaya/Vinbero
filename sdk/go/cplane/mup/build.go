package mup

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
)

// DownlinkContext supplies the complete SRv6 outer source and the remote
// GTP4 profile's byte offset. It never discovers an UPF anchor from an ST2.
// RQI is explicit because the pinned ST1 codec carries QFI but no RQI field.
type DownlinkContext struct {
	Source     netip.Addr
	ArgsOffset uint8
	RQI        uint8
}

func serviceForBuild(v resolve.Value[gobgppath.ServiceSID]) (gobgppath.ServiceSID, error) {
	if v.State != resolve.Present {
		return gobgppath.ServiceSID{}, fmt.Errorf("service SID state=%d: %s", v.State, v.Reason)
	}
	s := v.Value
	if !usableIP(s.Address) || !s.Address.Is6() || s.Flags != 0 {
		return s, fmt.Errorf("invalid_service_sid")
	}
	st := s.Structure
	if s.HasStructure && (int(st.LocatorBlock)+int(st.LocatorNode)+int(st.Function)+int(st.Argument) > 128 || st.TranspositionLength != 0 || st.TranspositionOffset != 0) {
		return s, fmt.Errorf("unsupported SID structure")
	}
	return s, nil
}

// BuildDownlink encodes RFC 9433's GTP4 Args.Mob.Session into the selected
// ISD SID. A missing/invalid SID rejects this pair, never selects another ISD.
func BuildDownlink(pair resolve.Pair[ST1, ISD], ctx DownlinkContext) (cplane.ForwardingHeadend, error) {
	var out cplane.ForwardingHeadend
	s, d := pair.Left, pair.Right
	if pair.Context == "" || !usableIP(ctx.Source) || !ctx.Source.Is6() {
		return out, fmt.Errorf("missing_downlink_context")
	}
	if !s.Prefix.IsValid() || s.Prefix.Addr().Is4In6() || !usableIP(s.Endpoint) || !s.Endpoint.Is4() {
		return out, fmt.Errorf("unsupported ST1 profile: GTP4 endpoint required")
	}
	if !d.Prefix.IsValid() || !d.Prefix.Contains(s.Endpoint) {
		return out, fmt.Errorf("ST1 endpoint is outside selected ISD")
	}
	if s.QFI > 63 || ctx.RQI > 1 {
		return out, fmt.Errorf("QFI or RQI out of range")
	}
	sid, err := serviceForBuild(d.Service)
	if err != nil {
		return out, err
	}
	if sid.Behavior != uint16(bgp.ENDM_GTP4E) {
		return out, fmt.Errorf("selected ISD is not End.M.GTP4.E")
	}
	st := sid.Structure
	functionEnd := int(st.LocatorBlock) + int(st.LocatorNode) + int(st.Function)
	if !sid.HasStructure || st.Function == 0 || int(st.LocatorBlock)+int(st.LocatorNode) == 0 || ctx.ArgsOffset > 7 || functionEnd != int(ctx.ArgsOffset)*8 || st.Argument < 72 {
		return out, fmt.Errorf("SID structure does not protect the configured 72-bit GTP4 argument area")
	}
	bytes := sid.Address.As16()
	endpoint := s.Endpoint.As4()
	offset := int(ctx.ArgsOffset)
	copy(bytes[offset:offset+4], endpoint[:])
	bytes[offset+4] = (s.QFI << 2) | (ctx.RQI << 1)
	binary.BigEndian.PutUint32(bytes[offset+5:offset+9], s.TEID)
	return cplane.ForwardingHeadend{Context: pair.Context, Entry: cplane.HeadendEntry{TriggerPrefix: s.Prefix.Masked().String(), Segments: []string{netip.AddrFrom16(bytes).String()}, SrcAddr: ctx.Source.String(), Mode: 2}}, nil // H.Encaps wire enum.
}

// BuildUplink targets the DSD's direct decapsulation SID. The host's MUP
// uplink profile disables argument rewriting; TEID remains a lookup key.
func BuildUplink(pair resolve.Pair[ST2, DSD], source netip.Addr) (cplane.MUPUplink, error) {
	var out cplane.MUPUplink
	s, d := pair.Left, pair.Right
	if pair.Context == "" || !usableIP(source) || !source.Is6() {
		return out, fmt.Errorf("missing_uplink_context")
	}
	if !usableIP(s.Endpoint) || !s.Endpoint.Is4() {
		return out, fmt.Errorf("unsupported ST2 profile: GTP4 endpoint required")
	}
	if s.TEIDBits > 32 {
		return out, fmt.Errorf("invalid TEID prefix length")
	}
	if s.Direct.State != resolve.Present || d.Direct.State != resolve.Present {
		return out, fmt.Errorf("unsupported direct segment: ST2 state=%d %s; DSD state=%d %s", s.Direct.State, s.Direct.Reason, d.Direct.State, d.Direct.Reason)
	}
	if s.Direct.Value != d.Direct.Value {
		return out, fmt.Errorf("ST2 and DSD direct segments differ")
	}
	sid, err := serviceForBuild(d.Service)
	if err != nil {
		return out, err
	}
	switch bgp.SRBehavior(sid.Behavior) {
	case bgp.END_DT4, bgp.END_DT6, bgp.END_DT46:
	default:
		return out, fmt.Errorf("unsupported DSD behavior: direct End.DT4/6/46 required")
	}
	teid := s.TEID & (^uint32(0) << uint(32-s.TEIDBits))
	return cplane.MUPUplink{Context: pair.Context, Endpoint: s.Endpoint.String(), TEID: teid, TEIDBits: s.TEIDBits, Segments: []string{sid.Address.String()}, SrcAddr: source.String()}, nil
}
