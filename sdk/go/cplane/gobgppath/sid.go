package gobgppath

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	ErrMissingSID     = errors.New("missing_service_sid")
	ErrAmbiguousSID   = errors.New("ambiguous_service_sid")
	ErrInvalidSID     = errors.New("invalid_service_sid")
	ErrUnsupportedSID = errors.New("unsupported_service_sid_profile")
)

// SIDStructure and ServiceSID are value projections suitable for comparison.
type SIDStructure struct {
	LocatorBlock, LocatorNode, Function, Argument uint8
	TranspositionLength, TranspositionOffset      uint8
}
type ServiceSID struct {
	Address      netip.Addr
	Behavior     uint16
	Flags        uint8
	Structure    SIDStructure
	HasStructure bool
}

// ReadServiceSID accepts exactly one service SID and optional SID Structure.
// This profile has no MPLS-label input: transposition is explicitly unsupported.
// Unknown TLVs are retained by Path, but are not interpreted by this helper.
func ReadServiceSID(attrs []bgp.PathAttributeInterface, serviceType bgp.TLVType) (ServiceSID, error) {
	var result ServiceSID
	var firstErr error
	count := 0
	for _, a := range attrs {
		ps, ok := a.(*bgp.PathAttributePrefixSID)
		if !ok {
			continue
		}
		if ps == nil {
			return result, ErrInvalidSID
		}
		for _, t := range ps.TLVs {
			svc, ok := t.(*bgp.SRv6ServiceTLV)
			if !ok {
				continue
			}
			if svc == nil {
				return result, ErrInvalidSID
			}
			if svc.Type != serviceType {
				continue
			}
			for _, sub := range svc.SubTLVs {
				info, ok := sub.(*bgp.SRv6InformationSubTLV)
				if !ok {
					continue
				}
				count++
				sid, err := readSIDInformation(info)
				if count == 1 {
					result = sid
					firstErr = err
				}
			}
		}
	}
	if count == 0 {
		return ServiceSID{}, ErrMissingSID
	}
	if count != 1 {
		return ServiceSID{}, ErrAmbiguousSID
	}
	return result, firstErr
}
func readSIDInformation(info *bgp.SRv6InformationSubTLV) (ServiceSID, error) {
	var out ServiceSID
	if info == nil || len(info.SID) != 16 {
		return out, ErrInvalidSID
	}
	addr, _ := netip.AddrFromSlice(info.SID)
	if !addr.Is6() || addr.Is4In6() || !addr.IsGlobalUnicast() {
		return out, ErrInvalidSID
	}
	out.Address, out.Behavior, out.Flags = addr, info.EndpointBehavior, info.Flags
	if info.Flags != 0 {
		return out, fmt.Errorf("%w: flags", ErrUnsupportedSID)
	}
	for _, sub := range info.SubSubTLVs {
		st, ok := sub.(*bgp.SRv6SIDStructureSubSubTLV)
		if !ok {
			continue
		}
		if st == nil {
			return out, ErrInvalidSID
		}
		if out.HasStructure {
			return out, fmt.Errorf("%w: duplicate SID Structure", ErrAmbiguousSID)
		}
		out.HasStructure = true
		out.Structure = SIDStructure{st.LocatorBlockLength, st.LocatorNodeLength, st.FunctionLength, st.ArgumentLength, st.TranspositionLength, st.TranspositionOffset}
		if int(st.LocatorBlockLength)+int(st.LocatorNodeLength)+int(st.FunctionLength)+int(st.ArgumentLength) > 128 {
			return out, fmt.Errorf("%w: structure exceeds 128 bits", ErrInvalidSID)
		}
		if st.TranspositionLength == 0 && st.TranspositionOffset != 0 {
			return out, fmt.Errorf("%w: offset without transposition", ErrInvalidSID)
		}
		if int(st.TranspositionLength)+int(st.TranspositionOffset) > 128 {
			return out, fmt.Errorf("%w: transposition exceeds 128 bits", ErrInvalidSID)
		}
		if st.TranspositionLength != 0 {
			return out, fmt.Errorf("%w: transposition requires label-aware decoding", ErrUnsupportedSID)
		}
	}
	return out, nil
}
