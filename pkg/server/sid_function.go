package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// SidFunctionServer implements the SidFunctionServiceHandler interface
type SidFunctionServer struct {
	mapOps *bpf.MapOperations
}

// NewSidFunctionServer creates a new SidFunctionServer
func NewSidFunctionServer(mapOps *bpf.MapOperations) *SidFunctionServer {
	return &SidFunctionServer{mapOps: mapOps}
}

// SidFunctionCreate creates SID function entries
func (s *SidFunctionServer) SidFunctionCreate(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionCreateRequest],
) (*connect.Response[v1.SidFunctionCreateResponse], error) {
	resp := &v1.SidFunctionCreateResponse{
		Created: make([]*v1.SidFunction, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, sidFunc := range req.Msg.SidFunctions {
		entry, aux, err := s.protoToEntry(sidFunc)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateSidFunction(sidFunc.TriggerPrefix, entry, aux); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		// Create End.B6 policy entry if segments are specified
		if len(sidFunc.Segments) > 0 {
			policyEntry, err := s.buildPolicyEntry(sidFunc)
			if err != nil {
				// Rollback: remove the SID function entry
				_ = s.mapOps.DeleteSidFunction(sidFunc.TriggerPrefix)
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: sidFunc.TriggerPrefix,
					Reason:        fmt.Sprintf("policy: %s", err.Error()),
				})
				continue
			}
			if err := s.mapOps.CreateEndB6Policy(sidFunc.TriggerPrefix, policyEntry); err != nil {
				_ = s.mapOps.DeleteSidFunction(sidFunc.TriggerPrefix)
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: sidFunc.TriggerPrefix,
					Reason:        fmt.Sprintf("policy map: %s", err.Error()),
				})
				continue
			}
		}

		resp.Created = append(resp.Created, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionDelete deletes SID function entries
func (s *SidFunctionServer) SidFunctionDelete(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionDeleteRequest],
) (*connect.Response[v1.SidFunctionDeleteResponse], error) {
	resp := &v1.SidFunctionDeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteSidFunction(prefix); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: prefix,
				Reason:        err.Error(),
			})
			continue
		}
		// Best-effort cleanup of End.B6 policy entry
		_ = s.mapOps.DeleteEndB6Policy(prefix)
		resp.DeletedTriggerPrefixes = append(resp.DeletedTriggerPrefixes, prefix)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionList lists all SID function entries
func (s *SidFunctionServer) SidFunctionList(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionListRequest],
) (*connect.Response[v1.SidFunctionListResponse], error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.SidFunctionListResponse{
		SidFunctions: make([]*v1.SidFunction, 0, len(entries)),
	}

	for prefix, entry := range entries {
		sidFunc := s.entryToProto(prefix, entry)
		resp.SidFunctions = append(resp.SidFunctions, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionGet retrieves a specific SID function entry
func (s *SidFunctionServer) SidFunctionGet(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionGetRequest],
) (*connect.Response[v1.SidFunctionGetResponse], error) {
	entry, err := s.mapOps.GetSidFunction(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.SidFunctionGetResponse{
		SidFunction: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf SidFunction to a BPF generic entry + optional aux entry
func (s *SidFunctionServer) protoToEntry(sidFunc *v1.SidFunction) (*bpf.SidFunctionEntry, *bpf.SidAuxEntry, error) {
	entry := &bpf.SidFunctionEntry{
		Action: uint8(sidFunc.Action),
		Flavor: uint8(sidFunc.Flavor),
	}

	// Resolve vrf_name → vrf_ifindex for End.T/DT4/DT6/DT46
	if sidFunc.VrfName != "" {
		vrfIfindex, err := resolveIfindex(sidFunc.VrfName)
		if err != nil {
			return nil, nil, fmt.Errorf("vrf %q: %w", sidFunc.VrfName, err)
		}
		entry.VrfIfindex = vrfIfindex
	}

	// Build aux entry based on action type
	var aux *bpf.SidAuxEntry
	action := v1.Srv6LocalAction(sidFunc.Action)

	switch action {
	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2:
		nexthop, err := bpf.ParseIPv6(sidFunc.Nexthop)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxNexthop(nexthop)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2:
		bridgeIfindex := uint32(0)
		if sidFunc.BridgeName != "" {
			idx, err := resolveIfindex(sidFunc.BridgeName)
			if err != nil {
				return nil, nil, fmt.Errorf("bridge %q: %w", sidFunc.BridgeName, err)
			}
			bridgeIfindex = idx
		}
		aux = bpf.NewSidAuxL2(uint16(sidFunc.BdId), bridgeIfindex)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E:
		if sidFunc.GtpV4SrcAddr == "" {
			return nil, nil, fmt.Errorf("gtp_v4_src_addr is required for END_M_GTP4_E")
		}
		gtpV4Src, err := bpf.ParseIPv4Optional(sidFunc.GtpV4SrcAddr)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxGtp4e(uint8(sidFunc.ArgsOffset), gtpV4Src)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_D,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_D_DI:
		aux = bpf.NewSidAuxGtp6d(uint8(sidFunc.ArgsOffset))

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_E:
		srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
		if err != nil {
			return nil, nil, err
		}
		dstAddr, err := bpf.ParseIPv6(sidFunc.DstAddr)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxGtp6e(uint8(sidFunc.ArgsOffset), srcAddr, dstAddr)
	}

	return entry, aux, nil
}

// entryToProto converts a BPF map entry to a protobuf SidFunction
func (s *SidFunctionServer) entryToProto(prefix string, entry *bpf.SidFunctionEntry) *v1.SidFunction {
	sf := &v1.SidFunction{
		Action:        v1.Srv6LocalAction(entry.Action),
		TriggerPrefix: prefix,
		Flavor:        v1.Srv6LocalFlavor(entry.Flavor),
		VrfName:       ifindexToName(entry.VrfIfindex),
	}

	// Read aux data if present
	if entry.HasAux != 0 {
		aux, err := s.mapOps.GetSidAux(entry.AuxIndex)
		if err == nil && aux != nil {
			action := v1.Srv6LocalAction(entry.Action)
			switch action {
			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2:
				sf.Nexthop = bpf.FormatIPv6(aux.Nexthop.Nexthop)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2:
				bdID, bridgeIfindex := bpf.SidAuxL2Data(aux)
				sf.BdId = uint32(bdID)
				sf.BridgeName = ifindexToName(bridgeIfindex)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E:
				argsOffset, gtpV4Src := bpf.SidAuxGtp4eData(aux)
				sf.ArgsOffset = uint32(argsOffset)
				sf.GtpV4SrcAddr = bpf.FormatIPv4Optional(gtpV4Src)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_D,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_D_DI:
				sf.ArgsOffset = uint32(aux.Nexthop.Nexthop[0])

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_E:
				sf.ArgsOffset = uint32(aux.Nexthop.Nexthop[0])
				// src_addr at bytes 8-23, dst_addr at bytes 24-39
				// These span the padding area; read via Nexthop for bytes 8-15
				var srcAddr, dstAddr [bpf.IPv6AddrLen]uint8
				copy(srcAddr[:8], aux.Nexthop.Nexthop[8:16])
				// Remaining bytes are in padding - for read-back we'd need raw access
				// For now, report what's accessible
				sf.SrcAddr = bpf.FormatIPv6(srcAddr)
				sf.DstAddr = bpf.FormatIPv6(dstAddr)
			}
		}
	}

	// Include policy fields for End.B6/End.B6.Encaps from policy map
	if entry.Action == uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6) ||
		entry.Action == uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS) {
		policy, err := s.mapOps.GetEndB6Policy(prefix)
		if err == nil && policy != nil {
			sf.Segments = bpf.FormatSegments(policy.Segments, policy.NumSegments)
			sf.HeadendMode = v1.Srv6HeadendBehavior(policy.Mode)
		}
	}

	return sf
}

// buildPolicyEntry creates a HeadendEntry for the End.B6 policy map
func (s *SidFunctionServer) buildPolicyEntry(sidFunc *v1.SidFunction) (*bpf.HeadendEntry, error) {
	srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
	if err != nil {
		return nil, err
	}

	segments, numSegments, err := bpf.ParseSegments(sidFunc.Segments)
	if err != nil {
		return nil, err
	}

	return &bpf.HeadendEntry{
		Mode:        uint8(sidFunc.HeadendMode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
	}, nil
}
