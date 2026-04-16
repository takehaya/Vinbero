package server

import (
	"context"
	"encoding/binary"
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

		// End.B6 policy is stored in sid_aux_map (b6_policy variant), no separate map needed

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
		// End.B6 policy is cleaned up automatically with aux entry
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
	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X:
		nexthop, err := bpf.ParseIPv6(sidFunc.Nexthop)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxNexthop(nexthop)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2:
		// DX2 stores OIF as uint32 in first 4 bytes of aux nexthop
		aux = &bpf.SidAuxEntry{}
		binary.NativeEndian.PutUint32(aux.Nexthop.Nexthop[:4], sidFunc.Oif)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2V:
		if sidFunc.TableId > 65535 {
			return nil, nil, fmt.Errorf("table_id %d exceeds maximum 65535", sidFunc.TableId)
		}
		aux = bpf.NewSidAuxDx2v(uint16(sidFunc.TableId))

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

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS:
		if len(sidFunc.Segments) > 0 {
			policyEntry, err := s.buildPolicyEntry(sidFunc)
			if err != nil {
				return nil, nil, fmt.Errorf("policy: %w", err)
			}
			aux = bpf.NewSidAuxB6Policy(policyEntry)
		}
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
			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X:
				sf.Nexthop = bpf.FormatIPv6(aux.Nexthop.Nexthop)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2:
				sf.Oif = binary.NativeEndian.Uint32(aux.Nexthop.Nexthop[:4])

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2V:
				sf.TableId = uint32(bpf.SidAuxDx2vData(aux))

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
				argsOffset, srcAddr, dstAddr := bpf.SidAuxGtp6eData(aux)
				sf.ArgsOffset = uint32(argsOffset)
				sf.SrcAddr = bpf.FormatIPv6(srcAddr)
				sf.DstAddr = bpf.FormatIPv6(dstAddr)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS:
				policy := bpf.SidAuxB6PolicyData(aux)
				sf.Segments = bpf.FormatSegments(policy.Segments, policy.NumSegments)
				sf.HeadendMode = v1.Srv6HeadendBehavior(policy.Mode)
				sf.SrcAddr = bpf.FormatIPv6(policy.SrcAddr)
			}
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
