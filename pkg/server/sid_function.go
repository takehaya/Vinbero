package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf/btf"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// sidFunctionErrorIdentifier picks a stable string for the OperationError
// TriggerPrefix field so a batched SidFunctionCreate response can be
// correlated back to its input. trigger_prefix is the natural choice
// when it is set; for locator_ref requests that fail before
// materialization the prefix is empty, so we fall back to the locator
// name (prefixed) which is recoverable to the operator's input.
func sidFunctionErrorIdentifier(sidFunc *v1.SidFunction) string {
	if p := sidFunc.GetTriggerPrefix(); p != "" {
		return p
	}
	if ref := sidFunc.GetLocatorRef(); ref != nil {
		return "locator:" + ref.GetName()
	}
	return ""
}

// parseLocatorSID extracts the 128-bit address from a /128 trigger_prefix
// minted by resolveLocatorRef so it can be looked up against the binding
// table. Non-/128 prefixes (legacy operator-built SIDs) return an error
// the caller treats as "not a locator binding".
func parseLocatorSID(prefix string) (netip.Addr, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	if p.Bits() != 128 {
		return netip.Addr{}, fmt.Errorf("locator SID must be /128, got %s", prefix)
	}
	return p.Addr(), nil
}

// AuxTypeLookup resolves a plugin slot to its BTF aux struct so the
// SidFunction handler can encode plugin_aux_json without a hard
// dependency on the full PluginServer. *PluginServer implements it.
type AuxTypeLookup interface {
	AuxType(mapType string, slot uint32) *btf.Struct
}

// SidFunctionServer implements the SidFunctionServiceHandler interface
type SidFunctionServer struct {
	mapOps     *bpf.MapOperations
	pluginAux  AuxTypeLookup
	locatorMgr *locator.Manager
}

// NewSidFunctionServer creates a new SidFunctionServer. pluginAux may be
// nil (plugin_aux_json then fails loudly). locatorMgr may also be nil,
// in which case any SidFunctionCreate carrying a locator_ref is rejected
// with a clear error -- legacy direct trigger_prefix requests still go
// through.
func NewSidFunctionServer(mapOps *bpf.MapOperations, pluginAux AuxTypeLookup, locatorMgr *locator.Manager) *SidFunctionServer {
	return &SidFunctionServer{mapOps: mapOps, pluginAux: pluginAux, locatorMgr: locatorMgr}
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
		if err := s.createOneSidFunction(sidFunc); err != nil {
			// A connect.Error means the request itself is malformed at
			// the server-config level (e.g. locator_ref given but
			// LocatorService not wired up) and per-item recovery is not
			// meaningful -- bubble up so the client sees the precise
			// status code instead of a per-entry error string.
			var cerr *connect.Error
			if errors.As(err, &cerr) {
				return nil, cerr
			}
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunctionErrorIdentifier(sidFunc),
				Reason:        err.Error(),
			})
			continue
		}
		resp.Created = append(resp.Created, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// createOneSidFunction owns the per-entry lifecycle of a SidFunctionCreate
// request. The defer-based rollback ensures any locator function we
// claimed at the top is returned to the pool on any downstream failure,
// removing the need for hand-mirrored rollback calls at each error path.
func (s *SidFunctionServer) createOneSidFunction(sidFunc *v1.SidFunction) error {
	if err := s.resolveLocatorRef(sidFunc); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			s.rollbackLocatorRef(sidFunc)
		}
	}()

	entry, aux, err := s.protoToEntry(sidFunc)
	if err != nil {
		return err
	}

	// Proxy SIDs bind their return circuit before the SID goes live so the
	// draft's one-proxy-per-IFACE-IN rule is enforced atomically
	// (CreateServiceIngress uses a no-exist update). The defer unbinds it
	// again when any later step fails.
	if isProxyAction(v1.Srv6LocalAction(entry.Action)) {
		ingress, err := s.buildServiceIngress(sidFunc)
		if err != nil {
			return err
		}
		ifaceIn := sidFunc.GetIfaceIn()
		vlanIn := uint16(sidFunc.GetVlanIn())
		prev, err := s.mapOps.CreateServiceIngress(ifaceIn, vlanIn, ingress)
		if err != nil {
			return err
		}
		defer func() {
			if committed {
				return
			}
			// Fresh bind: unbind. Same-SID re-bind: restore the previous
			// binding instead of leaving the circuit half-updated.
			if prev == nil {
				_ = s.mapOps.DeleteServiceIngress(ifaceIn, vlanIn)
			} else {
				_ = s.mapOps.RestoreServiceIngress(ifaceIn, vlanIn, prev)
			}
		}()
	}

	// plugin_aux_index path: aux already owned by the PluginAux RPC
	// lifecycle. CreateSidFunctionWithAuxIndex verifies the owner tag
	// atomically with the bind so a racing Free cannot reassign the idx.
	// SID functions live in the endpoint LPM map, so the owner tag is
	// always derived against MapTypeEndpoint. Headend plugins (if they
	// gain a separate plugin_aux_index path in the future) will need
	// their own bind helper with a different map_type.
	if sidFunc.PluginAuxIndex != 0 {
		owner := bpf.AuxOwnerPluginTag(bpf.MapTypeEndpoint, uint32(sidFunc.Action))
		if err := s.mapOps.CreateSidFunctionWithAuxIndex(sidFunc.TriggerPrefix, entry, owner, bpf.OwnerRPC); err != nil {
			return err
		}
	} else {
		if err := s.mapOps.CreateSidFunction(sidFunc.TriggerPrefix, entry, aux, bpf.OwnerRPC); err != nil {
			return err
		}
	}
	committed = true
	return nil
}

// resolveLocatorRef materializes a SID prefix from sidFunc.LocatorRef.
// When the request did not include a locator_ref the function still
// validates that trigger_prefix is set; an entirely empty SidFunction
// is rejected here so the missing-prefix error is reported with locator
// context.
//
// Returning a connect.Error signals a server-config problem the caller
// should bubble up as the RPC status code (FailedPrecondition for an
// unwired LocatorService); plain errors are per-entry validation
// failures.
func (s *SidFunctionServer) resolveLocatorRef(sidFunc *v1.SidFunction) error {
	ref := sidFunc.GetLocatorRef()
	if ref == nil {
		if sidFunc.GetTriggerPrefix() == "" {
			return fmt.Errorf("either trigger_prefix or locator_ref must be set")
		}
		return nil
	}
	if s.locatorMgr == nil {
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("locator_ref requires LocatorService to be wired up"))
	}
	if sidFunc.GetTriggerPrefix() != "" {
		return fmt.Errorf("locator_ref and trigger_prefix are mutually exclusive")
	}
	var requested *uint32
	if ref.Function != nil {
		v := ref.GetFunction()
		requested = &v
	}
	sid, _, err := s.locatorMgr.AllocateSID(ref.GetName(), requested)
	if err != nil {
		return fmt.Errorf("locator %q: %w", ref.GetName(), err)
	}
	// 128-bit SID materializes as a /128 trigger_prefix so the rest of
	// the pipeline (sid_function_map LPM key build, audit log, etc.)
	// works without further locator awareness.
	sidFunc.TriggerPrefix = sid.String() + "/128"
	return nil
}

// rollbackLocatorRef returns the function value to the locator pool when
// a subsequent step (validation, map write) failed after allocation.
// Safe to call when no locator_ref was used -- becomes a no-op via
// Manager.ReleaseSID's unknown-sid short-circuit.
func (s *SidFunctionServer) rollbackLocatorRef(sidFunc *v1.SidFunction) {
	if s.locatorMgr == nil || sidFunc.GetLocatorRef() == nil {
		return
	}
	sid, err := parseLocatorSID(sidFunc.GetTriggerPrefix())
	if err != nil {
		return
	}
	s.locatorMgr.ReleaseSID(sid)
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
		// Capture the proxy return circuit before the SID (and its aux)
		// disappears; unbind it only after the delete succeeds.
		circuitIf, circuitVlan, hasCircuit := s.captureProxyCircuit(prefix)
		if err := s.mapOps.DeleteSidFunction(prefix, bpf.OwnerRPC); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: prefix,
				Reason:        err.Error(),
			})
			continue
		}
		// Locator-minted SIDs return their function value to the pool.
		// Bindings for direct trigger_prefix SIDs simply miss the lookup
		// (Manager.ReleaseSID is a no-op for unknown sids).
		if s.locatorMgr != nil {
			if sid, err := parseLocatorSID(prefix); err == nil {
				s.locatorMgr.ReleaseSID(sid)
			}
		}
		// End.B6 policy is cleaned up automatically with aux entry
		if hasCircuit {
			_ = s.mapOps.DeleteServiceIngress(circuitIf, circuitVlan)
		}
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

// SidFunctionFlush removes every SID function entry and releases aux.
func (s *SidFunctionServer) SidFunctionFlush(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionFlushRequest],
) (*connect.Response[v1.SidFunctionFlushResponse], error) {
	// Collect proxy return circuits before the SIDs (and their aux
	// entries) are gone, then unbind them after the flush.
	type circuit struct {
		ifaceIn uint32
		vlanIn  uint16
	}
	var circuits []circuit
	if entries, err := s.mapOps.ListSidFunctions(); err == nil {
		for prefix := range entries {
			if ifaceIn, vlanIn, ok := s.captureProxyCircuit(prefix); ok {
				circuits = append(circuits, circuit{ifaceIn, vlanIn})
			}
		}
	}

	count, err := s.mapOps.FlushSidFunctions(bpf.OwnerRPC)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	for _, c := range circuits {
		_ = s.mapOps.DeleteServiceIngress(c.ifaceIn, c.vlanIn)
	}
	return connect.NewResponse(&v1.SidFunctionFlushResponse{DeletedCount: count}), nil
}

// protoToEntry converts a protobuf SidFunction to a BPF generic entry + optional aux entry
func (s *SidFunctionServer) protoToEntry(sidFunc *v1.SidFunction) (*bpf.SidFunctionEntry, *bpf.SidAuxEntry, error) {
	// SidFunctionEntry.Action is uint8, so any value > 255 (or negative) would
	// be silently truncated and produce an entry whose stored action disagrees
	// with the action used to derive the plugin owner tag. Reject up front.
	if sidFunc.Action < 0 || sidFunc.Action > 255 {
		return nil, nil, fmt.Errorf("action %d out of uint8 range [0, 255]", sidFunc.Action)
	}
	entry := &bpf.SidFunctionEntry{
		Action: uint8(sidFunc.Action),
		Flavor: uint8(sidFunc.Flavor),
	}

	// 3-way exclusive: plugin_aux_raw, plugin_aux_json, plugin_aux_index
	// cannot appear together on the same SidFunction.
	exclusives := 0
	if len(sidFunc.PluginAuxRaw) > 0 {
		exclusives++
	}
	if sidFunc.PluginAuxJson != "" {
		exclusives++
	}
	if sidFunc.PluginAuxIndex != 0 {
		exclusives++
	}
	if exclusives > 1 {
		return nil, nil, fmt.Errorf("plugin_aux_raw / plugin_aux_json / plugin_aux_index are mutually exclusive")
	}

	// plugin_aux_index: the aux slot is already populated by PluginAuxAlloc.
	// Wire entry.AuxIndex; ownership verification happens atomically inside
	// CreateSidFunctionWithAuxIndex so a racing PluginAuxFree cannot reassign
	// the index between check and bind.
	if sidFunc.PluginAuxIndex != 0 {
		action := uint32(sidFunc.Action)
		if action < bpf.EndpointPluginBase || action >= bpf.EndpointProgMax {
			return nil, nil, fmt.Errorf("plugin_aux_index requires action in [%d, %d) (endpoint plugin range), got %d",
				bpf.EndpointPluginBase, bpf.EndpointProgMax, action)
		}
		if sidFunc.PluginAuxIndex > 0xFFFF {
			return nil, nil, fmt.Errorf("plugin_aux_index %d exceeds uint16 range", sidFunc.PluginAuxIndex)
		}
		entry.AuxIndex = uint16(sidFunc.PluginAuxIndex)
		return entry, nil, nil
	}

	// Resolve vrf_name → vrf_ifindex for End.T/DT4/DT6/DT46. The resolved
	// ifindex is stored in the l3vrf aux variant below.
	var vrfIfindex uint32
	if sidFunc.VrfName != "" {
		idx, err := resolveIfindex(sidFunc.VrfName)
		if err != nil {
			return nil, nil, fmt.Errorf("vrf %q: %w", sidFunc.VrfName, err)
		}
		vrfIfindex = idx
	}

	// Build aux entry based on action type
	var aux *bpf.SidAuxEntry
	action := v1.Srv6LocalAction(sidFunc.Action)

	switch action {
	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_T,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT46:
		if vrfIfindex != 0 {
			aux = bpf.NewSidAuxL3Vrf(vrfIfindex)
		}

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

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M:
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
		// Exactly one source of the GTP-U outer IPv4 source: the static
		// gtp_v4_src_addr, or extraction from the outer IPv6 SA at
		// gtp_v4_src_position (RFC 9433 §6.6). Presence-checked (not zero-
		// checked) so position 0 stays expressible.
		hasSrcPos := sidFunc.GtpV4SrcPosition != nil
		switch {
		case sidFunc.GtpV4SrcAddr == "" && !hasSrcPos:
			return nil, nil, fmt.Errorf("END_M_GTP4_E requires gtp_v4_src_addr or gtp_v4_src_position")
		case sidFunc.GtpV4SrcAddr != "" && hasSrcPos:
			return nil, nil, fmt.Errorf("gtp_v4_src_addr and gtp_v4_src_position are mutually exclusive")
		}
		if hasSrcPos {
			pos := sidFunc.GetGtpV4SrcPosition()
			// 96 leaves exactly 32 bits of the outer IPv6 SA for the IPv4.
			if pos > 96 {
				return nil, nil, fmt.Errorf("gtp_v4_src_position %d out of range (0..96)", pos)
			}
			aux = bpf.NewSidAuxGtp4e(uint8(sidFunc.ArgsOffset), [4]uint8{}, true, uint8(pos))
		} else {
			gtpV4Src, err := bpf.ParseIPv4Optional(sidFunc.GtpV4SrcAddr)
			if err != nil {
				return nil, nil, err
			}
			aux = bpf.NewSidAuxGtp4e(uint8(sidFunc.ArgsOffset), gtpV4Src, false, 0)
		}

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

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM:
		svc, err := s.buildServiceAux(sidFunc)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxService(svc)

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN:
		// These land per-behavior on top of the shared return-path base.
		// Until a behavior's forward/return programs are registered,
		// accepting the SID would install a silent no-op (empty
		// tail-call slot), so reject explicitly.
		return nil, nil, fmt.Errorf("action %s is not implemented yet", action)
	}

	// Plugin-defined auxiliary payload. Only populated for plugin actions
	// (action value >= EndpointPluginBase) that have no built-in aux variant
	// above; the built-in variants take precedence so a caller cannot shadow
	// an End.X nexthop with arbitrary bytes. The 3-way mutex check above
	// already rejected any combination of raw / json / index, so at this
	// point at most one of hasRaw / hasJSON is set.
	hasRaw := len(sidFunc.PluginAuxRaw) > 0
	hasJSON := sidFunc.PluginAuxJson != ""
	if aux == nil && hasRaw {
		if len(sidFunc.PluginAuxRaw) > bpf.SidAuxPluginRawMax {
			return nil, nil, fmt.Errorf(
				"plugin_aux_raw length %d exceeds maximum %d",
				len(sidFunc.PluginAuxRaw), bpf.SidAuxPluginRawMax,
			)
		}
		aux = bpf.NewSidAuxPluginRaw(sidFunc.PluginAuxRaw)
	}
	if aux == nil && hasJSON {
		raw, err := s.encodePluginAuxJSON(sidFunc)
		if err != nil {
			return nil, nil, err
		}
		aux = bpf.NewSidAuxPluginRaw(raw)
	}

	return entry, aux, nil
}

// isProxyAction reports whether the action is a service-programming proxy
// that owns a return circuit in service_ingress_map.
func isProxyAction(action v1.Srv6LocalAction) bool {
	switch action {
	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
		v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM:
		return true
	default:
		return false
	}
}

// svcInnerBit maps the proto INNER-TYPE to the dataplane SVC_INNER_* bit.
func svcInnerBit(t v1.Srv6ProxyInnerType) (uint8, error) {
	switch t {
	case v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4:
		return bpf.SvcInnerIPv4, nil
	case v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV6:
		return bpf.SvcInnerIPv6, nil
	case v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_ETHERNET:
		return bpf.SvcInnerEthernet, nil
	default:
		return 0, fmt.Errorf("proxy actions require inner_type (IPV4 / IPV6 / ETHERNET)")
	}
}

// buildServiceAux validates the proxy forward-direction config and builds
// the service aux variant. The IFACE-OUT source MAC is resolved here (from
// the oif device) so the data plane never needs neighbour state in static
// MAC mode.
func (s *SidFunctionServer) buildServiceAux(sidFunc *v1.SidFunction) (*bpf.SidAuxService, error) {
	if sidFunc.Oif == 0 {
		return nil, fmt.Errorf("proxy actions require oif (IFACE-OUT ifindex)")
	}
	if sidFunc.GetIfaceIn() == 0 {
		return nil, fmt.Errorf("proxy actions require iface_in (return circuit ifindex)")
	}
	if sidFunc.GetVlanIn() > 4095 {
		return nil, fmt.Errorf("vlan_in %d out of range (0..4095)", sidFunc.GetVlanIn())
	}
	innerBit, err := svcInnerBit(sidFunc.InnerType)
	if err != nil {
		return nil, err
	}

	// End.AM specifics, checked before the MAC resolution below so the
	// operator sees the behavioral error, not an interface lookup one.
	// The masqueraded DA names the chain's final destination, so the FIB
	// fallback would route straight past the service — the static MAC is
	// the only sound delivery. And the frames on an AM circuit are the SR
	// packets themselves (IPv6 with the SRH still attached), whatever the
	// chain's payload is.
	if v1.Srv6LocalAction(sidFunc.Action) == v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM {
		if sidFunc.GetServiceMac() == "" {
			return nil, fmt.Errorf("END_AM requires service_mac (the masqueraded destination cannot be FIB-resolved towards the service)")
		}
		if innerBit != bpf.SvcInnerIPv6 {
			return nil, fmt.Errorf("END_AM requires inner_type IPV6 (the service sees the SR packet itself)")
		}
	}

	if sidFunc.GetHopLimitMargin() > 255 {
		return nil, fmt.Errorf("hop_limit_margin %d out of range (0..255)", sidFunc.GetHopLimitMargin())
	}

	svc := &bpf.SidAuxService{
		IfaceOut:       sidFunc.Oif,
		IfaceIn:        sidFunc.GetIfaceIn(),
		VlanIn:         uint16(sidFunc.GetVlanIn()),
		InnerType:      innerBit,
		HopLimitMargin: uint8(sidFunc.GetHopLimitMargin()),
	}

	if mac := sidFunc.GetServiceMac(); mac != "" {
		if innerBit == bpf.SvcInnerEthernet {
			return nil, fmt.Errorf("service_mac is only valid for L3 inner types (the L2 frame is forwarded untouched)")
		}
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("invalid service_mac %q", mac)
		}
		oifDev, err := net.InterfaceByIndex(int(sidFunc.Oif))
		if err != nil {
			return nil, fmt.Errorf("resolve oif %d: %w", sidFunc.Oif, err)
		}
		if len(oifDev.HardwareAddr) != 6 {
			return nil, fmt.Errorf("oif %d (%s) has no usable MAC for static rewrite", sidFunc.Oif, oifDev.Name)
		}
		svc.Flags |= bpf.SvcAuxFStaticMac
		copy(svc.Dmac[:], hw)
		copy(svc.Smac[:], oifDev.HardwareAddr)
	}

	return svc, nil
}

// buildServiceIngress builds the return-circuit binding for a proxy SID.
// End.AS embeds the static CACHE (outer source + segment list) so the
// return path re-encapsulates in one lookup; End.AD learns it dynamically
// and leaves the embedded encap zeroed.
func (s *SidFunctionServer) buildServiceIngress(sidFunc *v1.SidFunction) (*bpf.ServiceIngressEntry, error) {
	innerBit, err := svcInnerBit(sidFunc.InnerType)
	if err != nil {
		return nil, err
	}
	sid, err := parseLocatorSID(sidFunc.TriggerPrefix)
	if err != nil {
		return nil, fmt.Errorf("proxy trigger_prefix must be a /128 SID: %w", err)
	}

	entry := &bpf.ServiceIngressEntry{
		InnerTypeMask: innerBit,
		Sid:           sid.As16(),
	}

	switch v1.Srv6LocalAction(sidFunc.Action) {
	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD:
		if len(sidFunc.Segments) > 0 || sidFunc.SrcAddr != "" {
			return nil, fmt.Errorf("END_AD learns the encapsulation dynamically; segments / src_addr are not accepted")
		}
		entry.Behavior = bpf.SvcRetAD
		return entry, nil

	case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM:
		if len(sidFunc.Segments) > 0 || sidFunc.SrcAddr != "" {
			return nil, fmt.Errorf("END_AM carries the chain state inside the packet; segments / src_addr are not accepted")
		}
		entry.Behavior = bpf.SvcRetAM
		return entry, nil

	default: // END_AS
		if len(sidFunc.Segments) == 0 {
			return nil, fmt.Errorf("END_AS requires segments (the static CACHE the return path re-encapsulates with)")
		}
		if sidFunc.SrcAddr == "" {
			return nil, fmt.Errorf("END_AS requires src_addr (outer IPv6 source of the re-encapsulation)")
		}
		srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
		if err != nil {
			return nil, err
		}
		segments, numSegments, err := bpf.ParseSegments(sidFunc.Segments)
		if err != nil {
			return nil, err
		}
		entry.Behavior = bpf.SvcRetAS
		entry.Encap = bpf.HeadendEntry{
			Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: numSegments,
			SrcAddr:     srcAddr,
			Segments:    segments,
		}
		return entry, nil
	}
}

// captureProxyCircuit returns the return circuit bound to prefix when it
// names a proxy SID, so delete/flush can clean service_ingress_map after
// the SID entry goes away.
func (s *SidFunctionServer) captureProxyCircuit(prefix string) (ifaceIn uint32, vlanIn uint16, ok bool) {
	entry, err := s.mapOps.GetSidFunction(prefix)
	if err != nil || entry == nil || entry.AuxIndex == 0 {
		return 0, 0, false
	}
	if !isProxyAction(v1.Srv6LocalAction(entry.Action)) {
		return 0, 0, false
	}
	aux, err := s.mapOps.GetSidAux(uint32(entry.AuxIndex))
	if err != nil || aux == nil {
		return 0, 0, false
	}
	svc := bpf.SidAuxServiceData(aux)
	return svc.IfaceIn, svc.VlanIn, svc.IfaceIn != 0
}

// encodePluginAuxJSON resolves the plugin's BTF aux type and asks the
// encoder to turn the caller's JSON into the byte layout the plugin
// expects. The result is bounded by SidAuxPluginRawMax so it always fits
// inside sid_aux_entry.plugin_raw.
func (s *SidFunctionServer) encodePluginAuxJSON(sidFunc *v1.SidFunction) ([]byte, error) {
	if s.pluginAux == nil {
		return nil, fmt.Errorf("plugin_aux_json requires PluginService wiring")
	}
	action := uint32(sidFunc.Action)
	if action < bpf.EndpointPluginBase {
		return nil, fmt.Errorf("plugin_aux_json only valid for plugin actions (>= %d), got %d",
			bpf.EndpointPluginBase, action)
	}
	auxType := s.pluginAux.AuxType(bpf.MapTypeEndpoint, action)
	if auxType == nil {
		return nil, fmt.Errorf("plugin at slot %d does not declare <program>_aux BTF; register a plugin that uses VINBERO_PLUGIN_AUX_TYPE", action)
	}
	if auxType.Size > bpf.SidAuxPluginRawMax {
		return nil, fmt.Errorf("plugin aux struct is %d bytes, exceeds maximum %d",
			auxType.Size, bpf.SidAuxPluginRawMax)
	}
	dec := json.NewDecoder(strings.NewReader(sidFunc.PluginAuxJson))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("plugin_aux_json is not a valid JSON object: %w", err)
	}
	return EncodePluginAux(auxType, payload)
}

// entryToProto converts a BPF map entry to a protobuf SidFunction
func (s *SidFunctionServer) entryToProto(prefix string, entry *bpf.SidFunctionEntry) *v1.SidFunction {
	sf := &v1.SidFunction{
		Action:        v1.Srv6LocalAction(entry.Action),
		TriggerPrefix: prefix,
		Flavor:        v1.Srv6LocalFlavor(entry.Flavor),
	}

	// For plugin actions, surface the aux_index so the caller can tell
	// which PluginAuxAlloc-allocated slot is wired to this SID.
	if entry.AuxIndex != 0 && uint32(entry.Action) >= bpf.EndpointPluginBase {
		sf.PluginAuxIndex = uint32(entry.AuxIndex)
	}

	// Read aux data if present
	if entry.AuxIndex != 0 {
		aux, err := s.mapOps.GetSidAux(uint32(entry.AuxIndex))
		if err == nil && aux != nil {
			action := v1.Srv6LocalAction(entry.Action)
			switch action {
			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_T,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT46:
				sf.VrfName = ifindexToName(bpf.SidAuxL3VrfData(aux))

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X:
				sf.Nexthop = bpf.FormatIPv6(aux.Nexthop.Nexthop)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2:
				sf.Oif = binary.NativeEndian.Uint32(aux.Nexthop.Nexthop[:4])

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2V:
				sf.TableId = uint32(bpf.SidAuxDx2vData(aux))

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M:
				bdID, bridgeIfindex := bpf.SidAuxL2Data(aux)
				sf.BdId = uint32(bdID)
				sf.BridgeName = ifindexToName(bridgeIfindex)

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E:
				argsOffset, gtpV4Src, fromOuter, srcPos := bpf.SidAuxGtp4eData(aux)
				sf.ArgsOffset = uint32(argsOffset)
				if fromOuter {
					pos := uint32(srcPos)
					sf.GtpV4SrcPosition = &pos
				} else {
					sf.GtpV4SrcAddr = bpf.FormatIPv4Optional(gtpV4Src)
				}

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

			case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD,
				v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AM:
				svc := bpf.SidAuxServiceData(aux)
				sf.Oif = svc.IfaceOut
				ifaceIn := svc.IfaceIn
				sf.IfaceIn = &ifaceIn
				if svc.VlanIn != 0 {
					vlanIn := uint32(svc.VlanIn)
					sf.VlanIn = &vlanIn
				}
				switch svc.InnerType {
				case bpf.SvcInnerIPv4:
					sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV4
				case bpf.SvcInnerIPv6:
					sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_IPV6
				case bpf.SvcInnerEthernet:
					sf.InnerType = v1.Srv6ProxyInnerType_SRV6_PROXY_INNER_TYPE_ETHERNET
				}
				if svc.Flags&bpf.SvcAuxFStaticMac != 0 {
					mac := net.HardwareAddr(svc.Dmac[:]).String()
					sf.ServiceMac = &mac
				}
				switch action {
				case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AD:
					if svc.HopLimitMargin != 0 {
						margin := uint32(svc.HopLimitMargin)
						sf.HopLimitMargin = &margin
					}
				case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AS:
					// End.AS only: the static CACHE lives in the return-
					// circuit binding (AD learns it per-chain, AM carries
					// the state inside the packet — nothing to show).
					if ing, err := s.mapOps.GetServiceIngress(svc.IfaceIn, svc.VlanIn); err == nil {
						sf.Segments = bpf.FormatSegments(ing.Encap.Segments, ing.Encap.NumSegments)
						sf.SrcAddr = bpf.FormatIPv6(ing.Encap.SrcAddr)
					}
				}
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
