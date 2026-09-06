package cplane

import (
	"fmt"
	"net/netip"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// EncodeRouteEvent renders a received BGP route for delivery to a plugin.
//
// The plugin sees a flattened view rather than Vinbero's tagged union: it
// reads the fields its families define and ignores the rest, which keeps a
// plugin from having to know how the daemon happens to model a route.
func EncodeRouteEvent(ev bgp.RouteEvent) *v1.PluginRoute {
	out := &v1.PluginRoute{
		Family:           string(ev.Family),
		IsWithdraw:       ev.IsWithdraw,
		PathId:           ev.Source.PathID,
		EndpointBehavior: uint32(ev.EndpointBehavior),
	}
	if ev.Source.Peer.IsValid() {
		out.Peer = ev.Source.Peer.String()
	}
	for _, a := range ev.UnknownAttrs {
		out.UnknownAttrs = append(out.UnknownAttrs, &v1.PluginUnknownAttribute{
			Type:  uint32(a.Type),
			Flags: uint32(a.Flags),
			Value: append([]byte(nil), a.Value...),
		})
	}
	switch {
	case ev.VPN != nil:
		out.Rd = ev.VPN.RD
		out.Prefix = ev.VPN.Prefix
		out.Srv6Sid = ev.VPN.SRv6SID
		out.NextHop = ev.VPN.NextHop
		out.RouteTargets = append(out.RouteTargets, ev.VPN.RTs...)
		out.Color = ev.VPN.Color
	case ev.Unicast != nil:
		out.Prefix = ev.Unicast.Prefix
		out.NextHop = ev.Unicast.NextHop
	case ev.EVPN != nil:
		e := ev.EVPN
		out.Rd = e.RD
		out.Srv6Sid = e.SRv6SID
		out.NextHop = e.NextHop
		out.RouteTargets = append(out.RouteTargets, e.RTs...)
		out.Mac = e.MAC
		out.IpAddr = e.IPAddr
		out.EthernetTag = e.EthernetTag
		esi := e.ESI
		out.Esi = append([]byte(nil), esi[:]...)
	case ev.MUP != nil:
		out.Rd = ev.MUP.RD
		out.Prefix = ev.MUP.Prefix
		out.RouteTargets = append(out.RouteTargets, ev.MUP.RTs...)
	case ev.SRPolicy != nil:
		out.Color = ev.SRPolicy.Color
		if ev.SRPolicy.Endpoint.IsValid() {
			out.Prefix = ev.SRPolicy.Endpoint.String()
		}
	}
	return out
}

// DecodeHeadendEntry converts a plugin's declared entry into the BPF entry
// the map holds.
//
// A plugin never sees the map layout: it declares segments and a source
// address, and the layout stays the host's business, so a change to the
// BPF struct does not break every plugin built against it. defaultSrc is
// the daemon's encap source, used when the plugin leaves the source empty.
//
// An entry with no usable source is refused rather than written with a
// zero one. A zero source produces packets that go nowhere, and a
// blackhole that reports success is far harder to diagnose than a
// declaration that was refused.
func DecodeHeadendEntry(in *v1.PluginHeadendEntry, af AddressFamily, defaultSrc netip.Addr) (string, *bpf.HeadendEntry, error) {
	if in == nil {
		return "", nil, fmt.Errorf("nil headend entry")
	}
	if in.GetTriggerPrefix() == "" {
		return "", nil, fmt.Errorf("headend entry has no trigger prefix")
	}
	pfx, err := netip.ParsePrefix(in.GetTriggerPrefix())
	if err != nil {
		return "", nil, fmt.Errorf("trigger prefix %q: %w", in.GetTriggerPrefix(), err)
	}
	// Normalized before it becomes a key. The map is an LPM trie and stores
	// the masked network, so a declaration spelled 10.0.0.7/24 is written
	// as 10.0.0.0/24 and read back that way. Leasing and diffing the
	// unmasked spelling would leave the lease under a key the map never
	// reports: the owner's own next declaration would not recognize the
	// entry it just wrote, prune it, write it again, and never release the
	// lease -- and a second owner spelling it differently would slip past
	// the lease the first one holds.
	//
	// The advertise path does the same thing for the same reason; this is
	// its counterpart.
	// The family has to match the map the transaction is for. The caller
	// picks the map from the transaction's kind, so a prefix of the other
	// family is an entry that cannot be written -- and the reconcile prunes
	// before it writes, so the owner's whole set in that family goes first
	// and the write then fails. It repeats identically on every
	// declaration, so nothing recovers it.
	if af == AFv4 && !pfx.Addr().Is4() {
		return "", nil, fmt.Errorf("trigger prefix %q is not IPv4, and this is a %s declaration",
			in.GetTriggerPrefix(), af)
	}
	if af == AFv6 && pfx.Addr().Is4() {
		return "", nil, fmt.Errorf("trigger prefix %q is not IPv6, and this is a %s declaration",
			in.GetTriggerPrefix(), af)
	}
	trigger := pfx.Masked().String()

	segments := in.GetSegments()
	if len(segments) == 0 {
		return "", nil, fmt.Errorf("headend entry for %q declares no segments", in.GetTriggerPrefix())
	}
	if len(segments) > bpf.MaxSegments {
		return "", nil, fmt.Errorf("headend entry for %q declares %d segments, limit %d",
			in.GetTriggerPrefix(), len(segments), bpf.MaxSegments)
	}
	// Mode 0 means "the ordinary encapsulation" to a plugin, which is not
	// the same number the data plane uses: 0 is UNSPECIFIED there, and an
	// entry carrying it is written but never acted on -- a blackhole that
	// looks installed. The plugin-facing default stays 0 because a plugin
	// pairing with its own data-plane half is the only one that should
	// have to name a mode at all.
	declared := in.GetMode()
	if declared == 0 {
		declared = uint32(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
	}
	if err := validateHeadendMode(declared, af); err != nil {
		return "", nil, fmt.Errorf("headend entry for %q: %w", in.GetTriggerPrefix(), err)
	}
	mode := uint8(declared)
	entry := &bpf.HeadendEntry{
		Mode:        mode,
		NumSegments: uint8(len(segments)),
	}
	for i, s := range segments {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", nil, fmt.Errorf("segment %d of %q: %w", i, in.GetTriggerPrefix(), err)
		}
		if !addr.Is6() {
			return "", nil, fmt.Errorf("segment %d of %q is not IPv6", i, in.GetTriggerPrefix())
		}
		entry.Segments[i] = addr.As16()
	}
	// The outer destination is the FIRST segment: that is the next hop the
	// encapsulated packet is sent to, and the rest of the list is what the
	// SRH carries for the hops after it. The data plane reads
	// segments[0] for the outer daddr and treats dst_addr as reserved, so
	// this mirrors what the built-in applier writes rather than inventing
	// a second convention for plugins.
	entry.DstAddr = entry.Segments[0]

	src := defaultSrc
	if in.GetSrcAddr() != "" {
		parsed, err := netip.ParseAddr(in.GetSrcAddr())
		if err != nil {
			return "", nil, fmt.Errorf("source address of %q: %w", in.GetTriggerPrefix(), err)
		}
		src = parsed
	}
	if !src.IsValid() {
		return "", nil, fmt.Errorf("headend entry for %q has no source address and the daemon has no encap source to lend it",
			in.GetTriggerPrefix())
	}
	if !src.Is6() {
		return "", nil, fmt.Errorf("source address of %q is not IPv6", in.GetTriggerPrefix())
	}
	entry.SrcAddr = src.As16()
	return trigger, entry, nil
}

// validateHeadendMode refuses a mode the data plane has nothing behind.
//
// The mode indexes the headend PROG_ARRAY, so a number outside what is
// there is an entry that looks installed and tail-calls into an empty
// slot: the packet is dropped and nothing says why. A plugin may name one
// of vinbero's own behaviors -- ordinary encapsulation is the common case
// -- or one of the slots reserved for plugins, where its own data-plane
// half lives. Anything else is a mistake worth refusing at the boundary.
func validateHeadendMode(mode uint32, af AddressFamily) error {
	if _, known := v1.Srv6HeadendBehavior_name[int32(mode)]; known &&
		mode != uint32(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_UNSPECIFIED) {
		return nil
	}
	mapType := bpf.MapTypeHeadendV4
	if af == AFv6 {
		mapType = bpf.MapTypeHeadendV6
	}
	if err := bpf.ValidatePluginSlot(mapType, mode); err != nil {
		return fmt.Errorf("mode %d is neither a behavior vinbero implements nor a headend plugin slot: %w",
			mode, err)
	}
	return nil
}
