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
// the daemon's configured encap source, used when the plugin leaves the
// source empty.
func DecodeHeadendEntry(in *v1.PluginHeadendEntry, defaultSrc netip.Addr) (string, *bpf.HeadendEntry, error) {
	if in == nil {
		return "", nil, fmt.Errorf("nil headend entry")
	}
	if in.GetTriggerPrefix() == "" {
		return "", nil, fmt.Errorf("headend entry has no trigger prefix")
	}
	if _, err := netip.ParsePrefix(in.GetTriggerPrefix()); err != nil {
		return "", nil, fmt.Errorf("trigger prefix %q: %w", in.GetTriggerPrefix(), err)
	}

	segments := in.GetSegments()
	if len(segments) == 0 {
		return "", nil, fmt.Errorf("headend entry for %q declares no segments", in.GetTriggerPrefix())
	}
	if len(segments) > bpf.MaxSegments {
		return "", nil, fmt.Errorf("headend entry for %q declares %d segments, limit %d",
			in.GetTriggerPrefix(), len(segments), bpf.MaxSegments)
	}
	if in.GetMode() > 0xFF {
		return "", nil, fmt.Errorf("headend entry for %q: mode %d does not fit a byte",
			in.GetTriggerPrefix(), in.GetMode())
	}

	entry := &bpf.HeadendEntry{
		Mode:        uint8(in.GetMode()),
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
	if src.IsValid() {
		if !src.Is6() {
			return "", nil, fmt.Errorf("source address of %q is not IPv6", in.GetTriggerPrefix())
		}
		entry.SrcAddr = src.As16()
	}
	return in.GetTriggerPrefix(), entry, nil
}
