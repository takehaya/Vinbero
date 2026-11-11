package cni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// setupL2 attaches a pod to a pre-declared EVPN bridge domain. The pod side
// is brought up last, once the host veth is a bridge member, an AC of the
// tenant and on the data plane, so a pod frame is never classified as global
// (vrf 0) or forwarded before the bridge domain owns it.
func (p *Plugin) setupL2(ctx context.Context, daemon Daemon, store *Store, conf *NetConf, args *skel.CmdArgs, a *Attachment, tmpIf string) (*current.Result, error) {
	// The bridge domain is declared in the node's vinberod config. Fail the
	// ADD if the facet or binding is not there: the plugin never creates one.
	if err := daemon.EnsureBridgeDomain(ctx, conf.VRF, conf.Bridge, conf.BdID); err != nil {
		return nil, err
	}
	if conf.WantsBinding() {
		if err := daemon.EnsureBinding(ctx, Binding{
			VRF: conf.VRF, RD: conf.RD, RTs: conf.RTs, Locator: conf.Locator, MaxPrefixes: conf.MaxPrefixes,
		}); err != nil {
			return nil, err
		}
	}
	// Close the bridge's path into the host stack before any pod port joins
	// it (idempotent; the bridge may already carry other pods).
	if err := p.Net.HardenBridge(conf.Bridge); err != nil {
		return nil, err
	}

	veth, err := p.Net.CreateVeth(args.Netns, args.IfName, a.HostVeth, tmpIf, conf.MTU)
	if err != nil {
		return nil, err
	}
	a.PodMAC, a.HostMAC = veth.PodMAC.String(), veth.HostMAC.String()
	if err := store.Put(*a); err != nil {
		return nil, fmt.Errorf("record attachment: %w", err)
	}

	if err := daemon.AddBridgeMember(ctx, conf.VRF, a.HostVeth); err != nil {
		return nil, err
	}
	if err := p.Net.LinkUp(a.HostVeth); err != nil {
		return nil, err
	}
	// AC before the circuit and the device, so the front door classifies
	// the port to the tenant before any frame can arrive.
	if err := daemon.AddAC(ctx, conf.VRF, a.HostVeth); err != nil {
		return nil, err
	}
	if err := daemon.CreateL2Circuit(ctx, a.HostVeth, conf.BdID); err != nil {
		return nil, err
	}
	if err := daemon.AttachDevice(ctx, a.HostVeth, conf.DeviceMode); err != nil {
		return nil, err
	}
	// Pre-advertise the pod's MAC as an RT2, so a silent pod (one that never
	// sends) is still reachable from the other nodes.
	if err := p.Net.AddStaticFDB(a.HostVeth, veth.PodMAC); err != nil {
		return nil, err
	}
	// Last: bring the pod side up with its on-link address.
	if err := p.Net.ConfigurePodL2(PodL2Config{Netns: args.Netns, IfName: args.IfName, Address: a.Address}); err != nil {
		return nil, err
	}

	podIdx := 1
	return &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			{Name: a.HostVeth, Mac: a.HostMAC},
			{Name: args.IfName, Mac: a.PodMAC, Sandbox: args.Netns},
		},
		IPs: []*current.IPConfig{{
			Interface: &podIdx,
			Address:   *prefixToIPNet(a.Address),
		}},
		DNS: conf.DNS,
	}, nil
}

// teardownL2 undoes an L2 attachment in reverse. Forwarding is stopped before
// the port is released: the static FDB, the circuit and the device go first,
// then the AC and the bridge membership. The veth and the lease are freed only
// once the AC and the membership are gone, so a retried DEL finishes them.
func (p *Plugin) teardownL2(ctx context.Context, daemon Daemon, store *Store, conf *NetConf, args *skel.CmdArgs, a Attachment) error {
	var errs []error
	if a.PodMAC != "" {
		if mac, err := net.ParseMAC(a.PodMAC); err == nil {
			errs = append(errs, p.Net.DelStaticFDB(a.HostVeth, mac))
		}
	}
	errs = append(errs, daemon.DeleteL2Circuit(ctx, a.HostVeth))
	errs = append(errs, daemon.DetachDevice(ctx, a.HostVeth))
	acErr := daemon.RemoveAC(ctx, a.VRF, a.HostVeth)
	errs = append(errs, acErr)
	memErr := daemon.RemoveBridgeMember(ctx, a.VRF, a.HostVeth)
	errs = append(errs, memErr)
	if acErr == nil && memErr == nil {
		errs = append(errs,
			p.Net.DeleteVeth(a.HostVeth),
			p.IPAM.Del(ctx, conf.IPAM.Type, args.StdinData),
		)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return store.Delete(a.ContainerID, a.IfName)
}

// checkL2 verifies an L2 attachment against the record, netlink and the daemon.
func (p *Plugin) checkL2(ctx context.Context, daemon Daemon, conf *NetConf, args *skel.CmdArgs, a Attachment) error {
	if a.VRF != conf.VRF || a.Bridge != conf.Bridge || a.BdID != conf.BdID {
		return fmt.Errorf("attachment is in vrf %s bridge %s bd %d, the network configuration says vrf %s bridge %s bd %d",
			a.VRF, a.Bridge, a.BdID, conf.VRF, conf.Bridge, conf.BdID)
	}
	if err := daemon.EnsureBridgeDomain(ctx, conf.VRF, conf.Bridge, conf.BdID); err != nil {
		return err
	}
	if err := p.IPAM.Check(ctx, conf.IPAM.Type, args.StdinData); err != nil && !checkNotImplemented(err) {
		return fmt.Errorf("ipam %s: %w", conf.IPAM.Type, err)
	}
	if err := p.Net.CheckPodL2(PodL2Config{Netns: args.Netns, IfName: args.IfName, Address: a.Address}); err != nil {
		return err
	}
	if err := p.Net.CheckBridgeHardening(conf.Bridge); err != nil {
		return err
	}
	if err := p.Net.CheckL2Host(a.HostVeth, conf.Bridge); err != nil {
		return err
	}
	present, err := daemon.L2CircuitPresent(ctx, a.HostVeth, conf.BdID)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("host veth %s has no bridge-domain circuit for bd %d", a.HostVeth, conf.BdID)
	}
	attached, err := daemon.DeviceAttached(ctx, a.HostVeth)
	if err != nil {
		return err
	}
	if !attached {
		return fmt.Errorf("host veth %s is not attached to the data plane", a.HostVeth)
	}
	return nil
}

// podAddressL2 picks the single IPv4 address IPAM handed out as the pod's
// on-link prefix. L2 mode carries only the directly-connected subnet, so a
// gateway or external route from IPAM is an error rather than silently
// dropped; IPv6 IPAM is out of scope.
func podAddressL2(r *current.Result) (netip.Prefix, error) {
	var addr netip.Prefix
	for _, ipc := range r.IPs {
		ip, ok := netip.AddrFromSlice(ipc.Address.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() {
			return netip.Prefix{}, fmt.Errorf("ipam returned %s: only IPv4 is supported", ipc.Address.String())
		}
		if addr.IsValid() {
			return netip.Prefix{}, fmt.Errorf("ipam returned more than one IPv4 address")
		}
		ones, _ := ipc.Address.Mask.Size()
		addr = netip.PrefixFrom(ip, ones)
	}
	if !addr.IsValid() {
		return netip.Prefix{}, fmt.Errorf("ipam returned no IPv4 address")
	}
	for _, rt := range r.Routes {
		dst, ok := netip.AddrFromSlice(rt.Dst.IP)
		if !ok {
			continue
		}
		ones, _ := rt.Dst.Mask.Size()
		pfx := netip.PrefixFrom(dst.Unmap(), ones).Masked()
		if pfx.Addr().Is4() && pfx != addr.Masked() {
			return netip.Prefix{}, fmt.Errorf("ipam route %s: an L2 bridge domain carries only its on-link subnet %s; a gateway or external route is out of scope", pfx, addr.Masked())
		}
	}
	return addr, nil
}
