package cni

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// podGateway is the next hop the pod routes through. It is never assigned
// to an interface: the pod reaches it through a permanent neighbour entry
// for the host veth's MAC, so no ARP is needed in either direction.
var podGateway = netip.MustParseAddr("169.254.1.1")

// Veth is the pair ADD creates.
type Veth struct {
	HostMAC net.HardwareAddr
	PodMAC  net.HardwareAddr
}

// PodConfig is the pod side of an attachment.
type PodConfig struct {
	Netns   string
	IfName  string
	Address netip.Addr     // configured as a /32
	Routes  []netip.Prefix // routed via podGateway
	GwMAC   net.HardwareAddr
}

// HostConfig is the host side of an attachment.
type HostConfig struct {
	Veth    string
	VRF     string
	TableID uint32
	PodIP   netip.Addr
	PodMAC  net.HardwareAddr
}

// Netops is the netlink work of an attachment.
type Netops interface {
	CreateVeth(netnsPath, podIf, hostIf, tmpIf string, mtu int) (Veth, error)
	ConfigurePod(p PodConfig) error
	// EnslaveHost puts the host veth into the VRF and brings it up.
	EnslaveHost(hostIf, vrf string) error
	// AddHostRoute installs the pod's /32 into the VRF table as a static
	// route (what vinberod advertises) and its permanent neighbour entry.
	AddHostRoute(h HostConfig) error
	// DelHostRoute removes them; missing ones succeed.
	DelHostRoute(h HostConfig) error
	// DeleteVeth removes the pair through its host end, which ADD names
	// after the attachment; without that end there is no pair of ours. A
	// missing pair succeeds.
	DeleteVeth(hostIf string) error
	CheckPod(p PodConfig) error
	CheckHost(h HostConfig) error
}

// kernelNetops implements Netops with netlink handles, one per namespace,
// so the calling thread never switches namespaces.
type kernelNetops struct{}

func openNetns(path string) (*netlink.Handle, func(), error) {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open netns %s: %w", path, err)
	}
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		_ = ns.Close()
		return nil, nil, fmt.Errorf("netlink in netns %s: %w", path, err)
	}
	return h, func() { h.Close(); _ = ns.Close() }, nil
}

func isNotFound(err error) bool {
	var lnf netlink.LinkNotFoundError
	return errors.As(err, &lnf)
}

func (kernelNetops) CreateVeth(netnsPath, podIf, hostIf, tmpIf string, mtu int) (Veth, error) {
	pod, closeNS, err := openNetns(netnsPath)
	if err != nil {
		return Veth{}, err
	}
	defer closeNS()
	if _, err := pod.LinkByName(podIf); err == nil {
		return Veth{}, fmt.Errorf("interface %s already exists in %s", podIf, netnsPath)
	}
	// Leftovers of an earlier attempt that died before its cleanup.
	for _, name := range []string{hostIf, tmpIf} {
		if l, err := netlink.LinkByName(name); err == nil {
			if err := netlink.LinkDel(l); err != nil {
				return Veth{}, fmt.Errorf("remove stale %s: %w", name, err)
			}
		}
	}
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostIf, MTU: mtu},
		PeerName:  tmpIf,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return Veth{}, fmt.Errorf("create veth %s: %w", hostIf, err)
	}
	peer, err := netlink.LinkByName(tmpIf)
	if err != nil {
		return Veth{}, fmt.Errorf("veth peer %s: %w", tmpIf, err)
	}
	ns, err := netns.GetFromPath(netnsPath)
	if err != nil {
		return Veth{}, err
	}
	defer func() { _ = ns.Close() }()
	if err := netlink.LinkSetNsFd(peer, int(ns)); err != nil {
		return Veth{}, fmt.Errorf("move %s into %s: %w", tmpIf, netnsPath, err)
	}
	podLink, err := pod.LinkByName(tmpIf)
	if err != nil {
		return Veth{}, err
	}
	if err := pod.LinkSetName(podLink, podIf); err != nil {
		return Veth{}, fmt.Errorf("rename %s to %s: %w", tmpIf, podIf, err)
	}
	if err := pod.LinkSetMTU(podLink, mtu); err != nil {
		return Veth{}, err
	}
	podLink, err = pod.LinkByName(podIf)
	if err != nil {
		return Veth{}, err
	}
	hostLink, err := netlink.LinkByName(hostIf)
	if err != nil {
		return Veth{}, err
	}
	return Veth{HostMAC: hostLink.Attrs().HardwareAddr, PodMAC: podLink.Attrs().HardwareAddr}, nil
}

func (kernelNetops) ConfigurePod(p PodConfig) error {
	pod, closeNS, err := openNetns(p.Netns)
	if err != nil {
		return err
	}
	defer closeNS()
	link, err := pod.LinkByName(p.IfName)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: prefixToIPNet(netip.PrefixFrom(p.Address, 32))}
	if err := pod.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("address %s on %s: %w", p.Address, p.IfName, err)
	}
	if err := pod.LinkSetUp(link); err != nil {
		return err
	}
	if err := pod.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           net.IP(podGateway.AsSlice()),
		HardwareAddr: p.GwMAC,
	}); err != nil {
		return fmt.Errorf("gateway neighbour on %s: %w", p.IfName, err)
	}
	for _, dst := range p.Routes {
		// Add, not replace: a prefix the primary network already routes
		// must fail the ADD instead of moving that traffic into the VRF.
		if err := pod.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       prefixToIPNet(dst),
			Gw:        net.IP(podGateway.AsSlice()),
			Flags:     int(netlink.FLAG_ONLINK),
		}); err != nil {
			return fmt.Errorf("route %s on %s: %w", dst, p.IfName, err)
		}
	}
	return nil
}

func (kernelNetops) EnslaveHost(hostIf, vrf string) error {
	host, err := netlink.LinkByName(hostIf)
	if err != nil {
		return err
	}
	dev, err := netlink.LinkByName(vrf)
	if err != nil {
		return fmt.Errorf("vrf %s: %w", vrf, err)
	}
	if host.Attrs().MasterIndex != dev.Attrs().Index {
		if err := netlink.LinkSetMaster(host, dev); err != nil {
			return fmt.Errorf("enslave %s to %s: %w", hostIf, vrf, err)
		}
	}
	return netlink.LinkSetUp(host)
}

func hostRoute(link netlink.Link, h HostConfig) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       prefixToIPNet(netip.PrefixFrom(h.PodIP, 32)),
		Table:     int(h.TableID),
		Protocol:  unix.RTPROT_STATIC,
		Scope:     netlink.SCOPE_LINK,
	}
}

func (kernelNetops) AddHostRoute(h HostConfig) error {
	link, err := netlink.LinkByName(h.Veth)
	if err != nil {
		return err
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           net.IP(h.PodIP.AsSlice()),
		HardwareAddr: h.PodMAC,
	}); err != nil {
		return fmt.Errorf("neighbour %s on %s: %w", h.PodIP, h.Veth, err)
	}
	if err := netlink.RouteReplace(hostRoute(link, h)); err != nil {
		return fmt.Errorf("route %s/32 table %d: %w", h.PodIP, h.TableID, err)
	}
	return nil
}

func (kernelNetops) DelHostRoute(h HostConfig) error {
	link, err := netlink.LinkByName(h.Veth)
	if isNotFound(err) {
		return nil // the kernel dropped both with the link
	}
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(hostRoute(link, h)); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("delete route %s/32 table %d: %w", h.PodIP, h.TableID, err)
	}
	err = netlink.NeighDel(&netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    unix.AF_INET,
		IP:        net.IP(h.PodIP.AsSlice()),
	})
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("delete neighbour %s: %w", h.PodIP, err)
	}
	return nil
}

func (kernelNetops) DeleteVeth(hostIf string) error {
	l, err := netlink.LinkByName(hostIf)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok := l.(*netlink.Veth); !ok {
		return nil // not the pair ADD created
	}
	if err := netlink.LinkDel(l); err != nil && !isNotFound(err) {
		return fmt.Errorf("delete %s: %w", hostIf, err)
	}
	return nil
}

func (kernelNetops) CheckPod(p PodConfig) error {
	pod, closeNS, err := openNetns(p.Netns)
	if err != nil {
		return err
	}
	defer closeNS()
	link, err := pod.LinkByName(p.IfName)
	if err != nil {
		return fmt.Errorf("pod interface %s: %w", p.IfName, err)
	}
	addrs, err := pod.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok && ip.Unmap() == p.Address {
			return nil
		}
	}
	return fmt.Errorf("pod interface %s lacks address %s", p.IfName, p.Address)
}

func (kernelNetops) CheckHost(h HostConfig) error {
	link, err := netlink.LinkByName(h.Veth)
	if err != nil {
		return fmt.Errorf("host veth %s: %w", h.Veth, err)
	}
	dev, err := netlink.LinkByName(h.VRF)
	if err != nil {
		return fmt.Errorf("vrf %s: %w", h.VRF, err)
	}
	if link.Attrs().MasterIndex != dev.Attrs().Index {
		return fmt.Errorf("host veth %s is not in vrf %s", h.Veth, h.VRF)
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, hostRoute(link, h),
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return fmt.Errorf("route %s/32 dev %s table %d proto static is missing", h.PodIP, h.Veth, h.TableID)
	}
	return nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
