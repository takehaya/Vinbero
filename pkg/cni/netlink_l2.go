package cni

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A bridge-domain bridge is an L2 device only: it floods and learns MACs, and
// End.DT2 redirects decapsulated frames into its transmit path. It has no L3
// role — no address, no gateway. But the bridge device still has an IP input
// path in the host's network stack, and a pod can reach it by sending to the
// bridge's MAC. With forwarding on (Vinbero needs it for the underlay), a
// frame a pod addresses to another PE's SID would be routed out and decapsulated
// into another tenant, and an IPv4/UDP packet could reach a node service or a
// MUP headend. bridgeHardening closes that path for both families. None of
// these settings touch the L2 data path: the host veth's XDP program runs
// before the stack, the decap redirect is L2 transmit (not IP input), and
// FDB learning is L2, so pod-to-pod forwarding is unaffected.
//
// Each setting is the interface-scoped value; where the kernel takes the
// maximum of conf/all and conf/<bridge> (rp_filter, arp_ignore), setting the
// interface value is enough regardless of conf/all.
type sysctlSetting struct {
	// path is the /proc/sys path with one %s for the bridge name.
	path string
	val  string
	// optional skips the setting when the file is absent (e.g. MPLS not
	// built into the kernel), rather than failing.
	optional bool
	why      string
}

func bridgeHardening(bridge string) []sysctlSetting {
	return []sysctlSetting{
		{"/proc/sys/net/ipv6/conf/%s/disable_ipv6", "1", false,
			"no IPv6 stack on the bridge (no link-local, no ND replies, no IPv6 forwarding from it)"},
		{"/proc/sys/net/ipv4/conf/%s/forwarding", "0", false,
			"do not forward IPv4 packets received on the bridge"},
		{"/proc/sys/net/ipv4/conf/%s/rp_filter", "1", false,
			"strict reverse-path: the bridge has no route back to a pod source, so local delivery, forwarding and broadcast from pods fail source validation"},
		{"/proc/sys/net/ipv4/conf/%s/arp_ignore", "8", false,
			"never answer ARP for a local address on the bridge"},
		{"/proc/sys/net/ipv4/conf/%s/accept_local", "0", false,
			"do not accept packets with a local source address from the bridge"},
		{"/proc/sys/net/ipv4/conf/%s/route_localnet", "0", false,
			"do not route 127/8 on the bridge"},
		{"/proc/sys/net/ipv4/conf/%s/proxy_arp", "0", false,
			"no proxy ARP on the bridge"},
		{"/proc/sys/net/mpls/conf/%s/input", "0", true,
			"do not accept MPLS on the bridge (when MPLS is built in)"},
	}
}

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (kernelNetops) HardenBridge(bridge string) error {
	if _, err := netlink.LinkByName(bridge); err != nil {
		return fmt.Errorf("bridge %s: %w", bridge, err)
	}
	for _, s := range bridgeHardening(bridge) {
		path := fmt.Sprintf(s.path, bridge)
		if s.optional {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		if err := os.WriteFile(path, []byte(s.val+"\n"), 0o644); err != nil {
			return fmt.Errorf("harden bridge %s (%s): %w", bridge, s.why, err)
		}
	}
	return nil
}

func (kernelNetops) CheckBridgeHardening(bridge string) error {
	if _, err := netlink.LinkByName(bridge); err != nil {
		return fmt.Errorf("bridge %s: %w", bridge, err)
	}
	for _, s := range bridgeHardening(bridge) {
		path := fmt.Sprintf(s.path, bridge)
		got, err := readSysctl(path)
		if errors.Is(err, os.ErrNotExist) {
			if s.optional {
				continue
			}
			return fmt.Errorf("bridge %s is missing %s", bridge, path)
		}
		if err != nil {
			return err
		}
		if got != s.val {
			return fmt.Errorf("bridge %s has %s=%s, want %s (%s)", bridge, path, got, s.val, s.why)
		}
	}
	return nil
}

func (kernelNetops) LinkUp(ifname string) error {
	l, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

func (kernelNetops) ConfigurePodL2(p PodL2Config) error {
	pod, closeNS, err := openNetns(p.Netns)
	if err != nil {
		return err
	}
	defer closeNS()
	link, err := pod.LinkByName(p.IfName)
	if err != nil {
		return err
	}
	// The whole prefix on-link: pods of the bridge domain reach each other
	// with ordinary ARP/ND, no gateway.
	if err := pod.AddrReplace(link, &netlink.Addr{IPNet: prefixToIPNet(p.Address)}); err != nil {
		return fmt.Errorf("address %s on %s: %w", p.Address, p.IfName, err)
	}
	return pod.LinkSetUp(link)
}

func (kernelNetops) CheckPodL2(p PodL2Config) error {
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
	want := p.Address.Addr()
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || ip.Unmap() != want {
			continue
		}
		ones, _ := a.Mask.Size()
		if ones == p.Address.Bits() {
			return nil
		}
	}
	return fmt.Errorf("pod interface %s lacks on-link address %s", p.IfName, p.Address)
}

func (kernelNetops) CheckL2Host(hostIf, bridge string) error {
	host, err := netlink.LinkByName(hostIf)
	if err != nil {
		return fmt.Errorf("host veth %s: %w", hostIf, err)
	}
	br, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("bridge %s: %w", bridge, err)
	}
	if host.Attrs().MasterIndex != br.Attrs().Index {
		return fmt.Errorf("host veth %s is not a member of bridge %s", hostIf, bridge)
	}
	return nil
}

func fdbNeigh(hostIf string, mac net.HardwareAddr) (*netlink.Neigh, netlink.Link, error) {
	l, err := netlink.LinkByName(hostIf)
	if err != nil {
		return nil, nil, err
	}
	return &netlink.Neigh{
		LinkIndex:    l.Attrs().Index,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_MASTER,
		HardwareAddr: mac,
	}, l, nil
}

func (kernelNetops) AddStaticFDB(hostIf string, mac net.HardwareAddr) error {
	n, _, err := fdbNeigh(hostIf, mac)
	if err != nil {
		return err
	}
	// Replace, not append: a retried ADD must not leave two FDB entries for
	// the same MAC. A permanent entry on a bridge port (not the port's own
	// MAC) is synced to fdb_map and advertised as RT2 by the FDB watcher.
	if err := netlink.NeighSet(n); err != nil {
		return fmt.Errorf("static fdb %s dev %s: %w", mac, hostIf, err)
	}
	return nil
}

func (kernelNetops) DelStaticFDB(hostIf string, mac net.HardwareAddr) error {
	n, _, err := fdbNeigh(hostIf, mac)
	if isNotFound(err) {
		return nil // the kernel dropped the entry with the port
	}
	if err != nil {
		return err
	}
	if err := netlink.NeighDel(n); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("delete static fdb %s dev %s: %w", mac, hostIf, err)
	}
	return nil
}
