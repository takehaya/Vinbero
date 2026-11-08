package cni

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// rpcTimeout bounds every call to vinberod, so a hung daemon fails the CNI
// command instead of blocking the runtime.
const rpcTimeout = 10 * time.Second

// IPAM runs the delegated IPAM plugin named in the network configuration.
type IPAM interface {
	Add(ctx context.Context, ipamType string, conf []byte) (*current.Result, error)
	Del(ctx context.Context, ipamType string, conf []byte) error
	Check(ctx context.Context, ipamType string, conf []byte) error
}

// Plugin wires a pod into a Vinbero VRF.
type Plugin struct {
	Net    Netops
	IPAM   IPAM
	Daemon func(serverURL string) Daemon
	Store  func(dir string) *Store
}

// NewPlugin returns a Plugin that drives the kernel, the IPAM plugin binary
// and the vinberod at the configured address.
func NewPlugin() *Plugin {
	return &Plugin{
		Net:    kernelNetops{},
		IPAM:   execIPAM{},
		Daemon: NewDaemon,
		Store:  func(dir string) *Store { return &Store{Dir: dir} },
	}
}

// vethNames derives the host veth name and the temporary name of the pod
// end from the attachment key, so DEL finds them without a record.
func vethNames(containerID, ifName string) (host, tmp string) {
	sum := sha256.Sum256([]byte(containerID + "/" + ifName))
	h := hex.EncodeToString(sum[:])
	return "vb" + h[:11], "vp" + h[:11]
}

// Add runs CNI ADD.
func (p *Plugin) Add(args *skel.CmdArgs) (*current.Result, error) {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return nil, err
	}
	if err := validIfname(args.IfName); err != nil {
		return nil, fmt.Errorf("CNI_IFNAME: %w", err)
	}
	store := p.Store(conf.DataDir)
	unlock, err := store.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	ctx := context.Background()
	daemon := p.Daemon(conf.Server)

	// ADD without DEL: start from scratch, releasing the old address.
	if old, ok, err := store.Get(args.ContainerID, args.IfName); err != nil {
		return nil, err
	} else if ok {
		if err := p.teardown(ctx, daemon, store, conf, args, old); err != nil {
			return nil, fmt.Errorf("clean up the previous attachment: %w", err)
		}
	}

	ipamRes, err := p.IPAM.Add(ctx, conf.IPAM.Type, args.StdinData)
	if err != nil {
		return nil, fmt.Errorf("ipam %s: %w", conf.IPAM.Type, err)
	}
	addr, routes, err := podAddress(ipamRes)
	if err != nil {
		_ = p.IPAM.Del(ctx, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	hostIf, tmpIf := vethNames(args.ContainerID, args.IfName)
	a := Attachment{
		ContainerID: args.ContainerID,
		IfName:      args.IfName,
		Netns:       args.Netns,
		Network:     conf.Name,
		VRF:         conf.VRF,
		TableID:     conf.TableID,
		HostVeth:    hostIf,
		Address:     addr,
	}
	if err := p.checkOverlap(store, a); err != nil {
		_ = p.IPAM.Del(ctx, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	// Record before touching anything, so a DEL after a failed ADD finds
	// what to undo.
	if err := store.Put(a); err != nil {
		_ = p.IPAM.Del(ctx, conf.IPAM.Type, args.StdinData)
		return nil, fmt.Errorf("record attachment: %w", err)
	}
	res, err := p.setup(ctx, daemon, store, conf, args, &a, tmpIf, routes)
	if err != nil {
		if terr := p.teardown(ctx, daemon, store, conf, args, a); terr != nil {
			return nil, fmt.Errorf("%w (cleanup: %v)", err, terr)
		}
		return nil, err
	}
	return res, nil
}

func (p *Plugin) setup(ctx context.Context, daemon Daemon, store *Store, conf *NetConf, args *skel.CmdArgs, a *Attachment, tmpIf string, routes []netip.Prefix) (*current.Result, error) {
	veth, err := p.Net.CreateVeth(args.Netns, args.IfName, a.HostVeth, tmpIf, conf.MTU)
	if err != nil {
		return nil, err
	}
	a.PodMAC, a.HostMAC = veth.PodMAC.String(), veth.HostMAC.String()
	if err := store.Put(*a); err != nil {
		return nil, fmt.Errorf("record attachment: %w", err)
	}
	podIP := a.Address.Addr()
	if err := p.Net.ConfigurePod(PodConfig{
		Netns: args.Netns, IfName: args.IfName, Address: podIP, Routes: routes, GwMAC: veth.HostMAC,
	}); err != nil {
		return nil, err
	}

	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	if err := daemon.EnsureVRF(rctx, conf.VRF, conf.TableID); err != nil {
		return nil, err
	}
	if conf.WantsBinding() {
		if err := daemon.EnsureBinding(rctx, Binding{
			VRF: conf.VRF, RD: conf.RD, RTs: conf.RTs, Locator: conf.Locator, MaxPrefixes: conf.MaxPrefixes,
		}); err != nil {
			return nil, err
		}
	}
	if err := p.Net.EnslaveHost(a.HostVeth, conf.VRF); err != nil {
		return nil, err
	}
	if err := daemon.AddAC(rctx, conf.VRF, a.HostVeth); err != nil {
		return nil, err
	}
	if err := daemon.AttachDevice(rctx, a.HostVeth, conf.DeviceMode); err != nil {
		return nil, err
	}
	// Last: the static route is what vinberod advertises, so the pod is
	// announced only once its veth is on the data plane.
	if err := p.Net.AddHostRoute(HostConfig{
		Veth: a.HostVeth, VRF: conf.VRF, TableID: conf.TableID, PodIP: podIP, PodMAC: veth.PodMAC,
	}); err != nil {
		return nil, err
	}

	podIdx := 1
	res := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			{Name: a.HostVeth, Mac: a.HostMAC},
			{Name: args.IfName, Mac: a.PodMAC, Sandbox: args.Netns},
		},
		IPs: []*current.IPConfig{{
			Interface: &podIdx,
			Address:   *prefixToIPNet(netip.PrefixFrom(podIP, 32)),
			Gateway:   net.IP(podGateway.AsSlice()),
		}},
		DNS: conf.DNS,
	}
	for _, r := range routes {
		res.Routes = append(res.Routes, &types.Route{Dst: *prefixToIPNet(r), GW: net.IP(podGateway.AsSlice())})
	}
	return res, nil
}

// podAddress picks the IPv4 address from the IPAM result and the routes
// the pod sends through the host: the address's subnet plus the routes
// IPAM returned.
func podAddress(r *current.Result) (netip.Prefix, []netip.Prefix, error) {
	var addr netip.Prefix
	for _, ipc := range r.IPs {
		ip, ok := netip.AddrFromSlice(ipc.Address.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() {
			return netip.Prefix{}, nil, fmt.Errorf("ipam returned %s: only IPv4 is supported", ipc.Address.String())
		}
		if addr.IsValid() {
			return netip.Prefix{}, nil, fmt.Errorf("ipam returned more than one IPv4 address")
		}
		ones, _ := ipc.Address.Mask.Size()
		addr = netip.PrefixFrom(ip, ones)
	}
	if !addr.IsValid() {
		return netip.Prefix{}, nil, fmt.Errorf("ipam returned no IPv4 address")
	}
	routes := []netip.Prefix{addr.Masked()}
	for _, rt := range r.Routes {
		dst, ok := netip.AddrFromSlice(rt.Dst.IP)
		if !ok {
			continue
		}
		ones, _ := rt.Dst.Mask.Size()
		pfx := netip.PrefixFrom(dst.Unmap(), ones).Masked()
		if pfx.Addr().Is4() && pfx != routes[0] {
			routes = append(routes, pfx)
		}
	}
	return addr, routes, nil
}

// checkOverlap refuses an address whose subnet overlaps a subnet another
// VRF uses on this node. The headend table vinberod encapsulates from is
// shared by every VRF, so overlapping pod subnets in two VRFs would steal
// each other's traffic.
func (p *Plugin) checkOverlap(store *Store, a Attachment) error {
	all, err := store.List()
	if err != nil {
		return err
	}
	mine := a.Address.Masked()
	for _, o := range all {
		if o.VRF == a.VRF || !o.Address.IsValid() {
			continue
		}
		if theirs := o.Address.Masked(); theirs.Overlaps(mine) {
			return fmt.Errorf("pod subnet %s of vrf %s overlaps %s of vrf %s (network %s); pod subnets must not overlap across VRFs",
				mine, a.VRF, theirs, o.VRF, o.Network)
		}
	}
	return nil
}

// Del runs CNI DEL. Every step treats "already gone" as done, so a DEL
// without a record, a repeated DEL or one after a failed ADD succeeds.
func (p *Plugin) Del(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return err
	}
	store := p.Store(conf.DataDir)
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	a, ok, err := store.Get(args.ContainerID, args.IfName)
	if err != nil {
		return err
	}
	if !ok {
		// No record: ADD never got far, or the record was lost. The veth
		// name is derived, so the data-plane state can still be undone;
		// the kernel drops the route with the veth.
		host, _ := vethNames(args.ContainerID, args.IfName)
		a = Attachment{
			ContainerID: args.ContainerID, IfName: args.IfName, Netns: args.Netns,
			VRF: conf.VRF, TableID: conf.TableID, HostVeth: host,
		}
	}
	if args.Netns != "" {
		a.Netns = args.Netns
	}
	return p.teardown(context.Background(), p.Daemon(conf.Server), store, conf, args, a)
}

// teardown undoes an attachment in the reverse order of setup and drops the
// record once every step succeeded; on error the record stays for a retry.
func (p *Plugin) teardown(ctx context.Context, daemon Daemon, store *Store, conf *NetConf, args *skel.CmdArgs, a Attachment) error {
	var errs []error
	if a.Address.IsValid() {
		errs = append(errs, p.Net.DelHostRoute(HostConfig{
			Veth: a.HostVeth, VRF: a.VRF, TableID: a.TableID, PodIP: a.Address.Addr(),
		}))
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	errs = append(errs,
		daemon.DetachDevice(rctx, a.HostVeth),
		daemon.RemoveAC(rctx, a.VRF, a.HostVeth),
		p.Net.DeleteVeth(a.Netns, a.IfName, a.HostVeth),
		p.IPAM.Del(ctx, conf.IPAM.Type, args.StdinData),
	)
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return store.Delete(a.ContainerID, a.IfName)
}

// Check runs CNI CHECK.
func (p *Plugin) Check(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return err
	}
	store := p.Store(conf.DataDir)
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	a, ok, err := store.Get(args.ContainerID, args.IfName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no attachment recorded for container %s interface %s", args.ContainerID, args.IfName)
	}
	if a.VRF != conf.VRF || a.TableID != conf.TableID {
		return fmt.Errorf("attachment is in vrf %s table %d, the network configuration says vrf %s table %d",
			a.VRF, a.TableID, conf.VRF, conf.TableID)
	}
	ctx := context.Background()
	if err := p.IPAM.Check(ctx, conf.IPAM.Type, args.StdinData); err != nil {
		return fmt.Errorf("ipam %s: %w", conf.IPAM.Type, err)
	}
	if err := p.Net.CheckPod(PodConfig{Netns: args.Netns, IfName: args.IfName, Address: a.Address.Addr()}); err != nil {
		return err
	}
	if err := p.Net.CheckHost(HostConfig{
		Veth: a.HostVeth, VRF: a.VRF, TableID: a.TableID, PodIP: a.Address.Addr(),
	}); err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	attached, err := p.Daemon(conf.Server).DeviceAttached(rctx, a.HostVeth)
	if err != nil {
		return err
	}
	if !attached {
		return fmt.Errorf("host veth %s is not attached to the data plane", a.HostVeth)
	}
	return nil
}
