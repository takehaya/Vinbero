package cni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// recorder collects the calls of every fake in one ordered log.
type recorder struct {
	calls []string
	// fail makes the call whose log line starts with this prefix fail.
	fail string
}

func (r *recorder) do(format string, args ...any) error {
	call := fmt.Sprintf(format, args...)
	r.calls = append(r.calls, call)
	if r.fail != "" && strings.HasPrefix(call, r.fail) {
		return errors.New("injected failure: " + call)
	}
	return nil
}

var (
	hostMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	podMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
)

type fakeNet struct {
	r *recorder
}

func (f fakeNet) CreateVeth(ns, podIf, hostIf, tmpIf string, mtu int) (Veth, error) {
	return Veth{HostMAC: hostMAC, PodMAC: podMAC}, f.r.do("veth %s %s %s mtu=%d", ns, podIf, hostIf, mtu)
}
func (f fakeNet) ConfigurePod(p PodConfig) error {
	return f.r.do("pod %s %s routes=%v gw=%s", p.IfName, p.Address, p.Routes, p.GwMAC)
}
func (f fakeNet) EnslaveHost(hostIf, vrf string) error { return f.r.do("enslave %s %s", hostIf, vrf) }
func (f fakeNet) AddHostRoute(h HostConfig) error {
	return f.r.do("route-add %s table=%d %s lladdr=%s", h.Veth, h.TableID, h.PodIP, h.PodMAC)
}
func (f fakeNet) DelHostRoute(h HostConfig) error {
	return f.r.do("route-del %s table=%d %s", h.Veth, h.TableID, h.PodIP)
}
func (f fakeNet) DeleteVeth(hostIf string) error {
	return f.r.do("veth-del %s", hostIf)
}
func (f fakeNet) CheckPod(p PodConfig) error   { return f.r.do("check-pod %s %s", p.IfName, p.Address) }
func (f fakeNet) CheckHost(h HostConfig) error { return f.r.do("check-host %s %s", h.Veth, h.PodIP) }

func (f fakeNet) LinkUp(ifname string) error { return f.r.do("link-up %s", ifname) }
func (f fakeNet) ConfigurePodL2(p PodL2Config) error {
	return f.r.do("pod-l2 %s %s", p.IfName, p.Address)
}
func (f fakeNet) HardenBridge(bridge string) error         { return f.r.do("harden %s", bridge) }
func (f fakeNet) CheckBridgeHardening(bridge string) error { return f.r.do("check-harden %s", bridge) }
func (f fakeNet) AddStaticFDB(hostIf string, mac net.HardwareAddr) error {
	return f.r.do("fdb-add %s %s", hostIf, mac)
}
func (f fakeNet) DelStaticFDB(hostIf string, mac net.HardwareAddr) error {
	return f.r.do("fdb-del %s %s", hostIf, mac)
}
func (f fakeNet) CheckPodL2(p PodL2Config) error {
	return f.r.do("check-pod-l2 %s %s", p.IfName, p.Address)
}
func (f fakeNet) CheckL2Host(hostIf, bridge string) error {
	return f.r.do("check-l2host %s %s", hostIf, bridge)
}

type fakeIPAM struct {
	r        *recorder
	ip       string
	checkErr error
}

func (f fakeIPAM) Add(_ context.Context, typ string, _ []byte) (*current.Result, error) {
	if err := f.r.do("ipam-add %s", typ); err != nil {
		return nil, err
	}
	_, ipn, _ := net.ParseCIDR(f.ip)
	ipn.IP, _, _ = net.ParseCIDR(f.ip)
	return &current.Result{IPs: []*current.IPConfig{{Address: *ipn}}}, nil
}
func (f fakeIPAM) Del(_ context.Context, typ string, _ []byte) error {
	return f.r.do("ipam-del %s", typ)
}
func (f fakeIPAM) Check(_ context.Context, typ string, _ []byte) error {
	if err := f.r.do("ipam-check %s", typ); err != nil {
		return err
	}
	return f.checkErr
}

type staticDNSIPAM struct{ fakeIPAM }

func (f staticDNSIPAM) Add(ctx context.Context, typ string, conf []byte) (*current.Result, error) {
	res, err := f.fakeIPAM.Add(ctx, typ, conf)
	if err == nil {
		res.DNS = types.DNS{Nameservers: []string{"10.0.0.53"}}
	}
	return res, err
}

type fakeDaemon struct {
	r        *recorder
	attached map[string]bool
	circuits map[string]uint32
}

func (f *fakeDaemon) EnsureVRF(_ context.Context, name string, table uint32) error {
	return f.r.do("rpc vrf-create %s %d", name, table)
}
func (f *fakeDaemon) EnsureBinding(_ context.Context, b Binding) error {
	return f.r.do("rpc vrf-bgp-bind %s %s %s", b.VRF, b.RD, b.Locator)
}
func (f *fakeDaemon) AddAC(_ context.Context, vrf, ifname string) error {
	return f.r.do("rpc ac-add %s %s", vrf, ifname)
}
func (f *fakeDaemon) RemoveAC(_ context.Context, vrf, ifname string) error {
	return f.r.do("rpc ac-remove %s %s", vrf, ifname)
}
func (f *fakeDaemon) AttachDevice(_ context.Context, ifname, mode string) error {
	if err := f.r.do("rpc device-attach %s %s", ifname, mode); err != nil {
		return err
	}
	f.attached[ifname] = true
	return nil
}
func (f *fakeDaemon) DetachDevice(_ context.Context, ifname string) error {
	delete(f.attached, ifname)
	return f.r.do("rpc device-detach %s", ifname)
}
func (f *fakeDaemon) DeviceAttached(_ context.Context, ifname string) (bool, error) {
	return f.attached[ifname], f.r.do("rpc device-list")
}
func (f *fakeDaemon) EnsureBridgeDomain(_ context.Context, vrf, bridge string, bdID uint32) error {
	return f.r.do("rpc bd-verify %s %s %d", vrf, bridge, bdID)
}
func (f *fakeDaemon) AddBridgeMember(_ context.Context, vrf, ifname string) error {
	return f.r.do("rpc bridge-member-add %s %s", vrf, ifname)
}
func (f *fakeDaemon) RemoveBridgeMember(_ context.Context, vrf, ifname string) error {
	return f.r.do("rpc bridge-member-remove %s %s", vrf, ifname)
}
func (f *fakeDaemon) CreateL2Circuit(_ context.Context, ifname string, bdID uint32) error {
	if err := f.r.do("rpc hl2-create %s bd=%d", ifname, bdID); err != nil {
		return err
	}
	if f.circuits == nil {
		f.circuits = map[string]uint32{}
	}
	f.circuits[ifname] = bdID
	return nil
}
func (f *fakeDaemon) DeleteL2Circuit(_ context.Context, ifname string) error {
	delete(f.circuits, ifname)
	return f.r.do("rpc hl2-delete %s", ifname)
}
func (f *fakeDaemon) L2CircuitPresent(_ context.Context, ifname string, bdID uint32) (bool, error) {
	return f.circuits[ifname] == bdID && bdID != 0, f.r.do("rpc hl2-list")
}

func newTestPlugin(t *testing.T, ip string) (*Plugin, *recorder, string) {
	t.Helper()
	r := &recorder{}
	dir := t.TempDir()
	d := &fakeDaemon{r: r, attached: map[string]bool{}}
	p := &Plugin{
		Net:    fakeNet{r: r},
		IPAM:   fakeIPAM{r: r, ip: ip},
		Daemon: func(string) Daemon { return d },
		Store:  func(string) *Store { return &Store{Dir: dir} },
	}
	return p, r, dir
}

func testArgs(containerID, vrf string, table uint32, extra string) *skel.CmdArgs {
	return &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       "/var/run/netns/" + containerID,
		IfName:      "net1",
		StdinData: fmt.Appendf(nil, `{"cniVersion":"1.0.0","name":"net-%s","type":"vinbero","vrf":%q,"tableId":%d,"ipam":{"type":"host-local"}%s}`,
			vrf, vrf, table, extra),
	}
}

func TestAddWiresInOrder(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.100.1.5/16")
	args := testArgs("c1", "tenant-a", 100, `,"rd":"65000:100","rts":[{"family":"vpnv4","rt":"65000:100"}],"locator":"LOC1"`)
	res, err := p.Add(args)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := vethNames("c1", "net1")
	want := []string{
		"ipam-add host-local",
		"veth /var/run/netns/c1 net1 " + host + " mtu=1436",
		"pod net1 10.100.1.5 routes=[10.100.0.0/16] gw=02:00:00:00:00:01",
		"rpc vrf-create tenant-a 100",
		"rpc vrf-bgp-bind tenant-a 65000:100 LOC1",
		"enslave " + host + " tenant-a",
		"rpc ac-add tenant-a " + host,
		"rpc device-attach " + host + " generic",
		"route-add " + host + " table=100 10.100.1.5 lladdr=02:00:00:00:00:02",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(r.calls, "\n"), strings.Join(want, "\n"))
	}
	if len(res.IPs) != 1 || res.IPs[0].Address.String() != "10.100.1.5/32" || res.IPs[0].Gateway.String() != "169.254.1.1" {
		t.Errorf("result IPs = %v", res.IPs)
	}
	if len(res.Interfaces) != 2 || res.Interfaces[1].Sandbox != args.Netns || *res.IPs[0].Interface != 1 {
		t.Errorf("result interfaces = %v", res.Interfaces)
	}
	a, ok, err := (&Store{Dir: dir}).Get("c1", "net1")
	if err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	if a.HostVeth != host || a.Address != netip.MustParsePrefix("10.100.1.5/16") || a.PodMAC != podMAC.String() || a.VRF != "tenant-a" {
		t.Errorf("record = %+v", a)
	}

	// CHECK reads the record and asks every layer.
	r.calls = nil
	if err := p.Check(args); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(r.calls) != 4 {
		t.Errorf("check calls = %v", r.calls)
	}
}

// DNS comes from the network configuration, or else from IPAM.
func TestAddDNS(t *testing.T) {
	dnsIPAM := func(r *recorder) IPAM {
		return staticDNSIPAM{fakeIPAM{r: r, ip: "10.100.1.5/24"}}
	}
	p, r, _ := newTestPlugin(t, "10.100.1.5/24")
	p.IPAM = dnsIPAM(r)
	res, err := p.Add(testArgs("c1", "tenant-a", 100, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.DNS.Nameservers, []string{"10.0.0.53"}) {
		t.Errorf("DNS without one in the configuration = %+v, want IPAM's", res.DNS)
	}
	p, r, _ = newTestPlugin(t, "10.100.1.5/24")
	p.IPAM = dnsIPAM(r)
	res, err = p.Add(testArgs("c2", "tenant-a", 100, `,"dns":{"nameservers":["10.9.9.9"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.DNS.Nameservers, []string{"10.9.9.9"}) {
		t.Errorf("DNS with one in the configuration = %+v", res.DNS)
	}
}

// whereabouts answers every CHECK with "not implemented"; a healthy pod on it
// must pass, while a real IPAM CHECK failure still fails.
func TestCheckToleratesIPAMWithoutCheck(t *testing.T) {
	p, r, _ := newTestPlugin(t, "10.100.1.5/24")
	args := testArgs("c1", "tenant-a", 100, "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	p.IPAM = fakeIPAM{r: r, ip: "10.100.1.5/24", checkErr: errors.New("CNI CHECK method is not implemented")}
	if err := p.Check(args); err != nil {
		t.Errorf("Check with an IPAM plugin without CHECK: %v", err)
	}
	p.IPAM = fakeIPAM{r: r, ip: "10.100.1.5/24", checkErr: errors.New("lease lost")}
	if err := p.Check(args); err == nil {
		t.Error("Check ignored a real IPAM failure")
	}
}

func TestAddWithoutBindingSkipsBind(t *testing.T) {
	p, r, _ := newTestPlugin(t, "10.100.1.5/24")
	if _, err := p.Add(testArgs("c1", "tenant-a", 100, "")); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "rpc vrf-bgp-bind") {
			t.Errorf("bound a VRF the configuration has no binding for: %v", r.calls)
		}
	}
}

func TestAddFailureUndoes(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.100.1.5/24")
	r.fail = "rpc device-attach"
	_, err := p.Add(testArgs("c1", "tenant-a", 100, ""))
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("Add = %v", err)
	}
	host, _ := vethNames("c1", "net1")
	tail := r.calls[len(r.calls)-5:]
	want := []string{
		"route-del " + host + " table=100 10.100.1.5",
		"rpc device-detach " + host,
		"rpc ac-remove tenant-a " + host,
		"veth-del " + host,
		"ipam-del host-local",
	}
	if !slices.Equal(tail, want) {
		t.Errorf("cleanup calls = %v, want %v", tail, want)
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); ok {
		t.Error("record left after a cleaned-up ADD")
	}
}

func TestDelIsIdempotent(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.100.1.5/24")
	args := testArgs("c1", "tenant-a", 100, "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	host, _ := vethNames("c1", "net1")
	r.calls = nil
	if err := p.Del(args); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route-del " + host + " table=100 10.100.1.5",
		"rpc device-detach " + host,
		"rpc ac-remove tenant-a " + host,
		"veth-del " + host,
		"ipam-del host-local",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("DEL calls = %v, want %v", r.calls, want)
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); ok {
		t.Error("record left after DEL")
	}

	// A second DEL (and a DEL without netns) has no record: it still
	// undoes the derived veth and the IPAM lease, without a route.
	r.calls = nil
	args.Netns = ""
	if err := p.Del(args); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"rpc device-detach " + host,
		"rpc ac-remove tenant-a " + host,
		"veth-del " + host,
		"ipam-del host-local",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("repeated DEL calls = %v, want %v", r.calls, want)
	}
	if err := p.Check(args); err == nil {
		t.Error("CHECK after DEL succeeded")
	}
}

func TestDelKeepsRecordOnError(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.100.1.5/24")
	args := testArgs("c1", "tenant-a", 100, "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	r.fail = "rpc ac-remove"
	if err := p.Del(args); err == nil {
		t.Fatal("DEL with an unreachable daemon succeeded")
	}
	// The veth and the lease stay until the AC is gone.
	for _, c := range r.calls {
		if strings.HasPrefix(c, "veth-del") || strings.HasPrefix(c, "ipam-del") {
			t.Errorf("%q ran although the AC could not be removed: %v", c, r.calls)
		}
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); !ok {
		t.Error("record dropped although DEL failed; a retry could not find the route")
	}
	r.fail = ""
	r.calls = nil
	if err := p.Del(args); err != nil {
		t.Fatalf("retried DEL: %v", err)
	}
	if !slices.Contains(r.calls, "ipam-del host-local") {
		t.Errorf("retried DEL did not release the address: %v", r.calls)
	}
}

// Two VRFs may use the same subnet, and even the same address, on one node:
// each attachment keeps its own record, VRF table and host veth, and DEL of
// one leaves the other alone. Within one VRF the plugin leaves addresses to
// IPAM.
func TestOverlappingSubnetsAcrossVRFs(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.100.1.5/16")
	argsA := testArgs("ca", "tenant-a", 100, "")
	argsB := testArgs("cb", "tenant-b", 200, "")
	hostA, _ := vethNames("ca", "net1")
	hostB, _ := vethNames("cb", "net1")
	if _, err := p.Add(argsA); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	res, err := p.Add(argsB)
	if err != nil {
		t.Fatalf("ADD of the same address in another VRF: %v", err)
	}
	if res.IPs[0].Address.String() != "10.100.1.5/32" {
		t.Errorf("tenant-b address = %v", res.IPs[0].Address)
	}
	for _, want := range []string{
		"rpc vrf-create tenant-b 200",
		"enslave " + hostB + " tenant-b",
		"rpc ac-add tenant-b " + hostB,
		"route-add " + hostB + " table=200 10.100.1.5 lladdr=02:00:00:00:00:02",
	} {
		if !slices.Contains(r.calls, want) {
			t.Errorf("tenant-b ADD lacks %q: %v", want, r.calls)
		}
	}
	store := &Store{Dir: dir}
	for _, c := range []struct {
		id, vrf string
		table   uint32
		host    string
	}{{"ca", "tenant-a", 100, hostA}, {"cb", "tenant-b", 200, hostB}} {
		a, ok, err := store.Get(c.id, "net1")
		if err != nil || !ok {
			t.Fatalf("record %s: %v %v", c.id, ok, err)
		}
		if a.VRF != c.vrf || a.TableID != c.table || a.HostVeth != c.host || a.Address != netip.MustParsePrefix("10.100.1.5/16") {
			t.Errorf("record %s = %+v", c.id, a)
		}
	}

	// Within one VRF the plugin has no check of its own either: a second
	// pod of tenant-a in the same subnet is IPAM's business.
	p.IPAM = fakeIPAM{r: r, ip: "10.100.1.6/16"}
	if _, err := p.Add(testArgs("ca2", "tenant-a", 100, "")); err != nil {
		t.Fatalf("second pod in the same VRF: %v", err)
	}

	for _, args := range []*skel.CmdArgs{argsA, argsB} {
		if err := p.Check(args); err != nil {
			t.Errorf("CHECK %s: %v", args.ContainerID, err)
		}
	}

	// DEL of tenant-a's pod touches only its own table, veth and AC.
	r.calls = nil
	if err := p.Del(argsA); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route-del " + hostA + " table=100 10.100.1.5",
		"rpc device-detach " + hostA,
		"rpc ac-remove tenant-a " + hostA,
		"veth-del " + hostA,
		"ipam-del host-local",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("DEL tenant-a calls = %v, want %v", r.calls, want)
	}
	if _, ok, _ := store.Get("cb", "net1"); !ok {
		t.Fatal("DEL of tenant-a's pod dropped tenant-b's record")
	}
	if err := p.Check(argsB); err != nil {
		t.Errorf("CHECK tenant-b after tenant-a's DEL: %v", err)
	}
	r.calls = nil
	if err := p.Del(argsB); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"route-del " + hostB + " table=200 10.100.1.5",
		"rpc device-detach " + hostB,
		"rpc ac-remove tenant-b " + hostB,
		"veth-del " + hostB,
		"ipam-del host-local",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("DEL tenant-b calls = %v, want %v", r.calls, want)
	}
}

func TestAddAgainStartsOver(t *testing.T) {
	p, r, _ := newTestPlugin(t, "10.100.1.5/24")
	args := testArgs("c1", "tenant-a", 100, "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) < 6 || !strings.HasPrefix(r.calls[0], "route-del") || r.calls[4] != "ipam-del host-local" || r.calls[5] != "ipam-add host-local" {
		t.Errorf("second ADD did not undo the first: %v", r.calls)
	}
}

func TestPodAddress(t *testing.T) {
	mk := func(cidrs ...string) *current.Result {
		r := &current.Result{}
		for _, c := range cidrs {
			ip, ipn, _ := net.ParseCIDR(c)
			ipn.IP = ip
			r.IPs = append(r.IPs, &current.IPConfig{Address: *ipn})
		}
		return r
	}
	res := mk("10.1.2.3/16")
	_, extra, _ := net.ParseCIDR("172.16.0.0/16")
	_, same, _ := net.ParseCIDR("10.1.0.0/16")
	res.Routes = append(res.Routes, routeTo(*extra), routeTo(*same))
	addr, routes, err := podAddress(res)
	if err != nil {
		t.Fatal(err)
	}
	if addr != netip.MustParsePrefix("10.1.2.3/16") {
		t.Errorf("addr = %v", addr)
	}
	if !slices.Equal(routes, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("172.16.0.0/16")}) {
		t.Errorf("routes = %v", routes)
	}
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	withDefault := mk("10.1.2.3/16")
	withDefault.Routes = []*types.Route{routeTo(*def)}
	for _, bad := range []*current.Result{mk(), mk("fd00::1/64"), mk("10.0.0.1/24", "10.0.0.2/24"), withDefault} {
		if _, _, err := podAddress(bad); err == nil {
			t.Errorf("podAddress(%v) accepted", bad.IPs)
		}
	}
}

func TestCheckBinding(t *testing.T) {
	want := Binding{VRF: "v", RD: "65000:1", Locator: "LOC1", Redistribute: []string{"static"}}
	ok := bindingProto("65000:1", "LOC1", "static")
	if err := checkBinding(ok, want); err != nil {
		t.Errorf("matching binding: %v", err)
	}
	withRTs := func(direction string) *v1.VrfBgpBinding {
		b := bindingProto("65000:1", "LOC1", "static")
		b.MaxPrefixes = 10
		b.Families = map[string]*v1.VrfBgpFamily{
			"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: direction}}},
			"vpnv6": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:999", Direction: "both"}}},
		}
		return b
	}
	wantRT := want
	wantRT.RTs = []RouteTarget{{Family: "vpnv4", RT: "65000:100"}}
	if err := checkBinding(withRTs("both"), wantRT); err != nil {
		t.Errorf("same route targets (empty direction means both): %v", err)
	}
	if err := checkBinding(withRTs("import"), wantRT); err == nil || !strings.Contains(err.Error(), "route targets") {
		t.Errorf("another direction: %v", err)
	}
	other := wantRT
	other.RTs = []RouteTarget{{Family: "vpnv4", RT: "65000:200"}}
	if err := checkBinding(withRTs("both"), other); err == nil || !strings.Contains(err.Error(), "route targets") {
		t.Errorf("another route target: %v", err)
	}
	limited := wantRT
	limited.MaxPrefixes = 11
	if err := checkBinding(withRTs("both"), limited); err == nil || !strings.Contains(err.Error(), "maxPrefixes") {
		t.Errorf("another prefix limit: %v", err)
	}
	limited.MaxPrefixes = 10
	if err := checkBinding(withRTs("both"), limited); err != nil {
		t.Errorf("same prefix limit: %v", err)
	}

	for _, bad := range []struct {
		rd, loc, redist, want string
	}{
		{"65000:2", "LOC1", "static", "rd"},
		{"65000:1", "LOC2", "static", "locator"},
		{"65000:1", "LOC1", "connected", "redistribute"},
	} {
		err := checkBinding(bindingProto(bad.rd, bad.loc, bad.redist), want)
		if err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("checkBinding(%v) = %v, want %q", bad, err, bad.want)
		}
	}
}

func TestVethNames(t *testing.T) {
	h1, t1 := vethNames("c1", "net1")
	h2, _ := vethNames("c1", "net2")
	if h1 == h2 || len(h1) > 15 || len(t1) > 15 || h1[2:] != t1[2:] {
		t.Errorf("names %q %q %q", h1, t1, h2)
	}
}

func routeTo(dst net.IPNet) *types.Route { return &types.Route{Dst: dst} }

func bindingProto(rd, locator, redistribute string) *v1.VrfBgpBinding {
	return &v1.VrfBgpBinding{VrfName: "v", Rd: rd, DefaultLocator: locator, Redistribute: []string{redistribute}}
}
