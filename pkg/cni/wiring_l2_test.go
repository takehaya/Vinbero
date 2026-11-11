package cni

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// testArgsL2 builds CmdArgs for an L2 attachment. extra is appended raw.
func testArgsL2(containerID string, extra string) *skel.CmdArgs {
	return &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       "/var/run/netns/" + containerID,
		IfName:      "net1",
		StdinData: []byte(`{"cniVersion":"1.0.0","name":"tenant-l2","type":"vinbero","mode":"l2",` +
			`"vrf":"tenant-l2","bridge":"br-l2","bdId":100,"ipam":{"type":"host-local"}` + extra + `}`),
	}
}

func TestAddL2WiresInOrder(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.200.1.5/24")
	args := testArgsL2("c1", `,"rd":"65100:1","rts":[{"family":"evpn","rt":"65000:100"}],"locator":"LOC1"`)
	res, err := p.Add(args)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := vethNames("c1", "net1")
	want := []string{
		"ipam-add host-local",
		"rpc bd-verify tenant-l2 br-l2 100",
		"rpc vrf-bgp-bind tenant-l2 65100:1 LOC1",
		"harden br-l2",
		"veth /var/run/netns/c1 net1 " + host + " mtu=1422",
		"rpc bridge-member-add tenant-l2 " + host,
		"link-up " + host,
		"rpc ac-add tenant-l2 " + host,
		"rpc hl2-create " + host + " bd=100",
		"rpc device-attach " + host + " generic",
		"fdb-add " + host + " " + podMAC.String(),
		"pod-l2 net1 10.200.1.5/24",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(r.calls, "\n"), strings.Join(want, "\n"))
	}
	// On-link prefix, no gateway.
	if len(res.IPs) != 1 || res.IPs[0].Address.String() != "10.200.1.5/24" || res.IPs[0].Gateway != nil {
		t.Errorf("result IPs = %v", res.IPs)
	}
	if len(res.Routes) != 0 {
		t.Errorf("L2 result carries routes: %v", res.Routes)
	}
	a, ok, err := (&Store{Dir: dir}).Get("c1", "net1")
	if err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	if !a.isL2() || a.Bridge != "br-l2" || a.BdID != 100 || a.TableID != 0 ||
		a.Address != netip.MustParsePrefix("10.200.1.5/24") || a.PodMAC != podMAC.String() {
		t.Errorf("record = %+v", a)
	}

	// CHECK reads the record and verifies every L2 layer.
	r.calls = nil
	if err := p.Check(args); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, c := range []string{"rpc bd-verify tenant-l2 br-l2 100", "check-harden br-l2", "check-l2host " + host + " br-l2"} {
		if !slices.Contains(r.calls, c) {
			t.Errorf("CHECK did not run %q: %v", c, r.calls)
		}
	}
}

func TestAddL2Minimal(t *testing.T) {
	// No binding: the bridge domain and its binding come from the daemon config.
	p, r, _ := newTestPlugin(t, "10.200.1.5/24")
	if _, err := p.Add(testArgsL2("c1", "")); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "rpc vrf-bgp-bind") {
			t.Errorf("bound a VRF without a binding in the configuration: %v", r.calls)
		}
	}
}

// Rollback at each ADD step undoes in reverse, including the bridge membership.
func TestAddL2RollbackEachStep(t *testing.T) {
	for _, step := range []string{
		"harden br-l2",
		"rpc bridge-member-add",
		"rpc ac-add",
		"rpc hl2-create",
		"rpc device-attach",
		"fdb-add",
		"pod-l2",
	} {
		t.Run(step, func(t *testing.T) {
			p, r, dir := newTestPlugin(t, "10.200.1.5/24")
			r.fail = step
			_, err := p.Add(testArgsL2("c1", ""))
			if err == nil {
				t.Fatalf("ADD with %q failing succeeded", step)
			}
			host, _ := vethNames("c1", "net1")
			// Whatever failed, cleanup removes the AC and the bridge membership,
			// and never leaves the pod reachable.
			if slices.Contains(r.calls, "rpc ac-add tenant-l2 "+host) &&
				!slices.Contains(r.calls, "rpc ac-remove tenant-l2 "+host) {
				t.Errorf("AC added but not removed after %q: %v", step, r.calls)
			}
			if slices.Contains(r.calls, "rpc bridge-member-add tenant-l2 "+host) &&
				!slices.Contains(r.calls, "rpc bridge-member-remove tenant-l2 "+host) {
				t.Errorf("bridge member added but not removed after %q: %v", step, r.calls)
			}
			if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); ok {
				t.Errorf("record left after a cleaned-up ADD failing at %q", step)
			}
		})
	}
}

func TestDelL2Idempotent(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.200.1.5/24")
	args := testArgsL2("c1", "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	host, _ := vethNames("c1", "net1")
	r.calls = nil
	if err := p.Del(args); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"fdb-del " + host + " " + podMAC.String(),
		"rpc hl2-delete " + host,
		"rpc device-detach " + host,
		"rpc ac-remove tenant-l2 " + host,
		"rpc bridge-member-remove tenant-l2 " + host,
		"veth-del " + host,
		"ipam-del host-local",
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("DEL calls = %v\nwant %v", r.calls, want)
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); ok {
		t.Error("record left after DEL")
	}
	// A second DEL (netns gone, no record) still undoes the derived veth.
	r.calls = nil
	args.Netns = ""
	if err := p.Del(args); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.calls, "rpc ac-remove tenant-l2 "+host) || !slices.Contains(r.calls, "veth-del "+host) {
		t.Errorf("repeated DEL did not undo the derived wiring: %v", r.calls)
	}
}

// DEL keeps the record and the veth and lease when the AC cannot be removed.
func TestDelL2KeepsRecordOnError(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.200.1.5/24")
	args := testArgsL2("c1", "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	r.fail = "rpc ac-remove"
	if err := p.Del(args); err == nil {
		t.Fatal("DEL with an unreachable daemon succeeded")
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "veth-del") || strings.HasPrefix(c, "ipam-del") {
			t.Errorf("%q ran although the AC could not be removed: %v", c, r.calls)
		}
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); !ok {
		t.Error("record dropped although DEL failed")
	}
}

// A bridge domain the daemon does not carry fails the ADD and undoes it.
func TestAddL2UndeclaredBridge(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.200.1.5/24")
	r.fail = "rpc bd-verify"
	_, err := p.Add(testArgsL2("c1", ""))
	if err == nil {
		t.Fatal("ADD with an undeclared bridge domain succeeded")
	}
	host, _ := vethNames("c1", "net1")
	if slices.Contains(r.calls, "veth "+"/var/run/netns/c1 net1 "+host+" mtu=1422") {
		t.Errorf("created the veth before verifying the bridge domain: %v", r.calls)
	}
	if _, ok, _ := (&Store{Dir: dir}).Get("c1", "net1"); ok {
		t.Error("record left after a failed bridge-domain check")
	}
}

// Two bridge domains may use the same prefix, and the same address, on one
// node: each attachment keeps its own record and host veth, and DEL of one
// leaves the other alone.
func TestL2OverlappingBridgeDomains(t *testing.T) {
	p, r, dir := newTestPlugin(t, "10.200.1.5/24")
	argsA := testArgsL2("ca", "")
	argsB := &skel.CmdArgs{
		ContainerID: "cb", Netns: "/var/run/netns/cb", IfName: "net1",
		StdinData: []byte(`{"cniVersion":"1.0.0","name":"tenant-l2b","type":"vinbero","mode":"l2",` +
			`"vrf":"tenant-l2b","bridge":"br-l2b","bdId":200,"ipam":{"type":"host-local"}}`),
	}
	hostA, _ := vethNames("ca", "net1")
	hostB, _ := vethNames("cb", "net1")
	if _, err := p.Add(argsA); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(argsB); err != nil {
		t.Fatalf("ADD of the same address in another bridge domain: %v", err)
	}
	store := &Store{Dir: dir}
	for _, c := range []struct {
		id, vrf, bridge string
		bd              uint32
		host            string
	}{{"ca", "tenant-l2", "br-l2", 100, hostA}, {"cb", "tenant-l2b", "br-l2b", 200, hostB}} {
		a, ok, err := store.Get(c.id, "net1")
		if err != nil || !ok {
			t.Fatalf("record %s: %v %v", c.id, ok, err)
		}
		if a.VRF != c.vrf || a.Bridge != c.bridge || a.BdID != c.bd || a.HostVeth != c.host {
			t.Errorf("record %s = %+v", c.id, a)
		}
	}
	r.calls = nil
	if err := p.Del(argsA); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(r.calls, func(s string) bool { return strings.Contains(s, hostB) || strings.Contains(s, "l2b") }) {
		t.Errorf("DEL of bridge domain A touched B: %v", r.calls)
	}
	if _, ok, _ := store.Get("cb", "net1"); !ok {
		t.Fatal("DEL of A dropped B's record")
	}
}

// A record an older plugin wrote has no mode field: DEL and CHECK read it as
// L3 and undo the L3 wiring, even if the network configuration now says L2.
func TestOldRecordReadsAsL3(t *testing.T) {
	dir := t.TempDir()
	host, _ := vethNames("c1", "net1")
	// A pre-L2 record: no mode, an L3 table, a /32-style address.
	if err := (&Store{Dir: dir}).Put(Attachment{
		ContainerID: "c1", IfName: "net1", VRF: "tenant-a", TableID: 100,
		HostVeth: host, Address: netip.MustParsePrefix("10.100.1.5/16"),
	}); err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	d := &fakeDaemon{r: r, attached: map[string]bool{}}
	p := &Plugin{Net: fakeNet{r: r}, IPAM: fakeIPAM{r: r, ip: "10.100.1.5/16"},
		Daemon: func(string) Daemon { return d }, Store: func(string) *Store { return &Store{Dir: dir} }}
	// The network configuration is L3 (mode defaults to l3) for an old record.
	args := testArgs("c1", "tenant-a", 100, "")
	if err := p.Del(args); err != nil {
		t.Fatalf("DEL of an old record: %v", err)
	}
	// It took the L3 teardown (a host route delete), not the L2 one.
	if !slices.ContainsFunc(r.calls, func(s string) bool { return strings.HasPrefix(s, "route-del") }) {
		t.Errorf("old record not torn down as L3: %v", r.calls)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "fdb-del") || strings.HasPrefix(c, "rpc hl2-delete") {
			t.Errorf("old record took an L2 teardown step %q: %v", c, r.calls)
		}
	}
}

func TestCheckL2Mismatch(t *testing.T) {
	p, _, _ := newTestPlugin(t, "10.200.1.5/24")
	args := testArgsL2("c1", "")
	if _, err := p.Add(args); err != nil {
		t.Fatal(err)
	}
	// The configuration now names another bridge: CHECK must fail.
	bad := testArgsL2("c1", "")
	bad.StdinData = []byte(`{"cniVersion":"1.0.0","name":"tenant-l2","type":"vinbero","mode":"l2",` +
		`"vrf":"tenant-l2","bridge":"br-OTHER","bdId":100,"ipam":{"type":"host-local"}}`)
	if err := p.Check(bad); err == nil || !strings.Contains(err.Error(), "bridge") {
		t.Errorf("CHECK with a changed bridge = %v", err)
	}
}

func TestPodAddressL2(t *testing.T) {
	mk := func(cidrs ...string) *current.Result {
		r := &current.Result{}
		for _, c := range cidrs {
			ip, ipn, _ := net.ParseCIDR(c)
			ipn.IP = ip
			r.IPs = append(r.IPs, &current.IPConfig{Address: *ipn})
		}
		return r
	}
	addr, err := podAddressL2(mk("10.1.2.3/24"))
	if err != nil || addr != netip.MustParsePrefix("10.1.2.3/24") {
		t.Fatalf("podAddressL2 = %v %v", addr, err)
	}
	// An on-link route to the pod's own subnet is fine; anything else is not.
	ok := mk("10.1.2.3/24")
	_, same, _ := net.ParseCIDR("10.1.2.0/24")
	ok.Routes = []*types.Route{routeTo(*same)}
	if _, err := podAddressL2(ok); err != nil {
		t.Errorf("on-link route rejected: %v", err)
	}
	withExtra := mk("10.1.2.3/24")
	_, ext, _ := net.ParseCIDR("172.16.0.0/16")
	withExtra.Routes = []*types.Route{routeTo(*ext)}
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	withDefault := mk("10.1.2.3/24")
	withDefault.Routes = []*types.Route{routeTo(*def)}
	for _, bad := range []*current.Result{mk(), mk("fd00::1/64"), mk("10.0.0.1/24", "10.0.0.2/24"), withExtra, withDefault} {
		if _, err := podAddressL2(bad); err == nil {
			t.Errorf("podAddressL2(%v) accepted", bad.IPs)
		}
	}
}
