package fibmode

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ruleMsg builds an RTM_NEWRULE payload as the kernel dumps it.
func ruleMsg(family, dstLen, tos, action uint8, flags uint32, attrs ...*nl.RtAttr) []byte {
	b := make([]byte, fibRuleHdrLen)
	b[0], b[1], b[3], b[7] = family, dstLen, tos, action
	binary.NativeEndian.PutUint32(b[8:], flags)
	for _, a := range attrs {
		b = append(b, a.Serialize()...)
	}
	return b
}

func u32(t uint16, v uint32) *nl.RtAttr { return nl.NewRtAttr(int(t), nl.Uint32Attr(v)) }
func u8(t uint16, v uint8) *nl.RtAttr   { return nl.NewRtAttr(int(t), []byte{v}) }

// kernelRule is what the kernel dumps for one of its own rules.
func kernelRule(family uint8, prio, table uint32) []byte {
	attrs := []*nl.RtAttr{u32(unix.FRA_TABLE, table), u32(unix.FRA_SUPPRESS_PREFIXLEN, 0xffffffff), u8(unix.FRA_PROTOCOL, 2)}
	if prio != 0 {
		attrs = append(attrs, u32(unix.FRA_PRIORITY, prio))
	}
	return ruleMsg(family, 0, 0, unix.FR_ACT_TO_TBL, 0, attrs...)
}

func TestParseRule(t *testing.T) {
	l3mdev := ruleMsg(unix.AF_INET6, 0, 0, unix.FR_ACT_TO_TBL, 0,
		u32(unix.FRA_TABLE, 0), u32(unix.FRA_SUPPRESS_PREFIXLEN, 0xffffffff), u8(unix.FRA_PROTOCOL, 2),
		u32(unix.FRA_PRIORITY, 1000), u8(unix.FRA_L3MDEV, 1))
	cases := []struct {
		name     string
		msg      []byte
		want     Rule
		notPlain string
	}{
		{"local", kernelRule(unix.AF_INET, 0, 255), Rule{Family: unix.AF_INET, Table: 255}, ""},
		{"main", kernelRule(unix.AF_INET6, 32766, 254), Rule{Family: unix.AF_INET6, Priority: 32766, Table: 254}, ""},
		{"l3mdev", l3mdev, Rule{Family: unix.AF_INET6, Priority: 1000, L3mdev: true}, ""},
		{"from prefix", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 100),
			nl.NewRtAttr(unix.FRA_SRC, []byte{10, 0, 0, 0})), Rule{Family: unix.AF_INET, Table: 100}, "attribute 2"},
		{"to prefix in the header", ruleMsg(unix.AF_INET, 24, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 100)),
			Rule{Family: unix.AF_INET, Table: 100}, "prefix"},
		{"tos", ruleMsg(unix.AF_INET, 0, 0x10, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254)),
			Rule{Family: unix.AF_INET, Table: 254}, "TOS"},
		{"not", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, unix.FIB_RULE_INVERT, u32(unix.FRA_TABLE, 254)),
			Rule{Family: unix.AF_INET, Table: 254}, "flags"},
		{"unreachable action", ruleMsg(unix.AF_INET6, 0, 0, unix.FR_ACT_UNREACHABLE, 0, u32(unix.FRA_TABLE, 0)),
			Rule{Family: unix.AF_INET6}, "action"},
		{"goto", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_GOTO, 0, u32(unix.FRA_GOTO, 32766)),
			Rule{Family: unix.AF_INET}, "action"},
		{"suppress_prefixlength 0", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254),
			u32(unix.FRA_SUPPRESS_PREFIXLEN, 0)), Rule{Family: unix.AF_INET, Table: 254}, "suppresses"},
		{"fwmark", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254),
			u32(unix.FRA_FWMARK, 1)), Rule{Family: unix.AF_INET, Table: 254}, "attribute 10"},
		{"iif", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254),
			nl.NewRtAttr(unix.FRA_IIFNAME, []byte("eth0\x00"))), Rule{Family: unix.AF_INET, Table: 254}, "attribute 3"},
		{"ipproto", ruleMsg(unix.AF_INET, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254),
			u8(unix.FRA_IP_PROTO, 6)), Rule{Family: unix.AF_INET, Table: 254}, "attribute 22"},
		{"an attribute of a later kernel", ruleMsg(unix.AF_INET6, 0, 0, unix.FR_ACT_TO_TBL, 0, u32(unix.FRA_TABLE, 254),
			u32(200, 1)), Rule{Family: unix.AF_INET6, Table: 254}, "attribute 200"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := parseRule(c.msg)
			if err != nil {
				t.Fatal(err)
			}
			got := r
			got.NotPlain = ""
			if got != c.want {
				t.Errorf("parsed %+v, want %+v", got, c.want)
			}
			if c.notPlain == "" && r.NotPlain != "" || c.notPlain != "" && !strings.Contains(r.NotPlain, c.notPlain) {
				t.Errorf("NotPlain %q, want %q", r.NotPlain, c.notPlain)
			}
		})
	}
	if _, err := parseRule([]byte{2, 0}); err == nil {
		t.Error("a short message parsed")
	}
}

func defaultRules() []Rule {
	return []Rule{
		{Family: unix.AF_INET, Priority: 0, Table: 255},
		{Family: unix.AF_INET, Priority: 32766, Table: 254},
		{Family: unix.AF_INET, Priority: 32767, Table: 253},
		{Family: unix.AF_INET6, Priority: 0, Table: 255},
		{Family: unix.AF_INET6, Priority: 32766, Table: 254},
	}
}

func l3mdevRules() []Rule {
	return []Rule{
		{Family: unix.AF_INET, Priority: 1000, L3mdev: true},
		{Family: unix.AF_INET6, Priority: 1000, L3mdev: true},
	}
}

func host(s string) Route {
	a := netip.MustParseAddr(s)
	f := unix.AF_INET6
	if a.Is4() {
		f = unix.AF_INET
	}
	return Route{Family: f, Table: 255, Type: unix.RTN_LOCAL, Dst: netip.PrefixFrom(a, a.BitLen())}
}

func route(table uint32, typ uint8, p string) Route {
	pr := netip.MustParsePrefix(p)
	f := unix.AF_INET6
	if pr.Addr().Is4() {
		f = unix.AF_INET
	}
	return Route{Family: f, Table: table, Type: typ, Dst: pr}
}

func baseRoutes() []Route {
	return []Route{
		host("192.0.2.1"), host("192.0.2.255"), host("127.0.0.1"), route(255, unix.RTN_LOCAL, "127.0.0.0/8"),
		host("fd00::1"), route(255, unix.RTN_MULTICAST, "ff00::/8"), host("::1"),
	}
}

func vrfRoutes(table uint32) []Route {
	return []Route{
		route(table, unix.RTN_UNREACHABLE, "0.0.0.0/0"), route(table, unix.RTN_UNREACHABLE, "::/0"),
		route(table, unix.RTN_UNICAST, "10.1.0.0/24"), route(table, unix.RTN_LOCAL, "10.1.0.1/32"),
	}
}

func TestDecide(t *testing.T) {
	vrf := []VRF{{Name: "red", Index: 10, Table: 100}}
	type want struct {
		v4, v6 string // "" = direct, else a part of Why
	}
	cases := []struct {
		name string
		s    Snapshot
		want want
	}{
		{"kernel defaults", Snapshot{Rules: defaultRules(), Routes: baseRoutes()}, want{}},
		{"VRF with closed tables", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), VRFs: vrf,
			Routes: append(baseRoutes(), vrfRoutes(100)...)}, want{}},
		{"local rule moved after the l3mdev rule", Snapshot{Rules: append([]Rule{
			{Family: unix.AF_INET, Priority: 32765, Table: 255}, {Family: unix.AF_INET, Priority: 32766, Table: 254},
			{Family: unix.AF_INET6, Priority: 32765, Table: 255}, {Family: unix.AF_INET6, Priority: 32766, Table: 254},
		}, l3mdevRules()...), VRFs: vrf, Routes: append(baseRoutes(), vrfRoutes(100)...)}, want{}},
		{"l3mdev rules left after the VRF is gone", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), Routes: baseRoutes()}, want{}},
		{"custom rule", Snapshot{Rules: append(defaultRules(), Rule{Family: unix.AF_INET, Priority: 100, Table: 200}),
			Routes: baseRoutes()}, want{v4: "table 200"}},
		{"rule that is not plain", Snapshot{Rules: append(defaultRules(), Rule{Family: unix.AF_INET6, Priority: 100, Table: 254, NotPlain: "has selector or attribute 22"}),
			Routes: baseRoutes()}, want{v6: "attribute 22"}},
		{"IPv6 rule to the default table", Snapshot{Rules: append(defaultRules(), Rule{Family: unix.AF_INET6, Priority: 32767, Table: 253}),
			Routes: baseRoutes()}, want{v6: "table 253"}},
		{"no main rule", Snapshot{Rules: defaultRules()[1:2], Routes: baseRoutes()}, want{v6: "main table"}},
		{"l3mdev after main", Snapshot{Rules: append(defaultRules(), Rule{Family: unix.AF_INET, Priority: 40000, L3mdev: true}),
			Routes: baseRoutes()}, want{v4: "after"}},
		{"VRF without l3mdev rule", Snapshot{Rules: defaultRules(), VRFs: vrf, Routes: append(baseRoutes(), vrfRoutes(100)...)},
			want{v4: "no l3mdev rule", v6: "no l3mdev rule"}},
		{"local prefix", Snapshot{Rules: defaultRules(), Routes: append(baseRoutes(), route(255, unix.RTN_LOCAL, "10.200.0.0/16"))},
			want{v4: "10.200.0.0/16"}},
		{"IPv6 local prefix", Snapshot{Rules: defaultRules(), Routes: append(baseRoutes(), route(255, unix.RTN_LOCAL, "2001:db8::/64"))},
			want{v6: "2001:db8::/64"}},
		{"default table route", Snapshot{Rules: defaultRules(), Routes: append(baseRoutes(), route(253, unix.RTN_UNICAST, "10.9.0.0/24"))},
			want{v4: "default table"}},
		{"VRF table open", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), VRFs: vrf,
			Routes: append(baseRoutes(), route(100, unix.RTN_UNICAST, "10.1.0.0/24"))}, want{v4: "unreachable default", v6: "unreachable default"}},
		{"VRF table with a unicast default", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), VRFs: vrf,
			Routes: append(baseRoutes(), route(100, unix.RTN_UNICAST, "0.0.0.0/0"), route(100, unix.RTN_BLACKHOLE, "::/0"))},
			want{v4: "unreachable default"}},
		{"VRF table with a throw route", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), VRFs: vrf,
			Routes: append(append(baseRoutes(), vrfRoutes(100)...), route(100, unix.RTN_THROW, "10.2.0.0/24"), route(100, unix.RTN_THROW, "2001:db8:2::/48"))},
			want{v4: "throw"}},
		{"VRF table with a TOS default only", Snapshot{Rules: append(defaultRules(), l3mdevRules()...), VRFs: vrf,
			Routes: append(baseRoutes(), Route{Family: unix.AF_INET, Table: 100, Type: unix.RTN_UNREACHABLE, Dst: netip.MustParsePrefix("0.0.0.0/0"), Tos: 0x10},
				route(100, unix.RTN_PROHIBIT, "::/0"))},
			want{v4: "unreachable default"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(&c.s)
			for _, f := range []struct {
				name string
				got  Family
				want string
			}{{"IPv4", d.V4, c.want.v4}, {"IPv6", d.V6, c.want.v6}} {
				if f.want == "" && !f.got.Direct {
					t.Errorf("%s: full lookup (%s), want direct", f.name, f.got.Why)
				}
				if f.want != "" && (f.got.Direct || !strings.Contains(f.got.Why, f.want)) {
					t.Errorf("%s: direct=%v why %q, want the full lookup because of %q", f.name, f.got.Direct, f.got.Why, f.want)
				}
			}
		})
	}
}

func TestDecideLocalAddresses(t *testing.T) {
	d := Decide(&Snapshot{Rules: defaultRules(), Routes: append(baseRoutes(), host("192.0.2.1"), host("10.0.0.1"))})
	want4 := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.255")}
	if len(d.V4.Local) != len(want4) {
		t.Fatalf("IPv4 local %v, want %v", d.V4.Local, want4)
	}
	for i := range want4 {
		if d.V4.Local[i] != want4[i] {
			t.Fatalf("IPv4 local %v, want %v", d.V4.Local, want4)
		}
	}
	if len(d.V6.Local) != 2 {
		t.Fatalf("IPv6 local %v, want ::1 and fd00::1", d.V6.Local)
	}
	var many []Route
	for i := 0; i <= MaxLocal; i++ {
		many = append(many, host(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()))
	}
	if d := Decide(&Snapshot{Rules: defaultRules(), Routes: many}); d.V4.Direct || !strings.Contains(d.V4.Why, "host routes") {
		t.Errorf("%d local addresses: direct=%v why %q", len(many), d.V4.Direct, d.V4.Why)
	}
}

func TestParseRoute(t *testing.T) {
	b := make([]byte, rtMsgLen)
	b[0], b[1], b[4], b[7] = unix.AF_INET6, 0, unix.RT_TABLE_UNSPEC, unix.RTN_UNREACHABLE
	b = append(b, u32(unix.RTA_TABLE, 1000).Serialize()...)
	r, ok, err := parseRoute(b)
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	if r.Table != 1000 || r.Dst != netip.MustParsePrefix("::/0") || r.Type != unix.RTN_UNREACHABLE {
		t.Errorf("parsed %+v", r)
	}
	b = make([]byte, rtMsgLen)
	b[0], b[1], b[4], b[7] = unix.AF_INET, 32, 255, unix.RTN_LOCAL
	b = append(b, nl.NewRtAttr(unix.RTA_DST, []byte{192, 0, 2, 1}).Serialize()...)
	if r, ok, err = parseRoute(b); err != nil || !ok || r.Dst != netip.MustParsePrefix("192.0.2.1/32") || r.Table != 255 {
		t.Errorf("parsed %+v ok=%v err=%v", r, ok, err)
	}
	binary.NativeEndian.PutUint32(b[8:], unix.RTM_F_CLONED)
	if _, ok, _ = parseRoute(b); ok {
		t.Error("a cloned route was taken for a table route")
	}
}
