package fibmode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Read lists the state Decide reads from the network namespace of
// the calling thread: the ip rules of both families, the VRF devices, the
// local table of both families, the IPv4 default table and both families of
// each VRF table. Every request uses a NETLINK_ROUTE socket of its own (no
// handle that opens other families), and a dump the kernel interrupted is
// an error, so a partial listing is never decided on.
func Read() (*Snapshot, error) {
	s := &Snapshot{}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := listRules(family)
		if err != nil {
			return nil, err
		}
		s.Rules = append(s.Rules, rules...)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		if v, ok := l.(*netlink.Vrf); ok {
			s.VRFs = append(s.VRFs, VRF{Name: v.Name, Index: v.Index, Table: v.Table})
		}
	}
	tables := []struct {
		family int
		table  uint32
	}{{unix.AF_INET, tableLocal}, {unix.AF_INET6, tableLocal}, {unix.AF_INET, tableDefault}}
	for _, v := range s.VRFs {
		tables = append(tables, struct {
			family int
			table  uint32
		}{unix.AF_INET, v.Table}, struct {
			family int
			table  uint32
		}{unix.AF_INET6, v.Table})
	}
	sock, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open a route socket: %w", err)
	}
	defer sock.Close()
	// With strict checking the kernel dumps only the requested table, so a
	// large main table is not read for nothing. A kernel that refuses the
	// option dumps every table, and the routes are filtered here.
	strict := unix.SetsockoptInt(sock.GetFd(), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1) == nil
	for _, t := range tables {
		routes, err := listTable(sock, strict, t.family, t.table)
		if err != nil {
			return nil, err
		}
		s.Routes = append(s.Routes, routes...)
	}
	return s, nil
}

func listRules(family int) ([]Rule, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(family))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return nil, fmt.Errorf("list ip rules of family %d: %w", family, err)
	}
	out := make([]Rule, 0, len(msgs))
	for _, m := range msgs {
		r, err := parseRule(m)
		if err != nil {
			return nil, err
		}
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out, nil
}

func listTable(sock *nl.NetlinkSocket, strict bool, family int, table uint32) ([]Route, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_DUMP)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: sock}}
	msg := &nl.RtMsg{RtMsg: unix.RtMsg{Family: uint8(family)}}
	if table < 256 {
		msg.Table = uint8(table)
	}
	req.AddData(msg)
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, table)
	req.AddData(nl.NewRtAttr(unix.RTA_TABLE, b))
	var out []Route
	var perr error
	err := req.ExecuteIter(unix.NETLINK_ROUTE, unix.RTM_NEWROUTE, func(m []byte) bool {
		r, ok, err := parseRoute(m)
		if err != nil {
			perr = err
			return false
		}
		if ok && r.Family == family && r.Table == table {
			out = append(out, r)
		}
		return true
	})
	if strict && errors.Is(err, syscall.ENOENT) {
		// The table does not exist: nothing in it.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list table %d of family %d: %w", table, family, err)
	}
	if perr != nil {
		return nil, perr
	}
	return out, nil
}
