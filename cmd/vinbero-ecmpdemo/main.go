// vinbero-ecmpdemo drives the ECMP path-group data plane of a running
// vinberod for demos and the netns example. The BGP applier is the intended
// writer of ECMP groups and no operator-facing RPC exists yet, so this tool
// writes the group tables directly through the daemon's map file descriptors
// (found via /proc/<pid>/fdinfo). It is a test harness, not a management
// interface: it bypasses the daemon's owner-tag bookkeeping on purpose and
// will be superseded by the HeadendGroupService.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/urfave/cli/v2"

	"github.com/takehaya/vinbero/pkg/bpf"
)

const (
	mapHeadendV4 = "headend_v4_map"
	mapEcmpGroup = "ecmp_group_map"
	mapEcmpPath  = "ecmp_path_map"
	mapEcmpLive  = "ecmp_live_map"
)

// daemonMaps opens the named BPF maps through the daemon's open file
// descriptors. Matching by name alone via MapGetNextID would be ambiguous
// when several vinberod instances (or other loaded collections) coexist on
// the same kernel, so membership in the target process pins the instance.
func daemonMaps(pid int, names ...string) (map[string]*ebpf.Map, error) {
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		wanted[n] = true
	}
	found := make(map[string]*ebpf.Map, len(names))

	fdinfoDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
	entries, err := os.ReadDir(fdinfoDir)
	if err != nil {
		return nil, fmt.Errorf("read %s (is %d the vinberod pid, and are we root?): %w", fdinfoDir, pid, err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(fdinfoDir + "/" + e.Name())
		if err != nil {
			continue // fd raced away
		}
		var mapID uint64
		for line := range strings.SplitSeq(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "map_id:"); ok {
				mapID, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 32)
				break
			}
		}
		if mapID == 0 {
			continue
		}
		m, err := ebpf.NewMapFromID(ebpf.MapID(mapID))
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil || !wanted[info.Name] || found[info.Name] != nil {
			_ = m.Close()
			continue
		}
		found[info.Name] = m
	}
	for _, n := range names {
		if found[n] == nil {
			return nil, fmt.Errorf("map %q not found among pid %d's file descriptors", n, pid)
		}
	}
	return found, nil
}

// lpmKeyV4 builds the headend_v4_map trigger key from a CIDR.
func lpmKeyV4(cidr string) (*bpf.LpmKeyV4, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse trigger prefix %q: %w", cidr, err)
	}
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("trigger prefix %q is not IPv4", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	key := &bpf.LpmKeyV4{Prefixlen: uint32(ones)}
	copy(key.Addr[:], v4)
	return key, nil
}

// parsePathSpec parses "sid1+sid2[@weight]" into segments and a weight.
// Segments join with "+" because urfave/cli splits repeated string-slice
// flags on commas.
func parsePathSpec(spec string) ([]string, uint16, error) {
	segsPart := spec
	weight := uint16(1)
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		w, err := strconv.ParseUint(spec[at+1:], 10, 16)
		if err != nil || w == 0 {
			return nil, 0, fmt.Errorf("path %q: weight must be a positive integer", spec)
		}
		weight = uint16(w)
		segsPart = spec[:at]
	}
	segs := strings.Split(segsPart, "+")
	if len(segs) == 0 || segs[0] == "" {
		return nil, 0, fmt.Errorf("path %q: at least one segment required", spec)
	}
	return segs, weight, nil
}

// groupIDArg validates the shared --group-id flag: 0 is the no-group
// sentinel (ECMP_GROUP_NONE) and never a legal operation target.
func groupIDArg(c *cli.Context) (uint32, error) {
	groupID := uint32(c.Uint("group-id"))
	if groupID == bpf.EcmpGroupNone {
		return 0, fmt.Errorf("group-id 0 is the no-group sentinel")
	}
	return groupID, nil
}

func groupPut(c *cli.Context) error {
	pid := c.Int("pid")
	groupID, err := groupIDArg(c)
	if err != nil {
		return err
	}
	pathSpecs := c.StringSlice("path")
	if len(pathSpecs) < 1 || len(pathSpecs) > bpf.EcmpMaxPaths {
		return fmt.Errorf("need 1..%d --path specs, got %d", bpf.EcmpMaxPaths, len(pathSpecs))
	}

	maps, err := daemonMaps(pid, mapHeadendV4, mapEcmpGroup, mapEcmpPath, mapEcmpLive)
	if err != nil {
		return err
	}

	// Paths inherit mode / src_addr / policy_id from the trigger entry so the
	// tool only has to vary the segment lists.
	key, err := lpmKeyV4(c.String("from-trigger"))
	if err != nil {
		return err
	}
	var parent bpf.HeadendEntry
	if err := maps[mapHeadendV4].Lookup(key, &parent); err != nil {
		return fmt.Errorf("lookup trigger %s: %w", c.String("from-trigger"), err)
	}

	// Write order per the ECMP design: path slots first, then group info, so
	// a reader never sees num_paths pointing at an unwritten slot. Redefining
	// a group also resets its liveness bitmap: the old bits index the old
	// path set.
	info := bpf.EcmpGroupInfo{NumPaths: uint8(len(pathSpecs))}
	for i, spec := range pathSpecs {
		segs, weight, err := parsePathSpec(spec)
		if err != nil {
			return err
		}
		segments, numSegments, err := bpf.ParseSegments(segs)
		if err != nil {
			return fmt.Errorf("path %q: %w", spec, err)
		}
		entry := parent
		entry.Segments = segments
		entry.NumSegments = numSegments
		entry.GroupId = bpf.EcmpGroupNone // a path is terminal, never a group ref
		pk := bpf.EcmpPathKey{GroupId: groupID, PathIndex: uint32(i)}
		if err := maps[mapEcmpPath].Put(&pk, &entry); err != nil {
			return fmt.Errorf("put ecmp_path_map[%d,%d]: %w", groupID, i, err)
		}
		info.Weight[i] = weight
	}
	if err := maps[mapEcmpGroup].Put(&groupID, &info); err != nil {
		return fmt.Errorf("put ecmp_group_map[%d]: %w", groupID, err)
	}
	if err := maps[mapEcmpLive].Delete(&groupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("reset ecmp_live_map[%d]: %w", groupID, err)
	}
	fmt.Printf("group %d installed with %d paths\n", groupID, len(pathSpecs))
	return nil
}

func attach(c *cli.Context) error {
	groupID, err := groupIDArg(c)
	if err != nil {
		return err
	}
	maps, err := daemonMaps(c.Int("pid"), mapHeadendV4)
	if err != nil {
		return err
	}
	key, err := lpmKeyV4(c.String("trigger"))
	if err != nil {
		return err
	}
	var entry bpf.HeadendEntry
	if err := maps[mapHeadendV4].Lookup(key, &entry); err != nil {
		return fmt.Errorf("lookup trigger %s: %w", c.String("trigger"), err)
	}
	entry.GroupId = groupID
	if err := maps[mapHeadendV4].Put(key, &entry); err != nil {
		return fmt.Errorf("update trigger %s: %w", c.String("trigger"), err)
	}
	fmt.Printf("trigger %s now references group %d\n", c.String("trigger"), groupID)
	return nil
}

func liveSet(c *cli.Context) error {
	groupID, err := groupIDArg(c)
	if err != nil {
		return err
	}
	bitmap, err := strconv.ParseUint(c.String("bitmap"), 0, 64)
	if err != nil {
		return fmt.Errorf("parse bitmap %q: %w", c.String("bitmap"), err)
	}
	maps, err := daemonMaps(c.Int("pid"), mapEcmpLive)
	if err != nil {
		return err
	}
	if err := maps[mapEcmpLive].Put(&groupID, &bitmap); err != nil {
		return fmt.Errorf("put ecmp_live_map[%d]: %w", groupID, err)
	}
	fmt.Printf("group %d liveness bitmap set to %#x\n", groupID, bitmap)
	return nil
}

func liveClear(c *cli.Context) error {
	groupID, err := groupIDArg(c)
	if err != nil {
		return err
	}
	maps, err := daemonMaps(c.Int("pid"), mapEcmpLive)
	if err != nil {
		return err
	}
	if err := maps[mapEcmpLive].Delete(&groupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete ecmp_live_map[%d]: %w", groupID, err)
	}
	fmt.Printf("group %d liveness cleared (fail-open: all paths live)\n", groupID)
	return nil
}

func main() {
	pidFlag := &cli.IntFlag{Name: "pid", Usage: "pid of the target vinberod", Required: true}
	groupFlag := &cli.UintFlag{Name: "group-id", Usage: "ECMP group id (non-zero)", Required: true}

	app := &cli.App{
		Name:  "vinbero-ecmpdemo",
		Usage: "demo/test writer for the vinberod ECMP path-group maps",
		Commands: []*cli.Command{
			{
				Name:  "group-put",
				Usage: "install or replace an ECMP group; paths clone the trigger entry with their own segment list",
				Flags: []cli.Flag{
					pidFlag, groupFlag,
					&cli.StringFlag{Name: "from-trigger", Usage: "existing headend v4 trigger prefix to clone mode/src from", Required: true},
					&cli.StringSliceFlag{Name: "path", Usage: "path spec \"sid1+sid2[@weight]\" (repeatable, 1..8)", Required: true},
				},
				Action: groupPut,
			},
			{
				Name:   "attach",
				Usage:  "point an existing headend v4 trigger entry at a group",
				Flags:  []cli.Flag{pidFlag, groupFlag, &cli.StringFlag{Name: "trigger", Usage: "headend v4 trigger prefix", Required: true}},
				Action: attach,
			},
			{
				Name:   "live-set",
				Usage:  "write a group's liveness bitmap (bit i = path i up)",
				Flags:  []cli.Flag{pidFlag, groupFlag, &cli.StringFlag{Name: "bitmap", Usage: "bitmap value, e.g. 0x2", Required: true}},
				Action: liveSet,
			},
			{
				Name:   "live-clear",
				Usage:  "delete a group's liveness entry (falls back to fail-open)",
				Flags:  []cli.Flag{pidFlag, groupFlag},
				Action: liveClear,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
