package netresource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

type ManagedState struct {
	VRFs    []ManagedVrf    `json:"vrfs"`
	Bridges []ManagedBridge `json:"bridges"`
	// Devices are the interfaces attached to the data plane at runtime
	// (DeviceAttach). internal.devices entries are not recorded here.
	Devices []ManagedDevice `json:"devices,omitempty"`
	// VrfObjects are the VRF objects' identities and runtime facets. Nil on
	// a file written before they were recorded.
	VrfObjects *ManagedVrfObjects `json:"vrf_objects,omitempty"`
	// RuntimeVrfBindings are the VRF <-> BGP bindings made over the API,
	// ordered by VRF name. The bindings of the config file are not here.
	// Absent on a file written before they were recorded, which reads as
	// none saved.
	RuntimeVrfBindings []ManagedVrfBinding `json:"runtime_vrf_bindings,omitempty"`
	// RuntimeL2Circuits are the L2 headend circuits made over the API
	// (HeadendL2Create), ordered by ifindex and VLAN. Absent on a file
	// written before they were recorded, which reads as none saved.
	RuntimeL2Circuits []ManagedL2Circuit `json:"runtime_l2_circuits,omitempty"`
}

// ManagedVrfBinding is one VRF's BGP binding as it was in memory. The legacy
// route-target lists are kept next to the families they derive from, so a
// restored binding lists them in the same order.
type ManagedVrfBinding struct {
	VRFName   string   `json:"vrf_name"`
	RD        string   `json:"rd,omitempty"`
	ImportRTs []string `json:"import_rts,omitempty"`
	ExportRTs []string `json:"export_rts,omitempty"`
	// Families is null for a binding that never had a family and {} for
	// one whose last family was removed; both come back as they were.
	Families            map[string]ManagedFamilyPolicy `json:"families"`
	Redistribute        []string                       `json:"redistribute,omitempty"`
	MaxPrefixes         uint32                         `json:"max_prefixes,omitempty"`
	DefaultLocator      string                         `json:"default_locator,omitempty"`
	MupGTP4SourcePrefix string                         `json:"mup_gtp4_source_prefix,omitempty"`
}

// ManagedFamilyPolicy is one family's route targets, in registration order.
type ManagedFamilyPolicy struct {
	RouteTargets []ManagedRouteTarget `json:"route_targets"`
}

// ManagedRouteTarget is one route target and its direction ("import",
// "export" or "both").
type ManagedRouteTarget struct {
	RT        string `json:"rt"`
	Direction string `json:"direction"`
}

// UnmarshalJSON refuses a field this version does not know. A binding record
// written by a newer version may carry a policy this one would silently drop,
// and the binding would then import routes it was meant to keep out.
func (b *ManagedVrfBinding) UnmarshalJSON(data []byte) error {
	type plain ManagedVrfBinding
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p plain
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("runtime_vrf_bindings: %w (a newer vinberod may have written it)", err)
	}
	*b = ManagedVrfBinding(p)
	return nil
}

func cloneVrfBindings(in []ManagedVrfBinding) []ManagedVrfBinding {
	if in == nil {
		return nil
	}
	out := make([]ManagedVrfBinding, len(in))
	for i, b := range in {
		b.ImportRTs = slices.Clone(b.ImportRTs)
		b.ExportRTs = slices.Clone(b.ExportRTs)
		b.Redistribute = slices.Clone(b.Redistribute)
		if b.Families != nil {
			fams := make(map[string]ManagedFamilyPolicy, len(b.Families))
			for fam, fp := range b.Families {
				fams[fam] = ManagedFamilyPolicy{RouteTargets: slices.Clone(fp.RouteTargets)}
			}
			b.Families = fams
		}
		out[i] = b
	}
	return out
}

// ManagedVrfObjects is the vrf_id allocator and one record per VRF object.
// Both fields are required: without the watermark the ids of deleted VRFs
// could be handed out again, and without the entries every saved id and AC
// would be lost, so a record missing either is refused like a file that does
// not parse.
type ManagedVrfObjects struct {
	NextVrfID uint32             `json:"next_vrf_id"`
	Entries   []ManagedVrfObject `json:"entries"`
}

func (o *ManagedVrfObjects) UnmarshalJSON(data []byte) error {
	var raw struct {
		NextVrfID *uint32             `json:"next_vrf_id"`
		Entries   *[]ManagedVrfObject `json:"entries"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.NextVrfID == nil || *raw.NextVrfID == 0 {
		return errors.New("vrf_objects: next_vrf_id is missing or 0")
	}
	if raw.Entries == nil {
		return errors.New("vrf_objects: entries is missing")
	}
	o.NextVrfID, o.Entries = *raw.NextVrfID, *raw.Entries
	return nil
}

// clone copies o, with an empty rather than nil Entries so it encodes as [].
func (o *ManagedVrfObjects) clone() *ManagedVrfObjects {
	c := &ManagedVrfObjects{NextVrfID: o.NextVrfID, Entries: make([]ManagedVrfObject, 0, len(o.Entries))}
	for _, e := range o.Entries {
		e.RuntimeACs = slices.Clone(e.RuntimeACs)
		c.Entries = append(c.Entries, e)
	}
	return c
}

// ManagedVrfObject is what a VRF object keeps across a restart, by name. A
// VRF without a kernel device has a record here and none in ManagedState.VRFs.
// State the VRF manager declares at runtime for one VRF belongs in this
// record, a field per facet. The BGP binding, which another manager writes,
// is in ManagedState.RuntimeVrfBindings.
type ManagedVrfObject struct {
	Name  string `json:"name"`
	VrfID uint32 `json:"vrf_id"`
	// RuntimeACs are the ACs added over the API. Unlike the ACs of the
	// config, one whose interface is gone is skipped with a warning.
	RuntimeACs []ManagedAC `json:"runtime_acs,omitempty"`
	// Config is set when the VRF came from the boot-time load (the config
	// file, or a device or bridge record) rather than from the API. Such a
	// VRF is not restored once the config no longer declares it and it holds
	// no AC, device or bridge; its id stays retired.
	Config bool `json:"config,omitempty"`
}

// ManagedAC is one ingress access circuit.
type ManagedAC struct {
	Interface string `json:"interface"`
	VLAN      uint16 `json:"vlan"`
}

// ManagedDevice is a runtime-attached device: the interface name and the
// XDP mode it was attached in (config spelling, never empty).
type ManagedDevice struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type ManagedVrf struct {
	Name             string   `json:"name"`
	TableID          uint32   `json:"table_id"`
	Members          []string `json:"members"`
	EnableL3mdevRule bool     `json:"enable_l3mdev_rule"`
	// NoUnreachableDefault records whether the table goes without the
	// unreachable default that a create, an adopt and Reconcile otherwise
	// add. Nil (a record written before the field existed) is not decided
	// yet: Reconcile takes the config's setting for the VRF, or adds the
	// routes when the config does not declare it, and records the result.
	NoUnreachableDefault *bool  `json:"no_unreachable_default,omitempty"`
	Ifindex              uint32 `json:"ifindex"`
	// UnreachableDefaultAdded are the families ("ipv4", "ipv6") whose
	// unreachable default Vinbero added to the table itself. Only those are
	// ever removed: a route that was already there (the operator's own) is
	// left alone.
	UnreachableDefaultAdded []string `json:"unreachable_default_added,omitempty"`
}

// OptedOut reports whether the VRF's table goes without the unreachable
// default. An undecided record reads as not opted out.
func (v ManagedVrf) OptedOut() bool {
	return v.NoUnreachableDefault != nil && *v.NoUnreachableDefault
}

func (v *ManagedVrf) setNoUnreachableDefault(no bool) {
	v.NoUnreachableDefault = &no
}

func (v *ManagedVrf) addUnreachableFamilies(families []string) {
	for _, f := range families {
		if !slices.Contains(v.UnreachableDefaultAdded, f) {
			v.UnreachableDefaultAdded = append(v.UnreachableDefaultAdded, f)
		}
	}
}

type ManagedBridge struct {
	Name    string   `json:"name"`
	BdID    uint16   `json:"bd_id"`
	Members []string `json:"members"`
	Ifindex uint32   `json:"ifindex"`
	// VRF is the name of the VRF object this bridge is attached to as its L2
	// facet. Empty on records written before the facet existed; boot seeding
	// then falls back to the bridge's own name as a synthetic VRF. To move
	// such a bridge under its real VRF, stop the daemon, set this field in
	// the state file, and restart (detaching instead would delete the kernel
	// bridge and disrupt traffic).
	VRF string `json:"vrf,omitempty"`
	// RuntimeMembers are ports added one at a time (VrfBridgeMemberAdd),
	// typically veths that come and go with their workload. Unlike Members,
	// a runtime member that is gone at boot is dropped instead of failing
	// the reconcile.
	RuntimeMembers []string `json:"runtime_members,omitempty"`
}

func loadState(path string) (*ManagedState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ManagedState{VRFs: []ManagedVrf{}, Bridges: []ManagedBridge{}}, nil
		}
		return nil, err
	}
	var state ManagedState
	if err := json.Unmarshal(data, &state); err != nil {
		// Refuse to guess which kernel devices the daemon owns: starting with
		// an empty state would silently abandon every managed VRF / bridge.
		return nil, fmt.Errorf("parse state: %w (repair the file or move it aside and restart)", err)
	}
	return &state, nil
}

// persist snapshots the state under the read lock and writes it to the state
// file atomically. Callers must NOT hold m.mu (RWMutex is not reentrant); the
// file I/O happens outside the lock so a slow disk does not stall readers.
// writeMu spans the snapshot and the rename: the VRF service and the device
// service persist independently, and an older snapshot must not be renamed
// in after a newer one.
func (m *ResourceManager) persist() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.RLock()
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	return writeFileAtomic(m.statePath, data)
}

// writeFileAtomic writes data to path through a same-directory temp file and
// a rename, fsyncing both the file and the directory. A crash or an ENOSPC
// mid-write leaves the previous file intact instead of a truncated one --
// the old os.WriteFile (O_TRUNC in place) turned exactly that crash window
// into a state file the next boot refuses to parse.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on every early return; a no-op once the rename won.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp uses 0600; the state file is device names / table IDs, kept
	// world-readable like the old direct write.
	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsync the directory so the rename itself survives a crash.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
