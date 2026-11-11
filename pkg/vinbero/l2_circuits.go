package vinbero

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// l2CircuitMaps is the headend_l2 surface the circuits are written to.
// *bpf.MapOperations satisfies it.
type l2CircuitMaps interface {
	CreateHeadendL2(ifindex uint32, vlanID uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte) error
	DeleteHeadendL2(ifindex uint32, vlanID uint16) error
	GetHeadendL2(ifindex uint32, vlanID uint16) (*bpf.HeadendEntry, error)
	GetHeadendL2Esi(ifindex uint32, vlanID uint16) ([bpf.ESILen]byte, error)
	DeleteHeadendL2Where(match func(ifindex uint32) bool) (int, error)
}

// l2CircuitStore keeps the circuit records. *netresource.ResourceManager
// satisfies it.
type l2CircuitStore interface {
	L2Circuits() []netresource.ManagedL2Circuit
	SaveL2Circuits([]netresource.ManagedL2Circuit) error
	DropL2Circuits([]netresource.ManagedL2Circuit) error
}

// LinkID is what a circuit knows of its interface.
type LinkID struct {
	Name    string
	Ifindex uint32
	MAC     net.HardwareAddr
}

// L2Circuit is one L2 headend circuit to create: its interface, VLAN, entry
// and ESI (all-zero for a single-homed circuit).
type L2Circuit struct {
	Link  LinkID
	VLAN  uint16
	Entry *bpf.HeadendEntry
	ESI   [bpf.ESILen]byte
}

// ErrL2InterfaceGone is returned by Create when the interface was deleted
// while the circuit was written.
var ErrL2InterfaceGone = errors.New("the interface was deleted during the create")

// L2Circuits keeps the L2 headend circuits made over the API in headend_l2
// and in the state file together. Every change of either goes through it and
// runs under its lock: the RPCs, the link watcher and the restore at boot.
type L2Circuits struct {
	mu    sync.Mutex
	maps  l2CircuitMaps
	store l2CircuitStore // nil: nothing is saved
	// linkByIndex looks an interface up; found is false when there is none.
	// Tests replace it.
	linkByIndex func(ifindex uint32) (link LinkID, found bool, err error)
	logger      *zap.Logger
}

// NewL2Circuits returns the circuit book over maps and store. A nil store
// saves nothing: the circuits live in the map only, as with no state file.
func NewL2Circuits(maps l2CircuitMaps, store l2CircuitStore, logger *zap.Logger) *L2Circuits {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &L2Circuits{maps: maps, store: store, linkByIndex: netlinkLinkByIndex, logger: logger}
}

func netlinkLinkByIndex(ifindex uint32) (LinkID, bool, error) {
	l, err := netlink.LinkByIndex(int(ifindex))
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return LinkID{}, false, nil
	}
	if err != nil {
		return LinkID{}, false, err
	}
	a := l.Attrs()
	return LinkID{Name: a.Name, Ifindex: uint32(a.Index), MAC: a.HardwareAddr}, true, nil
}

// circuitRecord is the saved form of c.
func circuitRecord(c L2Circuit) netresource.ManagedL2Circuit {
	r := netresource.ManagedL2Circuit{
		Interface: c.Link.Name,
		Ifindex:   c.Link.Ifindex,
		VLAN:      c.VLAN,
		Mode:      v1.Srv6HeadendBehavior(c.Entry.Mode).String(),
		Segments:  bpf.FormatSegments(c.Entry.Segments, c.Entry.NumSegments),
		BdID:      c.Entry.BdId,
		ESI:       bpf.FormatESI(c.ESI),
	}
	if len(c.Link.MAC) > 0 {
		r.MAC = c.Link.MAC.String()
	}
	if c.Entry.SrcAddr != ([bpf.IPv6AddrLen]uint8{}) {
		r.SrcAddr = bpf.FormatIPv6(c.Entry.SrcAddr)
	}
	if len(r.Segments) == 0 {
		r.Segments = nil
	}
	return r
}

// circuitEntry is the entry and ESI a record restores.
func circuitEntry(r netresource.ManagedL2Circuit) (*bpf.HeadendEntry, [bpf.ESILen]byte, error) {
	var esi [bpf.ESILen]byte
	mode, ok := v1.Srv6HeadendBehavior_value[r.Mode]
	if !ok || mode == int32(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_UNSPECIFIED) {
		return nil, esi, fmt.Errorf("mode %q is not a headend behavior", r.Mode)
	}
	src, err := bpf.ParseIPv6(r.SrcAddr)
	if err != nil {
		return nil, esi, err
	}
	segs, n, err := bpf.ParseSegments(r.Segments)
	if err != nil {
		return nil, esi, err
	}
	if esi, err = bpf.ParseESI(r.ESI); err != nil {
		return nil, esi, err
	}
	return &bpf.HeadendEntry{Mode: uint8(mode), NumSegments: n, SrcAddr: src, Segments: segs, BdId: r.BdID}, esi, nil
}

func indexOfCircuit(recs []netresource.ManagedL2Circuit, ifindex uint32, vlan uint16) int {
	return slices.IndexFunc(recs, func(r netresource.ManagedL2Circuit) bool {
		return r.Ifindex == ifindex && r.VLAN == vlan
	})
}

// Create writes the circuit and saves it. The entry it replaces, if any, is
// read first: when the write, the check that the interface still exists or
// the save fails, the map gets that entry back, so a failed create changes
// neither the map nor the state file.
func (c *L2Circuits) Create(ckt L2Circuit) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ifindex, vlan := ckt.Link.Ifindex, ckt.VLAN
	prev, err := c.maps.GetHeadendL2(ifindex, vlan)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("read the entry the circuit replaces: %w", err)
	}
	var prevESI [bpf.ESILen]byte
	if prev != nil {
		if prevESI, err = c.maps.GetHeadendL2Esi(ifindex, vlan); err != nil {
			return fmt.Errorf("read the ESI of the entry the circuit replaces: %w", err)
		}
	}
	undo := func(cause error) error {
		var uerr error
		if prev != nil {
			uerr = c.maps.CreateHeadendL2(ifindex, vlan, prev, prevESI)
		} else if uerr = c.maps.DeleteHeadendL2(ifindex, vlan); errors.Is(uerr, ebpf.ErrKeyNotExist) {
			uerr = nil
		}
		if uerr != nil {
			return fmt.Errorf("%w; putting the previous entry back failed: %v", cause, uerr)
		}
		return cause
	}
	if err := c.maps.CreateHeadendL2(ifindex, vlan, ckt.Entry, ckt.ESI); err != nil {
		return undo(err)
	}
	// The interface can vanish between the lookup and the write, and the
	// link watcher would then not see the entry. A rename the watcher
	// recorded since the lookup is kept: the record takes the name and
	// address the interface has now.
	if link, found, err := c.linkByIndex(ifindex); err == nil && !found {
		return undo(ErrL2InterfaceGone)
	} else if err == nil {
		ckt.Link.Name, ckt.Link.MAC = link.Name, link.MAC
	}
	if c.store == nil {
		return nil
	}
	recs := c.store.L2Circuits()
	rec := circuitRecord(ckt)
	if i := indexOfCircuit(recs, ifindex, vlan); i >= 0 {
		recs[i] = rec
	} else {
		recs = append(recs, rec)
	}
	if err := c.store.SaveL2Circuits(recs); err != nil {
		return undo(fmt.Errorf("the circuit is not created: %w", err))
	}
	return nil
}

// Delete removes the circuit of an interface and VLAN. A saved circuit is
// first marked as being deleted, then its entry goes, then its record: a
// crash in between leaves a record the next start finishes instead of
// restoring. An entry without a record (left in pinned maps by a version
// that did not save circuits) is removed from the map only. With neither,
// the error wraps ebpf.ErrKeyNotExist.
func (c *L2Circuits) Delete(ifindex uint32, vlan uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var recs []netresource.ManagedL2Circuit
	i := -1
	if c.store != nil {
		recs = c.store.L2Circuits()
		i = indexOfCircuit(recs, ifindex, vlan)
	}
	if i >= 0 && !recs[i].Deleting {
		recs[i].Deleting = true
		if err := c.store.SaveL2Circuits(recs); err != nil {
			return fmt.Errorf("the circuit is not deleted: %w", err)
		}
	}
	err := c.maps.DeleteHeadendL2(ifindex, vlan)
	if errors.Is(err, ebpf.ErrKeyNotExist) && i >= 0 {
		err = nil
	}
	if err != nil {
		if i >= 0 {
			return fmt.Errorf("%w (the state file marks the circuit as being deleted: repeat the delete, or the next start removes it)", err)
		}
		return err
	}
	if i < 0 {
		return nil
	}
	recs = slices.Delete(recs, i, i+1)
	if err := c.store.SaveL2Circuits(recs); err != nil {
		return fmt.Errorf("the circuit is removed from the data plane, but the state file still marks it as being deleted (repeat the delete, or the next start removes it): %w", err)
	}
	return nil
}

// DeleteVanished removes the saved circuit of a name that no longer resolves
// on vlan, when no interface holds its ifindex any more. It reports whether
// there was such a circuit; the caller reports the name as not found when
// there was not.
func (c *L2Circuits) DeleteVanished(name string, vlan uint16) (bool, error) {
	if c.store == nil {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := c.store.L2Circuits()
	i := -1
	for j, r := range recs {
		if r.Interface != name || r.VLAN != vlan {
			continue
		}
		_, found, err := c.linkByIndex(r.Ifindex)
		if err != nil {
			return false, fmt.Errorf("look up ifindex %d: %w", r.Ifindex, err)
		}
		if !found {
			i = j
			break
		}
	}
	if i < 0 {
		return false, nil
	}
	if err := c.maps.DeleteHeadendL2(recs[i].Ifindex, vlan); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return true, err
	}
	recs = slices.Delete(recs, i, i+1)
	if err := c.store.SaveL2Circuits(recs); err != nil {
		return true, fmt.Errorf("the circuit is removed from the data plane, but not from the state file (the next start drops it): %w", err)
	}
	return true, nil
}

// Flush removes every circuit, the ones without a record included, the same
// way Delete removes one.
func (c *L2Circuits) Flush() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var recs []netresource.ManagedL2Circuit
	if c.store != nil {
		recs = c.store.L2Circuits()
		for i := range recs {
			recs[i].Deleting = true
		}
		if err := c.store.SaveL2Circuits(recs); err != nil {
			return 0, fmt.Errorf("the circuits are not flushed: %w", err)
		}
	}
	n, err := c.maps.DeleteHeadendL2Where(func(uint32) bool { return true })
	if err != nil {
		if len(recs) > 0 {
			err = fmt.Errorf("%w (the state file marks the circuits as being deleted: repeat the flush, or the next start removes them)", err)
		}
		return uint32(n), err
	}
	if len(recs) == 0 {
		return uint32(n), nil
	}
	if err := c.store.SaveL2Circuits(nil); err != nil {
		return uint32(n), fmt.Errorf("the circuits are removed from the data plane, but the state file still marks them as being deleted (repeat the flush, or the next start removes them): %w", err)
	}
	return uint32(n), nil
}

// deleteWhere removes the entries and records of the interfaces match
// selects, for the link watcher: the interface is gone. A record whose
// removal is not written stays in the file, where the next start finds its
// ifindex gone and drops it.
func (c *L2Circuits) deleteWhere(match func(ifindex uint32) bool) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.maps.DeleteHeadendL2Where(match)
	if c.store == nil {
		return n, err
	}
	recs := c.store.L2Circuits()
	kept := slices.DeleteFunc(slices.Clone(recs), func(r netresource.ManagedL2Circuit) bool { return match(r.Ifindex) })
	if len(kept) != len(recs) {
		if serr := c.store.DropL2Circuits(kept); serr != nil {
			c.logger.Warn("the circuits of a deleted interface stay in the state file until its next write; the next start drops them",
				zap.Error(serr))
		}
	}
	return n, err
}

// follow records a new name or hardware address of an interface that has
// circuits, so a rename the daemon saw does not keep the circuit from being
// restored.
func (c *L2Circuits) follow(link LinkID) {
	if c.store == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := c.store.L2Circuits()
	mac := ""
	if len(link.MAC) > 0 {
		mac = link.MAC.String()
	}
	changed := false
	for i := range recs {
		if recs[i].Ifindex != link.Ifindex || (recs[i].Interface == link.Name && recs[i].MAC == mac) {
			continue
		}
		c.logger.Info("L2 headend circuit follows its interface",
			zap.Uint32("ifindex", link.Ifindex), zap.String("was", recs[i].Interface), zap.String("now", link.Name),
			zap.String("mac", mac))
		recs[i].Interface, recs[i].MAC = link.Name, mac
		changed = true
	}
	if !changed {
		return
	}
	if err := c.store.DropL2Circuits(recs); err != nil {
		c.logger.Warn("the new interface name of an L2 headend circuit is not saved yet; until it is, the next start does not restore the circuit",
			zap.Error(err))
	}
}

// restore brings the saved circuits back into headend_l2 at boot, before
// the resource reconcile reads the map to decide which VRF tables stay open,
// and before the data plane is attached:
//
//   - a circuit marked as being deleted loses its entry and its record;
//   - a circuit is restored, entry and ESI, only on the interface that has
//     the saved ifindex, name and hardware address. Otherwise the interface
//     is gone, was made again under the same name, or another one took the
//     ifindex: the record is dropped and the entry under the saved key (left
//     in pinned maps) is removed, so no other interface inherits it.
//
// Entries without a record (pinned by a version that did not save circuits)
// are left as they are. A record that does not decode, a lookup or a map
// write that fails stops the start; a failed write of the state file is a
// warning, like the other boot-time saves.
func (c *L2Circuits) restore() error {
	if c.store == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := c.store.L2Circuits()
	seen := map[[2]uint32]bool{}
	for i, r := range recs {
		k := [2]uint32{r.Ifindex, uint32(r.VLAN)}
		if seen[k] {
			return fmt.Errorf("runtime_l2_circuits[%d]: a second circuit on ifindex %d VLAN %d", i, r.Ifindex, r.VLAN)
		}
		seen[k] = true
		if _, _, err := circuitEntry(r); err != nil {
			return fmt.Errorf("runtime_l2_circuits[%d] (%s VLAN %d): %w", i, r.Interface, r.VLAN, err)
		}
	}
	kept := make([]netresource.ManagedL2Circuit, 0, len(recs))
	for _, r := range recs {
		why := ""
		if r.Deleting {
			why = "its delete had not finished"
		} else {
			link, found, err := c.linkByIndex(r.Ifindex)
			switch {
			case err != nil:
				return fmt.Errorf("L2 circuit on %s VLAN %d: look up ifindex %d: %w", r.Interface, r.VLAN, r.Ifindex, err)
			case !found:
				why = "its interface is gone"
			case link.Name != r.Interface:
				why = fmt.Sprintf("ifindex %d is now %q", r.Ifindex, link.Name)
			case r.MAC != "" && !sameMAC(link.MAC, r.MAC), r.MAC == "" && len(link.MAC) > 0:
				why = fmt.Sprintf("the interface's hardware address is now %s", link.MAC)
			}
		}
		if why != "" {
			if err := c.maps.DeleteHeadendL2(r.Ifindex, r.VLAN); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("L2 circuit on %s VLAN %d: remove its entry: %w", r.Interface, r.VLAN, err)
			}
			if r.Deleting {
				c.logger.Info("L2 headend circuit removed: its delete had not finished",
					zap.String("interface", r.Interface), zap.Uint16("vlan", r.VLAN))
			} else {
				c.logger.Warn("L2 headend circuit not restored and forgotten; create it again on the interface it belongs to",
					zap.String("interface", r.Interface), zap.Uint32("ifindex", r.Ifindex), zap.Uint16("vlan", r.VLAN),
					zap.String("reason", why))
			}
			continue
		}
		entry, esi, _ := circuitEntry(r)
		if err := c.maps.CreateHeadendL2(r.Ifindex, r.VLAN, entry, esi); err != nil {
			return fmt.Errorf("restore the L2 circuit on %s VLAN %d: %w", r.Interface, r.VLAN, err)
		}
		kept = append(kept, r)
	}
	if len(kept) != len(recs) {
		if err := c.store.DropL2Circuits(kept); err != nil {
			c.logger.Warn("the L2 circuits dropped at boot stay in the state file until its next write", zap.Error(err))
		}
	}
	if len(kept) > 0 {
		c.logger.Info("L2 headend circuits restored from the state file", zap.Int("circuits", len(kept)))
	}
	return nil
}

func sameMAC(hw net.HardwareAddr, saved string) bool {
	want, err := net.ParseMAC(saved)
	return err == nil && bytes.Equal(hw, want)
}
