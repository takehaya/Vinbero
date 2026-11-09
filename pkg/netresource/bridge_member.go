package netresource

import (
	"errors"
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

var (
	// ErrNoMember: the port to add does not exist.
	ErrNoMember = errors.New("member interface not found")
	// ErrPersist: the kernel change was made but the state file could not
	// be written; a retry writes it.
	ErrPersist = errors.New("persist state")
	// ErrEnslavedElsewhere: the port already has another master.
	ErrEnslavedElsewhere = errors.New("port is enslaved to another device")
)

// enslave makes master the port's master. A port already enslaved to master
// is left alone. A port enslaved to another device is moved when move is
// set (members named at create or attach time, which the caller placed
// deliberately) and refused with ErrEnslavedElsewhere otherwise (members
// added at runtime, whose name may have been reused by an unrelated port).
func enslave(port, master netlink.Link, move bool) error {
	switch cur := port.Attrs().MasterIndex; {
	case cur == master.Attrs().Index:
		return nil
	case cur != 0 && !move:
		return fmt.Errorf("%w: interface %s is enslaved to another device (ifindex %d); release it first",
			ErrEnslavedElsewhere, port.Attrs().Name, cur)
	}
	if err := netlink.LinkSetMaster(port, master); err != nil {
		return fmt.Errorf("enslave %s to %s: %w", port.Attrs().Name, master.Attrs().Name, err)
	}
	return nil
}

// AddBridgeMember enslaves one more port to a managed bridge and records it
// as a runtime member. Adding a port that is already a member succeeds.
func (m *ResourceManager) AddBridgeMember(bridge, member string) error {
	if _, ok := m.GetBridgeByName(bridge); !ok {
		return fmt.Errorf("bridge %s is not managed", bridge)
	}
	br, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("bridge %s lookup: %w", bridge, err)
	}
	port, err := netlink.LinkByName(member)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return fmt.Errorf("%w: %s", ErrNoMember, member)
	}
	if err != nil {
		return fmt.Errorf("member %s lookup: %w", member, err)
	}
	if err := enslave(port, br, false); err != nil {
		return err
	}
	m.mu.Lock()
	for i := range m.state.Bridges {
		e := &m.state.Bridges[i]
		if e.Name == bridge && !slices.Contains(e.Members, member) && !slices.Contains(e.RuntimeMembers, member) {
			e.RuntimeMembers = append(e.RuntimeMembers, member)
		}
	}
	m.mu.Unlock()
	// Persist even when nothing changed, so a retry after a failed write
	// does not report success with the member still missing on disk.
	if err := m.persist(); err != nil {
		return fmt.Errorf("%w after adding member %s to bridge %s: %v", ErrPersist, member, bridge, err)
	}
	m.logger.Info("Added bridge member", zap.String("bridge", bridge), zap.String("member", member))
	return nil
}

// RemoveBridgeMember releases a port from a managed bridge and drops it from
// the bridge's members, whether it was declared at attach time or added at
// runtime. A port that is gone, or no longer enslaved to this bridge, only
// loses its state entry; removing a port that is not a member succeeds.
func (m *ResourceManager) RemoveBridgeMember(bridge, member string) error {
	if _, ok := m.GetBridgeByName(bridge); !ok {
		return fmt.Errorf("bridge %s is not managed", bridge)
	}
	br, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("bridge %s lookup: %w", bridge, err)
	}
	port, err := netlink.LinkByName(member)
	switch {
	case err == nil:
		if port.Attrs().MasterIndex == br.Attrs().Index {
			if err := netlink.LinkSetNoMaster(port); err != nil {
				return fmt.Errorf("release %s from %s: %w", member, bridge, err)
			}
		}
	case errors.As(err, &netlink.LinkNotFoundError{}):
	default:
		return fmt.Errorf("member %s lookup: %w", member, err)
	}
	isMember := func(n string) bool { return n == member }
	m.mu.Lock()
	for i := range m.state.Bridges {
		e := &m.state.Bridges[i]
		if e.Name == bridge {
			e.Members = slices.DeleteFunc(e.Members, isMember)
			e.RuntimeMembers = slices.DeleteFunc(e.RuntimeMembers, isMember)
		}
	}
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		return fmt.Errorf("%w after removing member %s from bridge %s: %v", ErrPersist, member, bridge, err)
	}
	m.logger.Info("Removed bridge member", zap.String("bridge", bridge), zap.String("member", member))
	return nil
}

// enslaveRuntimeMembers re-enslaves a reconciled bridge's runtime members
// and returns the ones to keep. A runtime member that is gone, or whose name
// now belongs to a port enslaved elsewhere, is dropped with a warning: its
// workload went away while the daemon was down, and that must not block the
// boot. A member that fails for another reason (a lookup or enslave error)
// is kept with a warning, so a transient failure does not forget it; the
// next start tries again. Called by Reconcile with m.mu held.
func (m *ResourceManager) enslaveRuntimeMembers(bridge string, ifindex uint32, members []string) []string {
	if len(members) == 0 {
		return members
	}
	br, err := netlink.LinkByIndex(int(ifindex))
	if err != nil {
		m.logger.Warn("Reconcile: bridge lookup failed; keeping its runtime members unenslaved",
			zap.String("bridge", bridge), zap.Error(err))
		return members
	}
	kept := make([]string, 0, len(members))
	for _, member := range members {
		port, err := netlink.LinkByName(member)
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			m.logger.Warn("Reconcile: dropping vanished bridge member",
				zap.String("bridge", bridge), zap.String("member", member))
			continue
		}
		if err == nil {
			err = enslave(port, br, false)
		}
		switch {
		case err == nil:
		case errors.Is(err, ErrEnslavedElsewhere):
			m.logger.Warn("Reconcile: dropping bridge member",
				zap.String("bridge", bridge), zap.String("member", member), zap.Error(err))
			continue
		default:
			m.logger.Warn("Reconcile: bridge member not enslaved; keeping it for the next start",
				zap.String("bridge", bridge), zap.String("member", member), zap.Error(err))
		}
		kept = append(kept, member)
	}
	return kept
}
