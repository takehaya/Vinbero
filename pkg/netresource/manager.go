package netresource

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

type ResourceManager struct {
	logger    *zap.Logger
	statePath string
	state     *ManagedState
	mu        sync.RWMutex
	writeMu   sync.Mutex // serializes persist (see there)
	// configNoUnreachable is the config's no_unreachable_default by VRF
	// name (SetConfigUnreachableDefault); Reconcile applies it.
	configNoUnreachable map[string]bool
	noIPv6Logged        atomic.Bool // the "no IPv6" line is logged once
	// tablesOpen leaves every VRF table without the unreachable default
	// (SetTablesClosed(false)).
	tablesOpen bool
	// closeGuard finds an L2 headend circuit a table's unreachable default
	// would cut off (SetTableCloseGuard); nil finds none.
	closeGuard TableCloseGuard
	// heldMu guards running and heldOpen.
	heldMu sync.Mutex
	// running is set by FinishBoot: from then on a close the guard objects
	// to is refused instead of the table being held open.
	running bool
	// heldOpen are the tables the boot left open for an L2 headend circuit,
	// with that circuit; they stay open until the next start.
	heldOpen map[uint32]L2CircuitOnTable
}

func NewResourceManager(statePath string, logger *zap.Logger) (*ResourceManager, error) {
	state, err := loadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load state from %s: %w", statePath, err)
	}

	return &ResourceManager{
		logger:    logger,
		statePath: statePath,
		state:     state,
	}, nil
}

// Reconcile makes every state entry real: a missing device is recreated, an
// existing one is adopted with the same validation and convergence the Create
// paths apply (type check, up, missing members enslaved). Fail-closed: an
// entry that cannot be materialized aborts the boot with a repair hint --
// continuing would persist a stale ifindex that the FDB watcher, the EVPN
// enable/replay machinery, and the SID-reference delete guards all key on,
// so they would silently operate on a dead (or kernel-reused) index.
// Called once at startup before any API requests.
func (m *ResourceManager) Reconcile() error {
	fix := func(name string, err error) error {
		return fmt.Errorf("reconcile %s from state %s: %w (restore the device / its members, or remove the entry from the state file, then restart)", name, m.statePath, err)
	}

	// The locked section is a closure so the unlock is deferred (panic-safe)
	// while persist still runs outside the lock (RWMutex is not reentrant).
	empty := false
	err := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		empty = len(m.state.Bridges) == 0 && len(m.state.VRFs) == 0

		for i := range m.state.Bridges {
			b := &m.state.Bridges[i]
			link, err := netlink.LinkByName(b.Name)
			if err != nil {
				m.logger.Info("Reconcile: recreating bridge",
					zap.String("name", b.Name), zap.Uint16("bd_id", b.BdID))
				ifindex, err := createBridgeNetlink(b.Name, b.Members)
				if err != nil {
					return fix("bridge "+b.Name, err)
				}
				b.Ifindex = ifindex
				b.RuntimeMembers = m.enslaveRuntimeMembers(b.Name, ifindex, b.RuntimeMembers)
				continue
			}
			ifindex, err := adoptBridgeDevice(link, b.Name, b.Members)
			if err != nil {
				return fix("bridge "+b.Name, err)
			}
			b.Ifindex = ifindex
			b.RuntimeMembers = m.enslaveRuntimeMembers(b.Name, ifindex, b.RuntimeMembers)
		}

		// Every record's unreachable-default setting is settled first (the
		// config's wins), so no table gets a route the config has opted out of,
		// and a record that now opts out gives back the routes it added.
		for i := range m.state.VRFs {
			if err := m.decideUnreachableLocked(i); err != nil {
				return fix("vrf "+m.state.VRFs[i].Name, err)
			}
		}
		// Tables an L2 headend circuit holds open are found before any route
		// is added, so none of them is closed even for a moment.
		for i := range m.state.VRFs {
			v := &m.state.VRFs[i]
			if v.OptedOut() {
				continue
			}
			if _, err := m.tableMayClose(v.Name, v.TableID, v.Members); err != nil {
				return fix("vrf "+v.Name, err)
			}
		}
		for i := range m.state.VRFs {
			v := &m.state.VRFs[i]
			link, err := netlink.LinkByName(v.Name)
			if err != nil {
				m.logger.Info("Reconcile: recreating VRF",
					zap.String("name", v.Name), zap.Uint32("table_id", v.TableID))
				ifindex, added, err := m.createVrfNetlink(v.Name, v.TableID, v.Members, v.EnableL3mdevRule, v.OptedOut())
				if err != nil {
					return fix("vrf "+v.Name, err)
				}
				v.Ifindex = ifindex
				v.addUnreachableFamilies(added)
				continue
			}
			ifindex, added, err := m.adoptVrfDevice(link, v.Name, v.TableID, v.Members, v.EnableL3mdevRule, v.OptedOut())
			if err != nil {
				return fix("vrf "+v.Name, err)
			}
			v.Ifindex = ifindex
			v.addUnreachableFamilies(added)
		}
		m.openHeldTablesLocked()
		return nil
	}()
	if err != nil {
		return err
	}
	if empty {
		// Nothing to protect and nothing to refresh: skipping the persist
		// keeps a deployment that uses no VRF/bridge features booting even
		// when the state directory is unwritable (read-only /var/lib, a
		// container without the volume). With entries present a persist
		// failure IS boot-fatal -- their refreshed ifindexes must land.
		return nil
	}
	return m.persist()
}

// GetBridgeByName returns the managed bridge info by name. Members is a copy
// so the caller cannot alias the state-owned backing array.
func (m *ResourceManager) GetBridgeByName(name string) (ManagedBridge, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.state.Bridges {
		if b.Name == name {
			b.Members = slices.Clone(b.Members)
			b.RuntimeMembers = slices.Clone(b.RuntimeMembers)
			return b, true
		}
	}
	return ManagedBridge{}, false
}

// GetVrfByName returns the managed VRF info by name. Members is a copy so
// the caller cannot alias the state-owned backing array.
func (m *ResourceManager) GetVrfByName(name string) (ManagedVrf, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, v := range m.state.VRFs {
		if v.Name == name {
			v.Members = slices.Clone(v.Members)
			v.UnreachableDefaultAdded = slices.Clone(v.UnreachableDefaultAdded)
			return v, true
		}
	}
	return ManagedVrf{}, false
}

// VrfObjects returns a copy of the VRF objects' record. It is nil on a file
// written before they were recorded.
func (m *ResourceManager) VrfObjects() *ManagedVrfObjects {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.VrfObjects == nil {
		return nil
	}
	return m.state.VrfObjects.clone()
}

// SaveVrfObjects records the VRF objects and writes the state file. On a
// persist failure the record stays in memory and the next persist writes it.
func (m *ResourceManager) SaveVrfObjects(objs ManagedVrfObjects) error {
	c := objs.clone()
	m.mu.Lock()
	m.state.VrfObjects = c
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after updating VRF objects: %w", err)
	}
	return nil
}
