package netresource

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	// fileBehind is set when a write of the state file failed, so the file
	// may lack what memory holds; the next save then writes even a record
	// equal to the one in memory. Changed under writeMu.
	fileBehind atomic.Bool
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
	// configDevices are the config's VRF devices (SetConfigVrfDevices).
	configDevices []ConfigVrfDevice
	// heldMu guards running, wantOpen, heldOpen and openFailed.
	heldMu sync.Mutex
	// running is set by FinishBoot: from then on a close the guard objects
	// to is refused instead of the table being held open.
	running bool
	// wantOpen are the tables the boot found an L2 headend circuit on, with
	// that circuit; heldOpen those of them without an unreachable default
	// left, which stay open until the next start; openFailed those whose
	// failure to open was logged.
	wantOpen   map[uint32]L2CircuitOnTable
	heldOpen   map[uint32]L2CircuitOnTable
	openFailed map[uint32]bool
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
		// Each table is checked for L2 headend circuits once, over every
		// port that will be on it, before any VRF on it is processed, and
		// the routes a table that stays open has are removed first.
		checked := map[uint32]bool{}
		for i := range m.state.VRFs {
			v := m.state.VRFs[i]
			if checked[v.TableID] {
				continue
			}
			checked[v.TableID] = true
			if _, err := m.checkTable(m.state.VRFs, v.Name, v.TableID, nil, v.OptedOut()); err != nil {
				return fix("vrf "+v.Name, err)
			}
		}
		m.openHeldTablesLocked()
		for i := range m.state.VRFs {
			v := &m.state.VRFs[i]
			link, err := netlink.LinkByName(v.Name)
			if err != nil {
				m.logger.Info("Reconcile: recreating VRF",
					zap.String("name", v.Name), zap.Uint32("table_id", v.TableID))
				ifindex, added, err := m.createVrfNetlink(m.state.VRFs, v.Name, v.TableID, v.Members, v.EnableL3mdevRule, v.OptedOut())
				if err != nil {
					return fix("vrf "+v.Name, err)
				}
				v.Ifindex = ifindex
				v.addUnreachableFamilies(added)
				continue
			}
			ifindex, added, err := m.adoptVrfDevice(m.state.VRFs, link, v.Name, v.TableID, v.Members, v.EnableL3mdevRule, v.OptedOut())
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

// DropRuntimeVrfBindings records the VRF bindings with some dropped and
// writes the state file. Unlike SaveRuntimeVrfBindings, a failed write keeps
// the new record: the boot uses it to drop bindings nothing uses any more,
// and keeping the dropped ones would let a later write by another record put
// them back on disk. The next successful write of any record carries it.
func (m *ResourceManager) DropRuntimeVrfBindings(bindings []ManagedVrfBinding) error {
	c := cloneVrfBindings(bindings)
	if len(c) == 0 {
		c = nil
	}
	m.mu.Lock()
	m.state.RuntimeVrfBindings = c
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after dropping VRF bindings: %w", err)
	}
	return nil
}

// RuntimeVrfBindings returns a copy of the saved VRF bindings.
func (m *ResourceManager) RuntimeVrfBindings() []ManagedVrfBinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneVrfBindings(m.state.RuntimeVrfBindings)
}

// SaveRuntimeVrfBindings records the VRF bindings and writes the state file.
// Unlike the other records, a failed write puts the previous record back: the
// caller undoes its change on the error, so the bindings in memory and in the
// file stay the same. writeMu is held from the swap to the revert, so no
// other write can put the failed record on disk in between. A record equal
// to the saved one is not written again.
func (m *ResourceManager) SaveRuntimeVrfBindings(bindings []ManagedVrfBinding) error {
	c := cloneVrfBindings(bindings)
	if len(c) == 0 {
		c = nil
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.Lock()
	prev := m.state.RuntimeVrfBindings
	if ((len(prev) == 0 && c == nil) || reflect.DeepEqual(prev, c)) && !m.fileBehind.Load() {
		m.mu.Unlock()
		return nil
	}
	m.state.RuntimeVrfBindings = c
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(m.statePath, data)
	}
	if err != nil {
		m.fileBehind.Store(true)
		m.mu.Lock()
		m.state.RuntimeVrfBindings = prev
		m.mu.Unlock()
		return fmt.Errorf("persist state after updating VRF bindings: %w", err)
	}
	m.fileBehind.Store(false)
	return nil
}
