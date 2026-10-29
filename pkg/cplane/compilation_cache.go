package cplane

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"sync"

	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/tetratelabs/wazero"
	"google.golang.org/protobuf/proto"
)

var errManagerClosed = errors.New("cplane: manager is closed")

// A cache holds only the current module of one registration name. A replacement
// borrows it while both generations exist; incompatible code keeps no history.
type compilationCacheOwner struct {
	mu    sync.Mutex
	cache wazero.CompilationCache
	refs  int
}

type compilationCacheLease struct {
	mu       sync.Mutex
	owner    *compilationCacheOwner
	released bool
}

func (l *compilationCacheLease) retain() *compilationCacheLease {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if l.owner.refs == 0 {
		return nil
	}
	l.owner.refs++
	return &compilationCacheLease{owner: l.owner}
}

func (l *compilationCacheLease) release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil
	}
	l.released = true
	l.mu.Unlock()
	l.owner.mu.Lock()
	l.owner.refs--
	last := l.owner.refs == 0
	l.owner.mu.Unlock()
	if last {
		return l.owner.cache.Close(ctx)
	}
	return nil
}

// Caller holds registerMu. Teardown cannot close a borrowed cache while the
// candidate is being built, and a retired generation cannot issue a new lease.
func (m *Manager) registrationCompilationCache(reg Registration) (wazero.CompilationCache, *compilationCacheLease) {
	if reg.Backend != BackendWASM {
		return nil, nil
	}
	m.mu.Lock()
	if old := m.plugins[reg.Name]; sameCompilationAuthority(old, reg) {
		if lease := old.cacheLease.retain(); lease != nil {
			cache := old.compilationCache
			m.mu.Unlock()
			return cache, lease
		}
	}
	m.mu.Unlock()
	cache := wazero.NewCompilationCache()
	return cache, &compilationCacheLease{owner: &compilationCacheOwner{cache: cache, refs: 1}}
}

func sameCompilationAuthority(old *plugin, reg Registration) bool {
	return old != nil && !old.dead && old.reg.Backend == BackendWASM && reg.Backend == BackendWASM &&
		bytes.Equal(old.reg.Module, reg.Module) &&
		wasm.DefaultLimits().Merge(old.reg.Limits) == wasm.DefaultLimits().Merge(reg.Limits) &&
		proto.Equal(old.reg.Input, reg.Input) &&
		reflect.DeepEqual(old.reg.Families, reg.Families) &&
		reflect.DeepEqual(old.reg.Behaviors, reg.Behaviors) &&
		reflect.DeepEqual(old.reg.Capabilities, reg.Capabilities) && reflect.DeepEqual(old.reg.Scope, reg.Scope)
}

// Cache compatibility must compare owned authority, not caller-mutable slices.
// Input was already cloned by parseInputPolicy; Module and Config by Register.
func ownRegistrationAuthority(reg *Registration) {
	reg.Capabilities = maps.Clone(reg.Capabilities)
	reg.Families = slices.Clone(reg.Families)
	reg.Behaviors = slices.Clone(reg.Behaviors)
	reg.Scope.Locators = slices.Clone(reg.Scope.Locators)
	reg.Scope.VRFs = slices.Clone(reg.Scope.VRFs)
	reg.Scope.HeadendPrefixes = slices.Clone(reg.Scope.HeadendPrefixes)
	reg.Scope.HeadendV4Slots = slices.Clone(reg.Scope.HeadendV4Slots)
	reg.Scope.HeadendV6Slots = slices.Clone(reg.Scope.HeadendV6Slots)
	reg.Scope.EndpointSlots = slices.Clone(reg.Scope.EndpointSlots)
}
