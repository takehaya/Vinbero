package cplane

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Quotas bound what one plugin may hold at once.
//
// The capability model says what a plugin may do; a quota says how much.
// The two answer different questions: a plugin granted `headend` is meant
// to write headend entries, and the question a quota settles is whether a
// bug in it can fill the map and take the entries of every other writer
// with it.
//
// Zero means the default; a negative value means unbounded, which is a
// deliberate escape hatch rather than a value anyone should reach for.
type Quotas struct {
	// MaxHeadendEntries caps the headend entries one plugin may own,
	// counting v4 and v6 together.
	MaxHeadendEntries int
	// MaxAdvertisedRoutes caps the routes one plugin may originate. It is
	// the quota that reaches other routers: a plugin that advertises
	// without bound spends its peers' memory, not only this node's.
	MaxAdvertisedRoutes int
	// MaxLocalSIDs caps the SIDs one plugin may hold. A locator is finite
	// and shared with vinbero's own allocations.
	MaxLocalSIDs int
}

// DefaultQuotas are generous enough that an ordinary plugin never meets
// them and small enough that a runaway one is stopped while the data
// plane is still usable.
func DefaultQuotas() Quotas {
	return Quotas{
		MaxHeadendEntries:   4096,
		MaxAdvertisedRoutes: 4096,
		MaxLocalSIDs:        256,
	}
}

// withDefaults fills zero fields from DefaultQuotas.
func (q Quotas) withDefaults() Quotas {
	d := DefaultQuotas()
	if q.MaxHeadendEntries == 0 {
		q.MaxHeadendEntries = d.MaxHeadendEntries
	}
	if q.MaxAdvertisedRoutes == 0 {
		q.MaxAdvertisedRoutes = d.MaxAdvertisedRoutes
	}
	if q.MaxLocalSIDs == 0 {
		q.MaxLocalSIDs = d.MaxLocalSIDs
	}
	return q
}

// QuotaError is a declaration refused for being larger than the plugin's
// quota.
//
// It reports Denied so the runtime maps it to the status a plugin can act
// on: a plugin told its set was too large can narrow it, where one told
// the host failed can only give up. That distinction is the whole reason
// the guest sees two different statuses.
type QuotaError struct {
	What     string
	Declared int
	Quota    int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s: %d declared, quota %d", e.What, e.Declared, e.Quota)
}

// Denied marks this as a policy refusal rather than a host failure.
func (e *QuotaError) Denied() bool { return true }

// limit reports the effective cap, and whether one applies at all.
func limitOf(n int) (int, bool) {
	if n < 0 {
		return 0, false
	}
	return n, true
}

// PluginStats is what an operator can see about one running plugin.
//
// A plugin that has fallen behind, that is restarting in a loop, or that
// is quietly refusing every event looks identical from outside to one
// that has nothing to do. These counters are what tell those apart, which
// is the whole reason a sandboxed component needs them: nothing else about
// it is observable.
type PluginStats struct {
	Name string
	// Capabilities and Behaviors are what it was granted and what it
	// claimed, so an operator can check a deployment without reading back
	// the registration.
	Capabilities []string
	Behaviors    []uint16
	// DroppedEvents counts event batches discarded because the plugin
	// could not keep up.
	DroppedEvents uint64
	// Restarts counts instances lost to a trap or an overrun budget since
	// the last successful delivery.
	Restarts int
	// Quarantined counts events the plugin asked the host to stop
	// redelivering.
	Quarantined uint64
	// Snapshots counts rib replays delivered to it.
	Snapshots uint64
	// Dead reports a plugin left stopped after repeated failures. Its
	// state is still installed; it is simply no longer being fed.
	Dead bool
	// PendingDeclarations is how many of its declarations are waiting on
	// something that does not exist yet, retried in the background. A
	// plugin stuck this way looks idle in every other counter.
	PendingDeclarations int
	// HeadendEntries, AdvertisedRoutes and LocalSIDs are what it holds
	// right now, against the quota that bounds each.
	HeadendEntries   int
	AdvertisedRoutes int
	LocalSIDs        int
	Quotas           Quotas
	// Since is when the current instance started.
	Since time.Time
}

// counters is the mutable half of a plugin's statistics.
type counters struct {
	mu          sync.Mutex
	quarantined uint64
	snapshots   uint64
	since       time.Time
}

func newCounters() *counters {
	return &counters{since: time.Now()}
}

func (c *counters) addQuarantined(n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quarantined += uint64(n)
}

func (c *counters) addSnapshot() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshots++
}

// restarted records that the instance was replaced, which resets the
// clock: Since describes the instance that is running, not the
// registration.
func (c *counters) restarted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.since = time.Now()
}

func (c *counters) snapshot() (quarantined, snapshots uint64, since time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.quarantined, c.snapshots, c.since
}

// Stats returns what is known about every running plugin, sorted by name
// so two snapshots can be diffed.
func (m *Manager) Stats() []PluginStats {
	m.mu.Lock()
	plugins := make([]*plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	m.mu.Unlock()

	out := make([]PluginStats, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, m.statsFor(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// StatsFor returns what is known about one plugin.
func (m *Manager) StatsFor(name string) (PluginStats, bool) {
	m.mu.Lock()
	p, ok := m.plugins[name]
	m.mu.Unlock()
	if !ok {
		return PluginStats{}, false
	}
	return m.statsFor(p), true
}

// statsFor gathers one plugin's numbers.
func (m *Manager) statsFor(p *plugin) PluginStats {
	m.mu.Lock()
	restarts := p.restarts
	dead := p.dead
	reg := p.reg
	m.mu.Unlock()

	quarantined, snapshots, since := p.counters.snapshot()
	owner := p.ops.Owner()
	return PluginStats{
		Name:                p.name,
		Capabilities:        reg.Capabilities.Names(),
		Behaviors:           reg.Behaviors,
		DroppedEvents:       p.worker.droppedCount(),
		Restarts:            restarts,
		Quarantined:         quarantined,
		Snapshots:           snapshots,
		Dead:                dead,
		PendingDeclarations: p.ops.PendingDeclarations(),
		HeadendEntries:      m.leases.CountOf(LeaseHeadendV4, owner) + m.leases.CountOf(LeaseHeadendV6, owner),
		AdvertisedRoutes:    m.advertise.LiveCount(owner),
		LocalSIDs:           m.localSIDs.LiveCount(owner),
		Quotas:              m.quotas,
		Since:               since,
	}
}
