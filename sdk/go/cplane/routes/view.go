// Package routes retains context-authorized GoBGP paths across update and replay.
package routes

import (
	"fmt"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"sort"
)

type Limits struct{ MaxPaths, MaxBytes int }
type Status struct {
	Ready, Replaying bool
	Revision         uint64
	Issue            string
}

// Entry is borrowed read-only during Range. Do not mutate the packet model.
type Entry struct {
	Key      cplane.BGPPathKey
	Family   string
	Contexts []string
	Path     *gobgppath.Path
}
type stored struct {
	entry Entry
	bytes int
}
type View struct {
	catalog map[string]map[string]bool
	paths   map[cplane.BGPPathKey]stored
	limits  Limits
	bytes   int
	status  Status
}

func NewView(config cplane.InputConfig, limits Limits) (*View, error) {
	if config.Version != 1 || config.Codec != cplane.BGPPathCodec {
		return nil, fmt.Errorf("routes: context input API v1 required")
	}
	if limits.MaxPaths == 0 {
		limits.MaxPaths = 4096
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = 8 << 20
	}
	if limits.MaxPaths < 1 || limits.MaxBytes < 1 {
		return nil, fmt.Errorf("routes: positive limits required")
	}
	v := &View{catalog: map[string]map[string]bool{}, paths: map[cplane.BGPPathKey]stored{}, limits: limits}
	for _, ctx := range config.Contexts {
		if ctx.Name == "" || v.catalog[ctx.Name] != nil || len(ctx.Families) == 0 {
			return nil, fmt.Errorf("routes: invalid context %q", ctx.Name)
		}
		families := map[string]bool{}
		for _, f := range ctx.Families {
			families[f] = true
		}
		v.catalog[ctx.Name] = families
	}
	return v, nil
}
func (v *View) Status() Status                     { return v.status }
func (v *View) Allows(context, family string) bool { return v.catalog[context][family] }
func (v *View) Len() int                           { return len(v.paths) }
func (v *View) Range(visit func(Entry)) {
	if !v.status.Ready {
		return
	}
	keys := make([]cplane.BGPPathKey, 0, len(v.paths))
	for k := range v.paths {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return KeyLess(keys[i], keys[j]) })
	for _, k := range keys {
		e := v.paths[k].entry
		e.Contexts = append([]string(nil), e.Contexts...)
		visit(e)
	}
}
func KeyLess(a, b cplane.BGPPathKey) bool {
	if a.Codec != b.Codec {
		return a.Codec < b.Codec
	}
	if a.AFI != b.AFI {
		return a.AFI < b.AFI
	}
	if a.SAFI != b.SAFI {
		return a.SAFI < b.SAFI
	}
	if a.Destination != b.Destination {
		return a.Destination < b.Destination
	}
	if a.Peer != b.Peer {
		return a.Peer < b.Peer
	}
	return a.PathID < b.PathID
}
func (v *View) incomplete(sequence uint64, reason string) cplane.EventResult {
	v.status.Ready = false
	v.status.Issue = reason
	return cplane.EventResult{Sequence: sequence, Disposition: cplane.InputIncomplete, Reason: reason}
}

// Update removes the previous key before decoding or accepting its replacement.
// Only a new, complete BGP replay recovers an incomplete view.
func (v *View) Update(events []cplane.Event) []cplane.EventResult {
	var results []cplane.EventResult
	for _, ev := range events {
		switch ev.Kind {
		case cplane.EventStartOfReplay:
			if ev.ReplaySource == cplane.BGPSource {
				v.paths = map[cplane.BGPPathKey]stored{}
				v.bytes = 0
				v.status = Status{Replaying: true, Revision: v.status.Revision + 1}
			}
		case cplane.EventEndOfReplay:
			if ev.ReplaySource == cplane.BGPSource && v.status.Replaying {
				v.status.Replaying = false
				v.status.Ready = v.status.Issue == ""
				v.status.Revision++
			}
		case cplane.EventRoute:
			if v.status.Issue != "" {
				continue
			}
			r := ev.Route
			k, ok := r.BGPKey()
			if !ok {
				results = append(results, v.incomplete(ev.Sequence, "routes: input has no usable identity"))
				continue
			}
			if old, held := v.paths[k]; held {
				v.bytes -= old.bytes
				delete(v.paths, k)
			}
			v.status.Revision++
			if r.Withdraw || len(r.Contexts) == 0 {
				continue
			}
			valid := true
			contexts := make([]string, 0, len(r.Contexts))
			seen := map[string]bool{}
			for _, ctx := range r.Contexts {
				if !v.Allows(ctx, r.Family) {
					valid = false
					break
				}
				if !seen[ctx] {
					contexts = append(contexts, ctx)
					seen[ctx] = true
				}
			}
			if !valid {
				results = append(results, v.incomplete(ev.Sequence, "routes: input names an ungranted context or family"))
				continue
			}
			path, err := gobgppath.Decode(r)
			if err != nil {
				results = append(results, cplane.EventResult{Sequence: ev.Sequence, Disposition: cplane.Quarantine, Reason: err.Error()})
				continue
			}
			size := len(k.Codec) + len(k.Destination) + len(k.Peer) + len(r.BGPPath.NLRI) + 128
			for _, a := range r.BGPPath.Attributes {
				size += len(a) + 24
			}
			for _, ctx := range contexts {
				size += len(ctx) + 16
			}
			if len(v.paths) >= v.limits.MaxPaths || size > v.limits.MaxBytes-v.bytes {
				results = append(results, v.incomplete(ev.Sequence, "routes: input budget exceeded"))
				continue
			}
			sort.Strings(contexts)
			v.paths[k] = stored{Entry{k, r.Family, contexts, path}, size}
			v.bytes += size
		}
	}
	return results
}

// Invalidate suppresses all reads until the next complete replay.
func (v *View) Invalidate(sequence uint64, reason string) cplane.EventResult {
	return v.incomplete(sequence, reason)
}
