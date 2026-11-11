package main

import (
	"fmt"
	"net/netip"
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/netresource"
)

// locatorStateStore keeps the locators registered over the API in the
// resource manager's state file. A locator named in the config's
// bgp.locators is the config's: it is never saved, whether or not BGP is
// enabled. Its calls run under the SID function server's lock, one at a time.
type locatorStateStore struct {
	res         *netresource.ResourceManager
	configNames []string
}

func (s locatorStateStore) SaveLocator(loc locator.Locator) error {
	if slices.Contains(s.configNames, loc.Name) {
		return nil
	}
	recs := s.res.RuntimeLocators()
	rec := locatorToRecord(loc)
	if i := slices.IndexFunc(recs, func(r netresource.ManagedLocator) bool { return r.Name == loc.Name }); i >= 0 {
		recs[i] = rec
	} else {
		recs = append(recs, rec)
	}
	return s.res.SaveRuntimeLocators(recs)
}

func (s locatorStateStore) ForgetLocator(name string) error {
	if slices.Contains(s.configNames, name) {
		return nil
	}
	recs := s.res.RuntimeLocators()
	kept := slices.DeleteFunc(slices.Clone(recs), func(r netresource.ManagedLocator) bool { return r.Name == name })
	if len(kept) == len(recs) {
		return nil
	}
	return s.res.SaveRuntimeLocators(kept)
}

func locatorToRecord(loc locator.Locator) netresource.ManagedLocator {
	return netresource.ManagedLocator{
		Name:              loc.Name,
		Prefix:            loc.Prefix.Masked().String(),
		BlockLen:          loc.BlockLen,
		NodeLen:           loc.NodeLen,
		FunctionLen:       loc.FunctionLen,
		ArgumentLen:       loc.ArgumentLen,
		Behavior:          loc.Behavior.String(),
		FunctionAutoStart: loc.FunctionAutoStart,
		FunctionAutoEnd:   loc.FunctionAutoEnd,
	}
}

func recordToLocator(r netresource.ManagedLocator) (locator.Locator, error) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return locator.Locator{}, fmt.Errorf("prefix: %w", err)
	}
	var behavior locator.Behavior
	switch r.Behavior {
	case "classic":
		behavior = locator.BehaviorClassic
	case "usid":
		behavior = locator.BehaviorUSID
	default:
		return locator.Locator{}, fmt.Errorf("behavior %q: want classic or usid", r.Behavior)
	}
	loc := locator.Locator{
		Name:              r.Name,
		Prefix:            prefix.Masked(),
		BlockLen:          r.BlockLen,
		NodeLen:           r.NodeLen,
		FunctionLen:       r.FunctionLen,
		ArgumentLen:       r.ArgumentLen,
		Behavior:          behavior,
		FunctionAutoStart: r.FunctionAutoStart,
		FunctionAutoEnd:   r.FunctionAutoEnd,
	}
	if err := loc.Validate(); err != nil {
		return locator.Locator{}, err
	}
	return loc, nil
}

// savedLocators decodes the locators the state file holds. A record that
// does not decode, or two records of one name or one prefix, stop the start,
// like a state file that does not parse.
func savedLocators(res *netresource.ResourceManager) ([]locator.Locator, error) {
	records := res.RuntimeLocators()
	out := make([]locator.Locator, 0, len(records))
	names := map[string]bool{}
	prefixes := map[netip.Prefix]bool{}
	for i, r := range records {
		loc, err := recordToLocator(r)
		if err != nil {
			return nil, fmt.Errorf("runtime_locators[%d] (%q): %w", i, r.Name, err)
		}
		if names[loc.Name] || prefixes[loc.Prefix] {
			return nil, fmt.Errorf("runtime_locators[%d] (%q): a second locator of that name or prefix", i, r.Name)
		}
		names[loc.Name], prefixes[loc.Prefix] = true, true
		out = append(out, loc)
	}
	return out, nil
}

// restoreLocators registers the locators made over the API again, in the
// order they were registered, after the stored SID reservations (so Add
// restores the functions a plugin holds) and the config's locators. The
// config wins: a saved locator with the name of one in bgp.locators, or the
// prefix of one the config registered, is not restored and is removed from
// the state file. Any other refusal stops the start: a create over the API
// would have been refused the same way, so the state file needs repair. The
// locators are restored whether BGP is enabled or not, as LocatorService
// runs either way.
func restoreLocators(mgr *locator.Manager, saved []locator.Locator, configNames []string, res *netresource.ResourceManager, lg *zap.Logger) error {
	configPrefixes := map[netip.Prefix]string{}
	for _, l := range mgr.List() {
		configPrefixes[l.Prefix.Masked()] = l.Name
	}
	kept := make([]netresource.ManagedLocator, 0, len(saved))
	dropped := 0
	for _, loc := range saved {
		if slices.Contains(configNames, loc.Name) {
			lg.Warn("the config file declares this locator; the one saved from the API is not restored and is removed from the state file",
				zap.String("locator", loc.Name))
			dropped++
			continue
		}
		if owner, ok := configPrefixes[loc.Prefix]; ok {
			lg.Warn("a locator of the config file has this prefix; the one saved from the API is not restored and is removed from the state file",
				zap.String("locator", loc.Name), zap.String("prefix", loc.Prefix.String()), zap.String("config_locator", owner))
			dropped++
			continue
		}
		l := loc
		if err := mgr.Add(&l); err != nil {
			return fmt.Errorf("runtime_locators %q: %w (repair the state file, settings.state_path, and restart)", loc.Name, err)
		}
		kept = append(kept, locatorToRecord(l))
	}
	if dropped > 0 {
		if err := res.DropRuntimeLocators(kept); err != nil {
			lg.Warn("the dropped locators stay in the state file until the next successful write of it; one comes back if the config stops declaring it before that",
				zap.Error(err))
		}
	}
	if len(kept) > 0 {
		lg.Info("locators restored from the state file", zap.Int("locators", len(kept)))
	}
	return nil
}
