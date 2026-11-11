package vinbero

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// "auto" follows the probe: a kernel that accepts BPF_FIB_LOOKUP_TBID keeps
// the main-table lookup silently; one that does not, or a probe that cannot
// run, falls back to the ingress lookup with one warning. "off" falls back
// without probing; anything else is a config error.
func TestResolveFibLookupTBID(t *testing.T) {
	for _, c := range []struct {
		name, setting string
		probe         func() (bool, error)
		off           bool
		warn          string
		wantErr       bool
	}{
		{"auto, accepted", "", func() (bool, error) { return true, nil }, false, "", false},
		{"auto, refused", "auto", func() (bool, error) { return false, nil }, true, "does not accept BPF_FIB_LOOKUP_TBID", false},
		{"auto, unknown", "auto", func() (bool, error) { return false, errors.New("no bpf") }, true, "cannot check", false},
		{"off", "off", func() (bool, error) { t.Error("off must not probe"); return true, nil }, true, "is off", false},
		{"typo", "of", func() (bool, error) { return true, nil }, false, "", true},
	} {
		core, logs := observer.New(zap.WarnLevel)
		opts := &config.BpfConfig{FibLookupTBID: c.setting}
		err := resolveFibLookupTBID(opts, c.probe, zap.New(core))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
			continue
		}
		if opts.FibLookupTBIDOff != c.off {
			t.Errorf("%s: FibLookupTBIDOff = %v, want %v", c.name, opts.FibLookupTBIDOff, c.off)
		}
		switch {
		case c.warn == "" && logs.Len() != 0:
			t.Errorf("%s: warnings %v, want none", c.name, logs.All())
		case c.warn != "" && logs.FilterMessageSnippet(c.warn).Len() != 1:
			t.Errorf("%s: warnings %v, want one containing %q", c.name, logs.All(), c.warn)
		}
	}
	cfg := &config.Config{}
	cfg.InternalConfig.BpfOptions.FibLookupTBIDOff = true
	if cfg.BpfConstants()["fib_lookup_tbid"] != uint8(0) {
		t.Errorf("constants = %v, want fib_lookup_tbid 0", cfg.BpfConstants())
	}
	if _, set := (&config.Config{}).BpfConstants()["fib_lookup_tbid"]; set {
		t.Error("the default constant set must not carry fib_lookup_tbid")
	}
}

// "rules" (or nothing) keeps the full lookup; "auto" enables the direct
// mode only with table-ID lookups, and otherwise stays "rules" with one
// warning; anything else is a config error. Only "auto" with table-ID
// lookups sets the program's constant.
func TestResolveFibLookupGlobal(t *testing.T) {
	for _, c := range []struct {
		name, setting string
		tbidOff       bool
		auto          bool
		warn          string
		wantErr       bool
	}{
		{"default", "", false, false, "", false},
		{"rules", "rules", false, false, "", false},
		{"auto", "auto", false, true, "", false},
		{"auto without table-ID lookups", "auto", true, false, "table-ID FIB lookups are off", false},
		{"rules without table-ID lookups", "rules", true, false, "", false},
		{"typo", "direct", false, false, "", true},
	} {
		core, logs := observer.New(zap.WarnLevel)
		opts := &config.BpfConfig{FibLookupGlobal: c.setting, FibLookupTBIDOff: c.tbidOff}
		err := resolveFibLookupGlobal(opts, zap.New(core))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
			continue
		}
		if opts.FibLookupGlobalAuto != c.auto {
			t.Errorf("%s: FibLookupGlobalAuto = %v, want %v", c.name, opts.FibLookupGlobalAuto, c.auto)
		}
		switch {
		case c.warn == "" && logs.Len() != 0:
			t.Errorf("%s: warnings %v, want none", c.name, logs.All())
		case c.warn != "" && logs.FilterMessageSnippet(c.warn).Len() != 1:
			t.Errorf("%s: warnings %v, want one containing %q", c.name, logs.All(), c.warn)
		}
		cfg := &config.Config{}
		cfg.InternalConfig.BpfOptions = *opts
		v, set := cfg.BpfConstants()["fib_lookup_global_auto"]
		if set != c.auto || set && v != uint8(1) {
			t.Errorf("%s: constants %v", c.name, cfg.BpfConstants())
		}
	}
}
