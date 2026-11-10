package vinbero

import (
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The load-time check warns when the kernel refuses BPF_FIB_LOOKUP_TBID or
// cannot be asked, and is silent when it accepts it.
func TestWarnWithoutFibLookupTBID(t *testing.T) {
	for _, c := range []struct {
		name  string
		probe func() (bool, error)
		warn  string
	}{
		{"accepted", func() (bool, error) { return true, nil }, ""},
		{"refused", func() (bool, error) { return false, nil }, "does not accept BPF_FIB_LOOKUP_TBID"},
		{"unknown", func() (bool, error) { return false, errors.New("no bpf") }, "cannot check bpf_fib_lookup"},
	} {
		core, logs := observer.New(zap.WarnLevel)
		warnWithoutFibLookupTBID(c.probe, zap.New(core))
		switch {
		case c.warn == "" && logs.Len() != 0:
			t.Errorf("%s: warnings %v, want none", c.name, logs.All())
		case c.warn != "" && logs.FilterMessageSnippet(c.warn).Len() != 1:
			t.Errorf("%s: warnings %v, want one containing %q", c.name, logs.All(), c.warn)
		}
	}
}
