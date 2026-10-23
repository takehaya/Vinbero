package wasm

import (
	"testing"

	"github.com/tetratelabs/wazero/experimental/wazerotest"
)

func TestGoMemoryLimitUsesEffectiveCap(t *testing.T) {
	for _, tc := range []struct {
		name            string
		host, moduleMax uint32
		want            string
	}{
		{"default unbounded module", 256, 0, "8388608B"},
		{"smaller module maximum", 512, 256, "8388608B"},
		{"smaller host maximum", 256, 512, "8388608B"},
		{"one page", 1, 1, "32768B"},
		{"four GiB does not overflow", 65536, 0, "2147483648B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := &wazerotest.Memory{Max: tc.moduleMax}
			if got := goMemoryLimit(tc.host, memory.Definition()); got != tc.want {
				t.Fatalf("GC target: got %q, want %q", got, tc.want)
			}
		})
	}
}
