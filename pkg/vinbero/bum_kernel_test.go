package vinbero

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckBumXDPKernel(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"not an RT kernel (no file)", filepath.Join(dir, "missing"), false},
		{"PREEMPT_RT", write("rt", "1\n"), true},
		{"realtime reads 0", write("nort", "0\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkBumXDPKernel(tc.path); (err != nil) != tc.wantErr {
				t.Errorf("checkBumXDPKernel = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestBumXDPUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		private bool
		err     error
		want    string // substring of the reason; "" means available
	}{
		{"private copies", true, nil, ""},
		{"shared copies", false, nil, "share one packet buffer"},
		{"probe failed", false, errors.New("no veth"), "could not run: no veth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bumXDPUnavailable(func(time.Duration) (bool, error) { return tc.private, tc.err })
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Errorf("bumXDPUnavailable = %q, want %q", got, tc.want)
			}
		})
	}
}
