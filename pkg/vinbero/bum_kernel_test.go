package vinbero

import (
	"os"
	"path/filepath"
	"testing"
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
