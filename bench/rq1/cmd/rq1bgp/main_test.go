//go:build bench

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAwaitChange(t *testing.T) {
	for _, value := range []string{"", "invalid", "0", fmt.Sprint(time.Now().Add(-time.Second).UnixNano())} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "change")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := awaitChange(path, time.Second); err == nil {
				t.Fatal("accepted invalid or expired timestamp")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "change")
	if _, err := awaitChange(path, time.Millisecond); err == nil {
		t.Fatal("missing readiness gate did not time out")
	}
	want := time.Now().Add(time.Minute).UnixNano()
	if err := os.WriteFile(path, fmt.Appendf(nil, "%d\n", want), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := awaitChange(path, time.Second)
	if err != nil || got != want {
		t.Fatalf("got %d, %v; want %d", got, err, want)
	}
}
