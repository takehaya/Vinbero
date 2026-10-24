//go:build bench

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestStartHandshake(t *testing.T) {
	path := filepath.Join(t.TempDir(), "start")
	ns := time.Now().Add(time.Second).UnixNano()
	if err := os.WriteFile(path, []byte(strconv.FormatInt(ns, 10)), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := awaitStart(path, time.Second)
	if err != nil || got != ns {
		t.Fatalf("future start %d %v", got, err)
	}
	for _, value := range []string{"invalid", "0", strconv.FormatInt(time.Now().Add(-time.Second).UnixNano(), 10)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := awaitStart(path, time.Second); err == nil {
			t.Fatalf("accepted invalid start %q", value)
		}
	}
	if _, err := awaitStart(filepath.Join(t.TempDir(), "missing"), time.Millisecond); err == nil {
		t.Fatal("missing handshake did not time out")
	}
}
