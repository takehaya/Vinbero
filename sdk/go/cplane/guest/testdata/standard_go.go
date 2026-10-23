package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	var mode string
	guest.Register(guest.Handlers{
		Configure: func(config []byte) error {
			mode = string(config)
			if mode == "panic" {
				fmt.Fprint(os.Stderr, "configuration-only diagnostic")
			}
			if string(config) == "sleep" {
				time.Sleep(time.Hour)
			}
			if mode != "check" {
				return nil
			}
			if env := os.Environ(); len(env) != 0 {
				return fmt.Errorf("unexpected guest environment: %v", env)
			}
			if _, err := os.ReadFile("/etc/passwd"); err == nil {
				return fmt.Errorf("host filesystem exposed")
			}
			if _, err := os.Stdin.Read(make([]byte, 1)); err != io.EOF {
				return fmt.Errorf("stdin: %v", err)
			}
			if _, err := fmt.Fprintln(os.Stdout, "discarded stdout"); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(os.Stderr, "discarded stderr"); err != nil {
				return err
			}
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				return err
			}
			if random == [32]byte{} {
				return fmt.Errorf("empty randomness")
			}
			start := time.Now()
			if start.Year() < 2000 {
				return fmt.Errorf("fake wall clock: %s", start)
			}
			time.Sleep(5 * time.Millisecond)
			if time.Since(start) < 5*time.Millisecond {
				return fmt.Errorf("timer returned early")
			}
			raw, err := json.Marshal(struct{ Ready bool }{true})
			if err != nil {
				return err
			}
			var decoded map[string]bool
			if err := json.Unmarshal(raw, &decoded); err != nil {
				return err
			}
			if !decoded["Ready"] {
				return fmt.Errorf("JSON round trip failed")
			}
			return nil
		},
		Events: func([]cplane.Event) []cplane.EventResult {
			if mode == "panic" {
				fmt.Fprint(os.Stderr, "retained panic diagnostic\n", strings.Repeat("x", 8192))
				panic("deliberate diagnostic panic")
			}
			// Force collection while the host owns an allocated input buffer.
			runtime.GC()
			guest.Log(cplane.LogInfo, "Go GC completed")
			return nil
		},
		Tick: func(int64) { time.Sleep(time.Hour) },
	})
}

func main() {}
