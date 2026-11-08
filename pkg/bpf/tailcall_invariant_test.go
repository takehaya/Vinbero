package bpf

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// headendL2TailCall matches a bpf_tail_call into headend_l2_progs, however
// it is spaced.
var headendL2TailCall = regexp.MustCompile(`bpf_tail_call\s*\(\s*\w+\s*,\s*&\s*headend_l2_progs\b`)

// TestHeadendL2SingleTailCallSite enforces the invariant documented on
// try_bd_peer_lookup (src/dispatch/l2_headend.c): the translation unit may
// hold only one lexical bpf_tail_call into headend_l2_progs. A second one,
// even in dead code, makes the kernel drop the first site's redirected
// frames without any trace, which no packet test is guaranteed to catch.
func TestHeadendL2SingleTailCallSite(t *testing.T) {
	root := filepath.Join("..", "..", "src")
	var sites []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".c" && ext != ".h" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if headendL2TailCall.MatchString(code) {
				sites = append(sites, filepath.ToSlash(path)+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	if len(sites) != 1 || !strings.Contains(sites[0], "src/dispatch/l2_headend.c:") {
		t.Fatalf("want exactly one bpf_tail_call into headend_l2_progs, in src/dispatch/l2_headend.c; found %d: %v",
			len(sites), sites)
	}
}

// bareRedirect matches a bpf_redirect() call (not bpf_redirect_map).
var bareRedirect = regexp.MustCompile(`\bbpf_redirect\s*\(`)

// TestXDPRedirectsGoThroughHelper enforces the invariant documented in
// src/core/xdp_redirect.h: every XDP redirect of the main program goes
// through xdp_redirect_dev, so that in native xdp-mode BUM a redirect to an
// uplink carries the same devmap egress program as the BUM copies. A bare
// bpf_redirect to an uplink would make a whole NAPI poll's BUM copies leave
// that uplink unencapsulated. TC code is exempt (no devmap bulk queues).
func TestXDPRedirectsGoThroughHelper(t *testing.T) {
	root := filepath.Join("..", "..", "src")
	exempt := map[string]bool{
		"core/xdp_redirect.h": true, // the helper itself
		"l2vpn/tc_bum.h":      true,
		"l2vpn/tc_prog.c":     true,
	}
	var sites []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".c" && ext != ".h" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if exempt[filepath.ToSlash(rel)] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if bareRedirect.MatchString(code) {
				sites = append(sites, filepath.ToSlash(path)+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) > 0 {
		t.Errorf("bare bpf_redirect in XDP code (use xdp_redirect_dev): %v", sites)
	}
}
