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

// funcStart matches the first line of a function definition at column 0
// and captures its name.
var funcStart = regexp.MustCompile(`^[A-Za-z_][^;]*?\b([A-Za-z_]\w*)\s*\([^;]*$`)

// blockComment matches a C block comment.
var blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

// TestXDPRedirectsGoThroughHelper enforces the invariant documented in
// src/core/xdp_redirect.h: every XDP redirect of the main program goes
// through xdp_redirect_dev, so that in native xdp-mode BUM a redirect to a
// device the BUM devmaps send to carries the same devmap egress program as
// the BUM copies. A bare bpf_redirect there would make a whole NAPI poll's
// BUM copies to that device skip the program. Only the helper itself and
// the TC clone encapsulation (no devmap bulk queues in TC) may call it.
func TestXDPRedirectsGoThroughHelper(t *testing.T) {
	root := filepath.Join("..", "..", "src")
	exempt := map[string]string{ // file -> the one function allowed
		"core/xdp_redirect.h": "xdp_redirect_dev",
		"l2vpn/tc_bum.h":      "tc_do_single_pe_encap_impl",
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
		allowed := exempt[filepath.ToSlash(rel)]
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Blank block comments out, keeping their newlines.
		src := blockComment.ReplaceAllStringFunc(string(data), func(c string) string {
			return strings.Repeat("\n", strings.Count(c, "\n"))
		})
		fn := ""
		for i, line := range strings.Split(src, "\n") {
			code, _, _ := strings.Cut(line, "//")
			if m := funcStart.FindStringSubmatch(code); m != nil {
				fn = m[1]
			}
			if bareRedirect.MatchString(code) && (allowed == "" || fn != allowed) {
				sites = append(sites, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+" ("+fn+")")
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
