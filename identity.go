// Package buildidentity fingerprints the statically linked control-plane source
// and dependency pins for fail-closed restoration of native registrations.
package buildidentity

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
)

// Embed sources automatically so ordinary go build cannot reuse a stale generated
// fingerprint. Tests are embedded by the globs but excluded from the digest.
//
//go:embed identity.go go.mod go.sum sdk/go/cplane/*.go sdk/go/cplane/*/*.go pkg/cplane/native/*.go
var sources embed.FS

// Source identifies the shared SDK, native adapter, dependency pins and compiler.
// Paths and bytes are length-framed; WalkDir visits paths in lexical order.
var Source = sourceDigest()

func sourceDigest() string {
	h := sha256.New()
	frame := func(data []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(data)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(data)
	}
	frame([]byte(runtime.Version()))
	if err := fs.WalkDir(sources, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := sources.ReadFile(path)
		if err != nil {
			return err
		}
		frame([]byte(path))
		frame(data)
		return nil
	}); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
