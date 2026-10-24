package cli

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/urfave/cli/v2"
)

// A behavior is conventionally written in hex (RFC 8986 numbers them that
// way), so reading 0x0013 as decimal 13 would claim a different one.
func TestParseBehaviorFlags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []uint32
	}{
		{name: "empty", in: nil},
		{name: "decimal", in: []string{"19"}, want: []uint32{19}},
		{name: "hex", in: []string{"0x0013"}, want: []uint32{0x13}},
		{name: "uppercase hex", in: []string{"0XFE01"}, want: []uint32{0xFE01}},
		{name: "mixed", in: []string{"0xFE01", "65000"}, want: []uint32{0xFE01, 65000}},
		{name: "whitespace", in: []string{" 0xFE01 "}, want: []uint32{0xFE01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBehaviorFlags(tt.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// A codepoint is 16 bits; a larger value must be refused rather than
// truncated into someone else's behavior.
func TestParseBehaviorFlagsRejectsBadValues(t *testing.T) {
	for _, in := range []string{"", "nonsense", "0x10000", "70000", "-1"} {
		if _, err := parseBehaviorFlags([]string{in}); err == nil {
			t.Errorf("value %q was accepted", in)
		}
	}
}

// uint is 64 bits on the platforms this runs on, so a slot number wider
// than the request field wraps silently. --endpoint-slot 4294967328 would
// arrive at the daemon as 32, pass its range check, and grant a slot the
// operator never named.
func TestSlotFlagsThatDoNotFitAreRefused(t *testing.T) {
	if _, err := uintSliceToUint32("endpoint-slot", []uint{math.MaxUint32 + 1}); err == nil {
		t.Fatal("a slot number wider than 32 bits was accepted")
	}
	got, err := uintSliceToUint32("endpoint-slot", []uint{32, 33})
	if err != nil {
		t.Fatalf("ordinary slots were refused: %v", err)
	}
	if len(got) != 2 || got[0] != 32 || got[1] != 33 {
		t.Fatalf("converted %v, want the slots as given", got)
	}
}

func TestCplaneArtifactFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--name", "test", "--wasm", "missing.wasm", "--native", "mup-composition", "--native-version", "1"},
		{"--name", "test", "--wasm", "missing.wasm", "--native-version", "1"},
		{"--name", "test", "--wasm", "missing.wasm", "--native", ""},
		{"--name", "test", "--wasm", ""},
	} {
		app := cli.NewApp()
		app.Commands = []*cli.Command{cplaneSubcommand()}
		err := app.Run(append([]string{"test", "cplane", "register"}, args...))
		if err == nil || (!strings.Contains(err.Error(), "cannot be combined") && !strings.Contains(err.Error(), "requires a module path")) {
			t.Fatalf("unexpected invalid artifact result: %v", err)
		}
	}
}

type cplaneRegisterCapture struct {
	vinberov1connect.PluginServiceClient
	request *v1.CplanePluginRegisterRequest
}

func (c *cplaneRegisterCapture) CplanePluginRegister(_ context.Context, req *connect.Request[v1.CplanePluginRegisterRequest]) (*connect.Response[v1.CplanePluginRegisterResponse], error) {
	c.request = req.Msg
	return connect.NewResponse(&v1.CplanePluginRegisterResponse{}), nil
}

func TestCplaneDefaultNativeAndExplicitWASM(t *testing.T) {
	module := filepath.Join(t.TempDir(), "plugin.wasm")
	if err := os.WriteFile(module, []byte("module"), 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.wasm")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, backend, id, version, module string
		args                               []string
	}{
		{name: "default", backend: "native"},
		{name: "alias", backend: "native", id: "bgp-observer", args: []string{"--native", "bgp-observer"}},
		{name: "pinned", backend: "native", id: "bgp-observer", version: "1", args: []string{"--native", "bgp-observer", "--native-version", "1"}},
		{name: "version only", backend: "native", version: "1", args: []string{"--native-version", "1"}},
		{name: "wasm", backend: "wasm", module: "module", args: []string{"--wasm", module}},
		{name: "empty wasm stays wasm", backend: "wasm", args: []string{"--wasm", empty}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &cplaneRegisterCapture{}
			app := cli.NewApp()
			app.Commands = []*cli.Command{cplaneSubcommand()}
			app.Metadata = map[string]interface{}{clientsKey: &Clients{Plugin: capture}}
			args := append([]string{"test", "cplane", "register", "--name", "bgp-observer"}, tc.args...)
			if err := app.Run(args); err != nil {
				t.Fatal(err)
			}
			r := capture.request
			if r == nil || r.Backend != tc.backend || r.NativeId != tc.id || r.NativeVersion != tc.version || string(r.Wasm) != tc.module || r.Name != "bgp-observer" {
				t.Fatalf("unexpected registration: %v", r)
			}
		})
	}
}
