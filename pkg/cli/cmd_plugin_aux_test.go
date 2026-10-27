package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/urfave/cli/v2"
)

type auxPayloadCapture struct {
	vinberov1connect.PluginServiceClient
	json  string
	calls int
}

func (c *auxPayloadCapture) PluginAuxAlloc(_ context.Context, req *connect.Request[v1.PluginAuxAllocRequest]) (*connect.Response[v1.PluginAuxAllocResponse], error) {
	c.json, c.calls = req.Msg.GetJson(), c.calls+1
	return connect.NewResponse(&v1.PluginAuxAllocResponse{Index: 7}), nil
}

func (c *auxPayloadCapture) PluginAuxUpdate(_ context.Context, req *connect.Request[v1.PluginAuxUpdateRequest]) (*connect.Response[v1.PluginAuxUpdateResponse], error) {
	c.json, c.calls = req.Msg.GetJson(), c.calls+1
	return connect.NewResponse(&v1.PluginAuxUpdateResponse{}), nil
}

func TestPluginAuxJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aux.json")
	// Preserve integers exactly: encoding is the server's BTF-aware job.
	content := "{\"limit\":9007199254740993}\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"alloc", "update"} {
		for _, tc := range []struct {
			name string
			args []string
			err  string
		}{
			{name: "file", args: []string{"--json-file", path}},
			{name: "missing file", args: []string{"--json-file", filepath.Join(dir, "missing")}, err: "read --json-file"},
			{name: "empty file", args: []string{"--json-file", empty}, err: "required"},
			{name: "inline conflict", args: []string{"--json-file", path, "--json", "{}"}, err: "mutually exclusive"},
			{name: "raw conflict", args: []string{"--json-file", path, "--raw", "01"}, err: "mutually exclusive"},
			{name: "empty flag conflict", args: []string{"--json-file", path, "--json", ""}, err: "mutually exclusive"},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				capture := &auxPayloadCapture{}
				app := cli.NewApp()
				app.Commands = []*cli.Command{pluginAuxCommand()}
				app.Metadata = map[string]interface{}{clientsKey: &Clients{Plugin: capture}}
				args := []string{"test", "aux", operation, "--map-type", "endpoint", "--slot", "32"}
				if operation == "update" {
					args = append(args, "--index", "7")
				}
				err := app.Run(append(args, tc.args...))
				if tc.err != "" {
					if err == nil || !strings.Contains(err.Error(), tc.err) || capture.calls != 0 {
						t.Fatalf("err=%v, RPC calls=%d; want %q without an RPC", err, capture.calls, tc.err)
					}
				} else if err != nil || capture.calls != 1 || capture.json != content {
					t.Fatalf("err=%v calls=%d JSON=%q; want unchanged file", err, capture.calls, capture.json)
				}
			})
		}
	}
}
