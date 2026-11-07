package jsonconfig_test

import (
	"strings"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane/jsonconfig"
)

type config struct {
	jsonconfig.Version
	Name   string   `json:"name"`
	Slot   *uint32  `json:"slot"`
	Values []string `json:"values"`
	Nested *struct {
		On bool `json:"on"`
	} `json:"nested"`
}

func TestDecodeAcceptsOneVersionedObject(t *testing.T) {
	var c config
	err := jsonconfig.Decode([]byte(` {"schema_version":1,"name":"a","slot":33,"values":["x"],"nested":{"on":true}} `+"\n"), 1, &c)
	if err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != 1 || c.Name != "a" || c.Slot == nil || *c.Slot != 33 || len(c.Values) != 1 || c.Nested == nil || !c.Nested.On {
		t.Fatalf("decoded %+v", c)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"empty", ``, "config must be a JSON object"},
		{"binary", "\x08\x81\xfc\x03", "config must be a JSON object"},
		{"array", `[{"schema_version":1}]`, "config must be a JSON object"},
		{"scalar", `1`, "config must be a JSON object"},
		{"top-level null", `null`, "config must be a JSON object"},
		{"missing version", `{"name":"a"}`, "schema_version is required"},
		{"wrong version", `{"schema_version":2}`, "schema_version must be 1 (got 2)"},
		{"string version", `{"schema_version":"1"}`, "schema_version"},
		{"unknown key", `{"schema_version":1,"nmae":"a"}`, `unknown field "nmae"`},
		{"null scalar", `{"schema_version":1,"slot":null}`, "null values are not supported"},
		{"null in array", `{"schema_version":1,"values":[null]}`, "null values are not supported"},
		{"null nested", `{"schema_version":1,"nested":{"on":null}}`, "null values are not supported"},
		{"two objects", `{"schema_version":1}{"schema_version":1}`, "expected one JSON object"},
		{"trailing data", `{"schema_version":1} x`, "expected one JSON object"},
		{"truncated", `{"schema_version":1`, "configuration:"},
		{"wrong type", `{"schema_version":1,"slot":"33"}`, "slot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			err := jsonconfig.Decode([]byte(tc.input), 1, &c)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "configuration: ") {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
