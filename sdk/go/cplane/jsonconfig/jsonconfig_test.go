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
	Items []struct {
		ID int `json:"id"`
	} `json:"items"`
	Free map[string]any `json:"free"`
}

func TestDecodeAcceptsOneVersionedObject(t *testing.T) {
	var c config
	err := jsonconfig.Decode([]byte(` {"schema_version":1,"name":"a","slot":33,"values":["x"],"nested":{"on":true},
		"items":[{"id":1},{"id":2}],"free":{"Any":{"Case":[1]}}} `+"\n"), 1, &c)
	if err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != 1 || c.Name != "a" || c.Slot == nil || *c.Slot != 33 || len(c.Values) != 1 || c.Nested == nil || !c.Nested.On ||
		len(c.Items) != 2 || c.Items[1].ID != 2 || c.Free["Any"] == nil {
		t.Fatalf("decoded %+v", c)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"empty", ``, "configuration must be a JSON object"},
		{"binary", "\x08\x81\xfc\x03", "configuration must be a JSON object"},
		{"array", `[{"schema_version":1}]`, "configuration must be a JSON object"},
		{"scalar", `1`, "configuration must be a JSON object"},
		{"top-level null", `null`, "configuration must be a JSON object"},
		{"missing version", `{"name":"a"}`, "schema_version is required"},
		{"wrong version", `{"schema_version":2}`, "schema_version must be 1 (got 2)"},
		{"string version", `{"schema_version":"1"}`, "schema_version"},
		{"unknown key", `{"schema_version":1,"nmae":"a"}`, `unknown key "nmae"`},
		{"null scalar", `{"schema_version":1,"slot":null}`, "null values are not supported"},
		{"null in array", `{"schema_version":1,"values":[null]}`, "null values are not supported"},
		{"null nested", `{"schema_version":1,"nested":{"on":null}}`, "null values are not supported"},
		{"two objects", `{"schema_version":1}{"schema_version":1}`, "expected one JSON object"},
		{"trailing data", `{"schema_version":1} x`, "expected one JSON object"},
		{"truncated", `{"schema_version":1`, "configuration:"},
		{"wrong type", `{"schema_version":1,"slot":"33"}`, "slot"},
		{"case-mismatched key", `{"schema_version":1,"Name":"a"}`, `unknown key "Name"`},
		{"case-mismatched version", `{"Schema_Version":1}`, `unknown key "Schema_Version"`},
		{"case-mismatched nested key", `{"schema_version":1,"nested":{"On":true}}`, `unknown key "nested.On"`},
		{"case-mismatched key in array", `{"schema_version":1,"items":[{"id":1},{"ID":2}]}`, `unknown key "items[].ID"`},
		{"unknown nested key", `{"schema_version":1,"nested":{"off":true}}`, `unknown key "nested.off"`},
		{"duplicate key", `{"schema_version":1,"name":"a","name":"b"}`, `duplicate key "name"`},
		{"duplicate version", `{"schema_version":1,"schema_version":1}`, `duplicate key "schema_version"`},
		{"duplicate nested object", `{"schema_version":1,"nested":{"on":true},"nested":{}}`, `duplicate key "nested"`},
		{"duplicate nested key", `{"schema_version":1,"nested":{"on":true,"on":false}}`, `duplicate key "nested.on"`},
		{"duplicate key in array", `{"schema_version":1,"items":[{"id":1,"id":2}]}`, `duplicate key "items[].id"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			err := jsonconfig.Decode([]byte(tc.input), 1, &c)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "configuration") {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
