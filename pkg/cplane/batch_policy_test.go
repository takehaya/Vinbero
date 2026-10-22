package cplane

import (
	"fmt"
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestInputBatchPolicyBounds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		field     string
		want      int
		wantError bool
	}{
		{name: "omitted", want: 1},
		{name: "zero", field: `,"max_batch_events":0`, want: 1},
		{name: "one", field: `,"max_batch_events":1`, want: 1},
		{name: "two", field: `,"max_batch_events":2`, want: 2},
		{name: "sixteen", field: `,"max_batch_events":16`, want: 16},
		{name: "seventeen", field: `,"max_batch_events":17`, wantError: true},
		{name: "uint32_max", field: `,"max_batch_events":4294967295`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"version":1,"contexts":[{"name":"mobile","grants":[{"families":["mup_ipv4"],"route_targets":["65000:7"]}]}]%s}`, tc.field)
			var input v1.CplaneInputPolicy
			if err := protojson.Unmarshal([]byte(raw), &input); err != nil {
				t.Fatal(err)
			}
			original := proto.Clone(&input)
			policy, err := parseInputPolicy(&input, nil)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "max_batch_events") {
					t.Fatalf("invalid batch limit accepted or misclassified: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if policy.maxBatchEvents != tc.want || !proto.Equal(policy.spec, original) || !proto.Equal(&input, original) {
				t.Fatalf("effective limit or preserved policy differs: limit=%d input=%v stored=%v", policy.maxBatchEvents, &input, policy.spec)
			}
			// Proto JSON is the CLI input transport. Its policy
			// value remains explicit even when 0 and 1 have the same effect.
			encoded, err := protojson.Marshal(policy.spec)
			if err != nil {
				t.Fatal(err)
			}
			var restored v1.CplaneInputPolicy
			if err := protojson.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(&restored, original) {
				t.Fatal("batch policy changed in JSON round trip")
			}
			input.MaxBatchEvents = 17
			if !proto.Equal(policy.spec, original) || policy.maxBatchEvents != tc.want {
				t.Fatal("caller mutation changed parsed policy")
			}
		})
	}
}
