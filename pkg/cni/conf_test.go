package cni

import (
	"strings"
	"testing"
)

func TestParseConfDefaults(t *testing.T) {
	c, err := ParseConf([]byte(`{"cniVersion":"1.0.0","name":"tenant-a","type":"vinbero",
		"server":"127.0.0.1:8081","vrf":"tenant-a","tableId":100,"ipam":{"type":"host-local"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "http://127.0.0.1:8081" {
		t.Errorf("server = %q", c.Server)
	}
	if c.Mode != ModeL3 || c.DeviceMode != "generic" || c.MTU != 1436 || c.DataDir != "/var/lib/vinbero/cni" {
		t.Errorf("defaults = mode %q deviceMode %q mtu %d dataDir %q", c.Mode, c.DeviceMode, c.MTU, c.DataDir)
	}
	if c.WantsBinding() {
		t.Error("no rd/rts/locator but WantsBinding")
	}

	c, err = ParseConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"vinbero","vrf":"v","tableId":7,
		"rd":"65000:100","rts":[{"family":"vpnv4","rt":"65000:100","direction":"both"}],"locator":"LOC1",
		"maxPrefixes":10,"mtu":9000,"deviceMode":"driver","ipam":{"type":"whereabouts"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != defaultServer || !c.WantsBinding() || c.MTU != 9000 || c.DeviceMode != "driver" {
		t.Errorf("parsed %+v", c)
	}
}

func TestParseConfRejects(t *testing.T) {
	base := map[string]string{
		"cniVersion": `"1.0.0"`, "name": `"n"`, "type": `"vinbero"`,
		"vrf": `"tenant-a"`, "tableId": `100`, "ipam": `{"type":"host-local"}`,
	}
	for _, tc := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{"no name", map[string]string{"name": `""`}, "name is required"},
		{"l2 mode", map[string]string{"mode": `"l2"`}, "not supported"},
		{"no vrf", map[string]string{"vrf": `""`}, "vrf"},
		{"long vrf", map[string]string{"vrf": `"a-vrf-name-too-long"`}, "longer than 15"},
		{"slash vrf", map[string]string{"vrf": `"a/b"`}, "contains"},
		{"global vrf", map[string]string{"vrf": `"global"`}, "reserved"},
		{"no table", map[string]string{"tableId": `0`}, "tableId is required"},
		{"main table", map[string]string{"tableId": `254`}, "reserved kernel table"},
		{"no ipam", map[string]string{"ipam": `{}`}, "ipam.type"},
		{"offload", map[string]string{"deviceMode": `"offload"`}, "deviceMode"},
		{"tiny mtu", map[string]string{"mtu": `60`}, "mtu"},
		{"rd only", map[string]string{"rd": `"65000:1"`}, "together"},
		{"no locator", map[string]string{"rd": `"65000:1"`, "rts": `[{"family":"vpnv4","rt":"65000:1"}]`}, "together"},
		{"evpn rt", map[string]string{"rd": `"65000:1"`, "locator": `"L"`, "rts": `[{"family":"evpn","rt":"65000:1"}]`}, "family"},
		{"empty rt", map[string]string{"rd": `"65000:1"`, "locator": `"L"`, "rts": `[{"family":"vpnv4"}]`}, "rt is required"},
		{"bad direction", map[string]string{"rd": `"65000:1"`, "locator": `"L"`, "rts": `[{"family":"vpnv4","rt":"1:1","direction":"in"}]`}, "direction"},
		{"max without binding", map[string]string{"maxPrefixes": `5`}, "maxPrefixes"},
		{"not json", nil, "parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data string
			if tc.set == nil {
				data = "{"
			} else {
				fields := make([]string, 0, len(base))
				for k, v := range base {
					if o, ok := tc.set[k]; ok {
						v = o
					}
					fields = append(fields, `"`+k+`":`+v)
				}
				for k, v := range tc.set {
					if _, ok := base[k]; !ok {
						fields = append(fields, `"`+k+`":`+v)
					}
				}
				data = "{" + strings.Join(fields, ",") + "}"
			}
			_, err := ParseConf([]byte(data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseConf(%s) = %v, want error containing %q", data, err, tc.want)
			}
		})
	}
}
