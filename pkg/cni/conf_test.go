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

	// L2 mode: a bridge domain, the EVPN family, and the inner-Ethernet MTU.
	c, err = ParseConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"vinbero","mode":"l2",
		"vrf":"tenant-l2","bridge":"br-l2","bdId":100,
		"rd":"65100:1","rts":[{"family":"evpn","rt":"65000:100","direction":"both"}],"locator":"LOC1",
		"ipam":{"type":"host-local"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeL2 || c.Bridge != "br-l2" || c.BdID != 100 || c.MTU != 1422 || !c.WantsBinding() {
		t.Errorf("l2 parsed %+v", c)
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
		{"bad mode", map[string]string{"mode": `"l4"`}, "not supported"},
		{"l2 with tableId", map[string]string{"mode": `"l2"`, "bridge": `"br0"`, "bdId": `100`}, "tableId is not used"},
		{"l2 no bridge", map[string]string{"mode": `"l2"`, "tableId": `0`, "bdId": `100`}, "bridge"},
		{"l2 bad bdId", map[string]string{"mode": `"l2"`, "tableId": `0`, "bridge": `"br0"`, "bdId": `0`}, "bdId"},
		{"l2 vpnv4 rt", map[string]string{"mode": `"l2"`, "tableId": `0`, "bridge": `"br0"`, "bdId": `100`, "rd": `"1:1"`, "locator": `"L"`, "rts": `[{"family":"vpnv4","rt":"1:1"}]`}, "evpn"},
		{"l3 bridge", map[string]string{"bridge": `"br0"`}, "only for mode"},
		{"no vrf", map[string]string{"vrf": `""`}, "vrf"},
		{"long vrf", map[string]string{"vrf": `"a-vrf-name-too-long"`}, "longer than 15"},
		{"slash vrf", map[string]string{"vrf": `"a/b"`}, "contains"},
		{"cr vrf", map[string]string{"vrf": `"a\rb"`}, "contains"},
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
