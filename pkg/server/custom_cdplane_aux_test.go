package server

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/vinbero/sdk/go/cplane/cdplanecontroller"
)

func TestCustomCDplaneBTFAndGoEncodingAgree(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../../sdk/examples/plugin-custom-cdplane-behavior/plugin.o")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("build the BTF fixture: make -C sdk/examples/plugin-custom-cdplane-behavior")
	}
	if err != nil {
		t.Fatal(err)
	}
	var aux *btf.Struct
	if err := spec.Types.TypeByName("plugin_custom_cdplane_behavior_aux", &aux); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"::/0", "2001:db8::/64", "2001:db8:0:0:8000::/65", "2001:db8:ff::1/128"} {
		t.Run(cidr, func(t *testing.T) {
			manual, err := EncodePluginAux(aux, parseJSON(t, `{"version":1,"allowed_underlay_prefix":"`+cidr+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			controller, err := cdplanecontroller.EncodeEndpointAux(netip.MustParsePrefix(cidr))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(manual, controller) {
				t.Fatalf("manual BTF encoding %x differs from shared controller %x", manual, controller)
			}
		})
	}
}
