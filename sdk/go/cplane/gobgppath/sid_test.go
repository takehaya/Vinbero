package gobgppath

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestServiceSIDStrictProfile(t *testing.T) {
	makeInfo := func() *bgp.SRv6InformationSubTLV {
		return bgp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00::1"), bgp.END_DT4, bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 0, 0))
	}
	attrs := func(i ...bgp.PrefixSIDTLVInterface) []bgp.PathAttributeInterface {
		return []bgp.PathAttributeInterface{bgp.NewPathAttributePrefixSID(bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service, i...))}
	}
	if _, err := ReadServiceSID(nil, bgp.TLVTypeSRv6L3Service); !errors.Is(err, ErrMissingSID) {
		t.Fatal(err)
	}
	info := makeInfo()
	got, err := ReadServiceSID(attrs(info), bgp.TLVTypeSRv6L3Service)
	if err != nil || !got.HasStructure || got.Structure.Function != 16 || got.Address.String() != "fd00::1" {
		t.Fatalf("SID %+v %v", got, err)
	}
	info.SID[0] = 0
	if got.Address.String() != "fd00::1" {
		t.Fatal("SID projection borrows packet memory")
	}
	if _, err := ReadServiceSID(attrs(makeInfo(), makeInfo()), bgp.TLVTypeSRv6L3Service); !errors.Is(err, ErrAmbiguousSID) {
		t.Fatalf("duplicate SID %v", err)
	}
	if _, err := ReadServiceSID(attrs(makeInfo()), bgp.TLVTypeSRv6L2Service); !errors.Is(err, ErrMissingSID) {
		t.Fatalf("wrong service type %v", err)
	}
	for _, tt := range []struct {
		name string
		st   *bgp.SRv6SIDStructureSubSubTLV
		want error
	}{
		{"overflow", bgp.NewSRv6SIDStructureSubSubTLV(64, 64, 1, 0, 0, 0), ErrInvalidSID},
		{"orphan-offset", bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 0, 64), ErrInvalidSID},
		{"transpose", bgp.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 16, 48), ErrUnsupportedSID},
	} {
		t.Run(tt.name, func(t *testing.T) {
			i := makeInfo()
			i.SubSubTLVs = []bgp.PrefixSIDTLVInterface{tt.st}
			if _, err := ReadServiceSID(attrs(i), bgp.TLVTypeSRv6L3Service); !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
	info = makeInfo()
	info.SubSubTLVs = append(info.SubSubTLVs, info.SubSubTLVs[0])
	if _, err := ReadServiceSID(attrs(info), bgp.TLVTypeSRv6L3Service); !errors.Is(err, ErrAmbiguousSID) {
		t.Fatalf("duplicate structure %v", err)
	}
	info = makeInfo()
	info.SID = make([]byte, 16)
	if _, err := ReadServiceSID(attrs(info), bgp.TLVTypeSRv6L3Service); !errors.Is(err, ErrInvalidSID) {
		t.Fatalf("zero SID %v", err)
	}
}
