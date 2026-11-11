package cplane

import (
	"fmt"
	"strings"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// The composition fake holds entries of every VRF, as the BPF maps do: a MUP
// gate is an entry of its uplinks' VRF. An entry of another VRF than the
// global one is kept in the embedded prefix-keyed maps under
// "vrf <id> <prefix>", so the tests that count the maps see every entry.

func serviceVRFKey(vrfID uint32, prefix string) string {
	return bpf.HeadendID{VRF: vrfID, Prefix: maskKey(prefix)}.String()
}

func parseServiceVRFKey(key string) bpf.HeadendID {
	var id bpf.HeadendID
	if rest, ok := strings.CutPrefix(key, "vrf "); ok {
		if _, err := fmt.Sscanf(rest, "%d %s", &id.VRF, &id.Prefix); err == nil {
			return id
		}
	}
	return bpf.HeadendID{Prefix: key}
}

func serviceIDs[V any](in map[string]V, err error) (map[bpf.HeadendID]V, error) {
	if err != nil {
		return nil, err
	}
	out := make(map[bpf.HeadendID]V, len(in))
	for k, v := range in {
		out[parseServiceVRFKey(k)] = v
	}
	return out, nil
}

func (f *serviceFake) ListHeadendV4IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error) {
	return serviceIDs(f.ListHeadendV4())
}
func (f *serviceFake) ListHeadendV6IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error) {
	return serviceIDs(f.ListHeadendV6())
}
func (f *serviceFake) ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return serviceIDs(f.ListHeadendV4Owners())
}
func (f *serviceFake) ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error) {
	return serviceIDs(f.ListHeadendV6Owners())
}
func (f *serviceFake) GetHeadendV4OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return f.GetHeadendV4Owner(serviceVRFKey(v, p))
}
func (f *serviceFake) GetHeadendV6OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	return f.GetHeadendV6Owner(serviceVRFKey(v, p))
}
func (f *serviceFake) CreateHeadendV4In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.CreateHeadendV4(serviceVRFKey(v, p), e, o)
}
func (f *serviceFake) CreateHeadendV6In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	return f.CreateHeadendV6(serviceVRFKey(v, p), e, o)
}
func (f *serviceFake) DeleteHeadendV4In(v uint32, p string, o bpf.OwnerTag) error {
	return f.DeleteHeadendV4(serviceVRFKey(v, p), o)
}
func (f *serviceFake) DeleteHeadendV6In(v uint32, p string, o bpf.OwnerTag) error {
	return f.DeleteHeadendV6(serviceVRFKey(v, p), o)
}
