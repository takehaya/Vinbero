package bpf

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

// Loading the collection runs the verifier over every program in it, which
// costs seconds, and the tests in this package did it well over a hundred
// times -- the same programs, verified again and again. The loaded objects
// only depend on the constants they were built with, so load one collection
// per distinct set and give every test the map state it would have had from
// a fresh load.
//
// The collections are never closed: they live as long as the test binary,
// and the kernel reclaims them when it exits.
var (
	sharedCollMu sync.Mutex
	sharedColls  = map[string]*BpfObjects{}
)

func sharedCollectionKey(constants map[string]any) string {
	if len(constants) == 0 {
		return ""
	}
	names := make([]string, 0, len(constants))
	for name := range constants {
		names = append(names, name)
	}
	sort.Strings(names)
	key := ""
	for _, name := range names {
		key += fmt.Sprintf("%s=%v;", name, constants[name])
	}
	return key
}

// sharedCollection returns the collection for constants, loading it on first
// use, with every map back in the state a fresh load would have left it.
func sharedCollection(tb testing.TB, constants map[string]any) *BpfObjects {
	tb.Helper()
	sharedCollMu.Lock()
	defer sharedCollMu.Unlock()

	key := sharedCollectionKey(constants)
	if objs, ok := sharedColls[key]; ok {
		resetSharedCollection(tb, objs)
		return objs
	}
	objs, err := ReadCollection(constants, nil)
	if err != nil {
		tb.Fatalf("Failed to load BPF objects: %v", err)
	}
	sharedColls[key] = objs
	return objs
}

// resetSharedCollection empties every map a test could have written.
// PROG_ARRAYs are left alone: they hold the tail-call targets that
// ReadCollection populated, and clearing them would break dispatch.
func resetSharedCollection(tb testing.TB, objs *BpfObjects) {
	tb.Helper()
	maps := reflect.ValueOf(objs.BpfMaps)
	for i := range maps.NumField() {
		m, ok := maps.Field(i).Interface().(*ebpf.Map)
		if !ok || m == nil {
			continue
		}
		if err := clearMap(m); err != nil {
			tb.Fatalf("failed to reset map %s: %v", maps.Type().Field(i).Name, err)
		}
	}
}

func clearMap(m *ebpf.Map) error {
	info, err := m.Info()
	if err != nil {
		return err
	}
	switch info.Type {
	case ebpf.ProgramArray:
		return nil
	case ebpf.Array, ebpf.PerCPUArray:
		return zeroArray(m, info)
	default:
		return deleteAllKeys(m, info)
	}
}

// zeroArray writes a zero value back to every index. Array maps have no
// delete, and their entries exist from the moment the map is created.
func zeroArray(m *ebpf.Map, info *ebpf.MapInfo) error {
	zero := make([]byte, info.ValueSize)
	perCPU := info.Type == ebpf.PerCPUArray
	var value any = zero
	if perCPU {
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			return err
		}
		values := make([][]byte, cpus)
		for i := range values {
			values[i] = make([]byte, info.ValueSize)
		}
		value = values
	}
	for i := uint32(0); i < info.MaxEntries; i++ {
		if err := m.Put(i, value); err != nil {
			return fmt.Errorf("index %d: %w", i, err)
		}
	}
	return nil
}

// deleteAllKeys drains a hash or LPM trie. Keys are collected first: the
// iterator's behavior while the map is being modified is not defined.
func deleteAllKeys(m *ebpf.Map, info *ebpf.MapInfo) error {
	var keys [][]byte
	key := make([]byte, info.KeySize)
	value := make([]byte, info.ValueSize)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}
